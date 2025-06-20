use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Write};
use std::ops::Not;
use std::path::{Path, PathBuf};
use std::process::Command;

use cargo_metadata::{Metadata, MetadataCommand};
use path_macro::path;

use crate::arg::*;

#[derive(Clone, Debug)]
pub enum BSANCommand {
    /// Our own special 'setup' command.
    Setup,
    /// A command to be forwarded to cargo.
    Forward(String),
    /// Clean the cache
    Clean,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RustcPhase {
    /// Sysroot build
    Setup,
    /// Regular build
    Build,
}

pub fn show_error_(msg: &impl std::fmt::Display) -> ! {
    eprintln!("fatal error: {msg}");
    std::process::exit(1)
}

macro_rules! show_error {
    ($($tt:tt)*) => { crate::util::show_error_(&format_args!($($tt)*)) };
}

pub(crate) use show_error;

/// Debug-print a command that is going to be run.
pub fn debug_cmd(prefix: &str, verbose: usize, cmd: &Command) {
    if verbose != 0 {
        eprintln!("{prefix} running command: {cmd:?}");
    }
}

pub fn cargo() -> Command {
    Command::new(env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo")))
}

pub fn find_library(default: &str, sysroot: &Path, libname: &str) -> Option<PathBuf> {
    env::var_os(default).map(|o| o.into()).or_else(|| {
        let plugin: PathBuf = path!(sysroot / "lib" / libname);
        if plugin.exists() {
            Some(plugin)
        } else {
            None
        }
    })
}

pub fn find_library_dir(default: &str, sysroot: &Path, libname: &str) -> Option<PathBuf> {
    env::var_os(default).map(|o| o.into()).or_else(|| {
        let libdir = path!(sysroot / "lib");
        let plugin = path!(&libdir / libname);
        if plugin.exists() {
            Some(libdir)
        } else {
            None
        }
    })
}

/// Returns the path to the `bsan-driver` binary
pub fn find_bsan() -> PathBuf {
    if let Some(path) = env::var_os("BSAN_DRIVER") {
        return path.into();
    }
    // Assume it is in the same directory as ourselves.
    let mut path = std::env::current_exe().expect("current executable path invalid");
    path.set_file_name(format!("bsan-driver{}", env::consts::EXE_SUFFIX));
    path
}

pub fn bsan() -> Command {
    let mut cmd = Command::new(find_bsan());
    // We never want to inherit this from the environment.
    // However, this is sometimes set in the environment to work around build scripts that don't
    // honor RUSTC_WRAPPER. So remove it again in case it is set.
    cmd.env_remove("BSAN_BE_RUSTC");
    cmd
}

pub fn bsan_for_host() -> Command {
    let mut cmd = bsan();
    cmd.env("BSAN_BE_RUSTC", "host");
    cmd
}

/// Execute the `Command`, where possible by replacing the current process with a new process
/// described by the `Command`. Then exit this process with the exit code of the new process.
pub fn exec(mut cmd: Command) -> ! {
    // On non-Unix imitate POSIX exec as closely as we can
    #[cfg(not(unix))]
    {
        let exit_status = cmd.status().expect("failed to run command");
        std::process::exit(exit_status.code().unwrap_or(-1))
    }
    // On Unix targets, actually exec.
    // If exec returns, process setup has failed. This is the same error condition as the expect in
    // the non-Unix case.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = cmd.exec();
        panic!("failed to run command: {error}")
    }
}

pub fn exec_stdout(mut cmd: Command) -> String {
    let output = cmd.output().expect("failed to run command");
    if output.status.success() {
        String::from_utf8(output.stdout).expect("output bytes should be valid utf8")
    } else {
        panic!("failed to run command: {output:?}")
    }
}

#[allow(unused)]
pub fn exec_with_pipe<P>(mut cmd: Command, input: &[u8], path: P) -> !
where
    P: AsRef<Path>,
{
    #[cfg(unix)]
    {
        // Write the bytes we want to send to stdin out to a file
        std::fs::write(&path, input).unwrap();
        // Open the file for reading, and set our new stdin to it
        let stdin = File::open(&path).unwrap();
        cmd.stdin(stdin);
        // Unlink the file so that it is fully cleaned up as soon as the new process exits
        std::fs::remove_file(&path).unwrap();
        // Finally, we can hand off control.
        exec(cmd)
    }
    #[cfg(not(unix))]
    {
        drop(path); // We don't need the path, we can pipe the bytes directly
        cmd.stdin(std::process::Stdio::piped());
        let mut child = cmd.spawn().expect("failed to spawn process");
        let child_stdin = child.stdin.take().unwrap();
        // Write stdin in a background thread, as it may block.
        let exit_status = std::thread::scope(|s| {
            s.spawn(|| {
                let mut child_stdin = child_stdin;
                // Ignore failure, it is most likely due to the process having terminated.
                let _ = child_stdin.write_all(input);
            });
            child.wait().expect("failed to run command")
        });
        std::process::exit(exit_status.code().unwrap_or(-1))
    }
}

/// Determines where the host sysroot of this execution is
pub fn get_host_sysroot_dir(verbose: usize) -> PathBuf {
    let mut cmd = bsan_for_host();
    cmd.args(["--print", "sysroot"]);
    debug_cmd("[cargo-bsan rustc]", verbose, &cmd);
    let libdir = exec_stdout(cmd);
    PathBuf::from(libdir.trim())
}

/// Determines where the sysroot of this execution is
///
/// Either in a user-specified spot by an envar, or in a default cache location.
pub fn get_target_sysroot_dir() -> PathBuf {
    match std::env::var_os("BSAN_SYSROOT") {
        Some(dir) => PathBuf::from(dir),
        None => {
            let user_dirs =
                directories::ProjectDirs::from("org", "borrowsanitizer", "bsan").unwrap();
            user_dirs.cache_dir().to_owned()
        }
    }
}

pub fn ask_to_run(mut cmd: Command, ask: bool, text: &str) {
    // Disable interactive prompts in CI (GitHub Actions, Travis, AppVeyor, etc).
    // Azure doesn't set `CI` though (nothing to see here, just Microsoft being Microsoft),
    // so we also check their `TF_BUILD`.
    let is_ci = env::var_os("CI").is_some() || env::var_os("TF_BUILD").is_some();
    if ask && !is_ci {
        let mut buf = String::new();
        print!("I will run `{cmd:?}` to {text}. Proceed? [Y/n] ");
        io::stdout().flush().unwrap();
        io::stdin().read_line(&mut buf).unwrap();
        match buf.trim().to_lowercase().as_ref() {
            // Proceed.
            "" | "y" | "yes" => {}
            "n" | "no" => show_error!("aborting as per your request"),
            a => show_error!("invalid answer `{}`", a),
        };
    } else {
        eprintln!("Running `{cmd:?}` to {text}.");
    }

    if cmd.status().unwrap_or_else(|_| panic!("failed to execute {cmd:?}")).success().not() {
        show_error!("failed to {}", text);
    }
}

/// Get the target directory for bsan output.
///
/// Either in an argument passed-in, or from cargo metadata.
pub fn get_target_dir(meta: &Metadata) -> PathBuf {
    let mut output = match get_arg_flag_value("--target-dir") {
        Some(dir) => PathBuf::from(dir),
        None => meta.target_directory.clone().into_std_path_buf(),
    };
    output.push("bsan");
    output
}

// Computes the extra flags that need to be passed to cargo to make it behave like the current
// cargo invocation.
fn cargo_extra_flags() -> Vec<String> {
    let mut flags = Vec::new();
    // Forward `--config` flags.
    let config_flag = "--config";
    for arg in get_arg_flag_values(config_flag) {
        flags.push(config_flag.to_string());
        flags.push(arg);
    }

    // Forward `--manifest-path`.
    let manifest_flag = "--manifest-path";
    if let Some(manifest) = get_arg_flag_value(manifest_flag) {
        flags.push(manifest_flag.to_string());
        flags.push(manifest);
    }

    // Forwarding `--target-dir` would make sense, but `cargo metadata` does not support that flag.
    flags
}

pub fn get_cargo_metadata() -> Metadata {
    // This will honor the `CARGO` env var the same way our `cargo()` does.
    MetadataCommand::new().no_deps().other_options(cargo_extra_flags()).exec().unwrap()
}

pub fn clean_sysroot_dir() {
    let sysroot = get_target_sysroot_dir();
    if sysroot.exists() {
        std::fs::remove_dir_all(&sysroot).unwrap();
    }
}

pub fn clean_target_dir() {
    let target_dir = get_target_dir(&get_cargo_metadata());
    if target_dir.exists() {
        std::fs::remove_dir_all(&target_dir).unwrap();
    }
}
