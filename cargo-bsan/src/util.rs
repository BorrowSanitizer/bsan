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
pub enum BsanCommand {
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
    eprintln!("{msg}");
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
/// Execute the `Command`, then exit this process with the exit code of the new process.
/// `input` is also piped to the new process's stdin.
pub fn exec_with_pipe(mut cmd: Command) -> ! {
    // We can't use `exec` since then the background thread will stop running.
    cmd.stdin(std::process::Stdio::inherit());
    let mut child = cmd.spawn().expect("failed to spawn process");
    let exit_status = child.wait().expect("failed to run command");
    std::process::exit(exit_status.code().unwrap_or(-1))
}

/// Determines where the host sysroot of this execution is
pub fn get_host_sysroot_dir(verbose: usize) -> PathBuf {
    let mut cmd = rustc();
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

pub fn get_host_sysroot_binary(binary: &str, verbose: usize) -> PathBuf {
    let bsan_sysroot = get_host_sysroot_dir(verbose);
    let sysroot_bindir = Path::new(&bsan_sysroot).join("bin");
    let symbolizer_path = sysroot_bindir.join(binary);
    if symbolizer_path.exists() {
        symbolizer_path
    } else {
        show_error!("Unable to locate `{binary}` within the host sysroot ({sysroot_bindir:?}).");
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
    MetadataCommand::new().no_deps().other_options(cargo_extra_flags()).exec().unwrap_or_else(
        |err| {
            if let cargo_metadata::Error::CargoMetadata { stderr } = err {
                show_error!("{stderr}")
            } else {
                show_error!("{err}")
            }
        },
    )
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

pub fn expect_env(key: &str) -> OsString {
    env::var_os(key).expect(&format!("expected `{key}` to be set from a prior phase"))
}

pub fn expect_env_path(key: &str) -> PathBuf {
    let path: PathBuf = expect_env(key).into();
    if !path.exists() {
        panic!("the path set for `{key}` does not exist: {}", path.display())
    }
    path
}

pub fn env_or_host(key: &str, binary: &str) -> PathBuf {
    let path =
        env::var_os(key).map(|p| Some(p.into())).unwrap_or_else(|| which::which(binary).ok());
    path.expect("unable to locate `{binary}`")
}

pub fn rustc_path() -> PathBuf {
    env_or_host("BSAN_ORIG_RUSTC", "rustc")
}

pub fn rustc() -> Command {
    Command::new(rustc_path())
}
