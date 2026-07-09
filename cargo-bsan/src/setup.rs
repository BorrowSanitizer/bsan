//! Implements `cargo bsan setup`.
//! This was copied directly from cargo-miri, with only small changes
//! to comments and the names of environment variables.
use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use rustc_build_sysroot::{BuildMode, SysrootBuilder, SysrootConfig, SysrootStatus};
use rustc_version::VersionMeta;

use crate::arg::*;
use crate::llvm::LlvmTools;
use crate::util::*;

const RUST_RT: &str = "libbsan_rt";
const LLVM_RT: &str = "libclang_rt.bsan";
const LLVM_PLUGIN: &str = "libbsan_plugin";

pub struct EnvConfig {
    pub verbose: bool,
    pub quiet: bool,
    pub lto: bool,
    pub nop: bool,
    pub skip_harness: bool,
}

impl EnvConfig {
    pub fn from_args() -> Self {
        let verbose = has_arg_flag("-v");
        let quiet = has_arg_flag("-q") || has_arg_flag("--quiet");
        let lto = has_arg_flag("--lto");
        let nop = has_arg_flag("--nop");
        let skip_harness = has_arg_flag("--skip-harness");
        Self { verbose, quiet, lto, nop, skip_harness }
    }

    pub fn from_env() -> Self {
        let verbose = env::var_os("BSAN_VERBOSE").is_some();
        let quiet = env::var_os("BSAN_QUIET").is_some();
        let lto = env::var_os("BSAN_LTO").is_some();
        let nop: bool = env::var_os("BSAN_NOP").is_some();
        let skip_harness = env::var_os("BSAN_SKIP_HARNESS").is_some();
        Self { verbose, quiet, lto, nop, skip_harness }
    }

    pub fn populate_env(&self, cmd: &mut Command) {
        if self.verbose {
            cmd.env("BSAN_VERBOSE", "1");
        }
        if self.quiet {
            cmd.env("BSAN_QUIET", "1");
        }
        if self.lto {
            cmd.env("BSAN_LTO", "1");
        }
        if self.nop {
            cmd.env("BSAN_NOP", "1");
        }
        if self.skip_harness {
            cmd.env("BSAN_SKIP_HARNESS", "1");
        }
    }
}

pub struct Dependencies {
    pub rust_runtime: PathBuf,
    pub llvm_runtime: PathBuf,
    pub llvm_pass: PathBuf,
}

impl Dependencies {
    pub fn setup(version: &VersionMeta, host_sysroot: &Sysroot) -> Self {
        let ensure_library_var = |var: &str, sysroot: &Sysroot, libname: &str| {
            env::var_os(var).map(|o| o.into()).or_else(|| {
                let plugin: PathBuf = (*sysroot).join("lib").join(libname).to_path_buf();
                if plugin.exists() {
                    Some(plugin)
                } else {
                    None
                }
            })
        };

        let Some(llvm_pass) =
            ensure_library_var("BSAN_PLUGIN", host_sysroot, &format!("{LLVM_PLUGIN}.so"))
        else {
            show_error!(
                "failed to locate the BorrowSanitizer LLVM plugin (libbsan_plugin.so) within the host sysroot: {}",
                    host_sysroot.display()
            );
        };

        let rust_runtime_name = format!("{RUST_RT}.a");
        let Some(rust_runtime) =
            ensure_library_var("BSAN_RT_RUST", host_sysroot, &rust_runtime_name)
        else {
            show_error!(
                "failed to locate the BorrowSanitizer core runtime ({rust_runtime_name}) within the host sysroot."
            );
        };

        let llvm_runtime_name = {
            let host = &version.host;
            let components: Vec<&str> = host.split("-").collect();
            if let Some(arch) = components.first() {
                format!("{LLVM_RT}-{arch}.a")
            } else {
                show_error!(
                    "Failed to resolve the host architecture from the target triple: {host}"
                );
            }
        };
        let Some(llvm_runtime) =
            ensure_library_var("BSAN_RT_LLVM", host_sysroot, &llvm_runtime_name)
        else {
            show_error!(
                "failed to locate the BorrowSanitizer LLVM runtime ({llvm_runtime_name}) within the host sysroot."
            );
        };

        Self { rust_runtime, llvm_runtime, llvm_pass }
    }

    pub fn populate_env(&self, cmd: &mut Command) {
        cmd.env("BSAN_RT_LLVM", &self.llvm_runtime);
        cmd.env("BSAN_RT_RUST", &self.rust_runtime);
        cmd.env("BSAN_PLUGIN", &self.llvm_pass);
    }

    pub fn from_env() -> Self {
        let llvm_runtime = expect_env_path("BSAN_RT_LLVM");
        let rust_runtime = expect_env_path("BSAN_RT_RUST");
        let llvm_pass = expect_env_path("BSAN_PLUGIN");
        Self { rust_runtime, llvm_runtime, llvm_pass }
    }

    pub fn llvm_runtime(&self) -> (PathBuf, String) {
        Self::rt_include(&self.llvm_runtime).unwrap_or_else(|| {
            show_error!(
                "Invalid format for LLVM runtime (`BSAN_RT_LLVM`): {}",
                self.llvm_runtime.display()
            )
        })
    }

    pub fn rust_runtime(&self) -> (PathBuf, String) {
        Self::rt_include(&self.rust_runtime).unwrap_or_else(|| {
            show_error!(
                "Invalid format for LLVM runtime (`BSAN_RT_RUST`): {}",
                self.llvm_runtime.display()
            )
        })
    }

    fn rt_include(runtime: &Path) -> Option<(PathBuf, String)> {
        let parent_dir = runtime.parent().map(|p| p.to_path_buf())?;
        let file_name = runtime.file_name().and_then(|n| n.to_str())?;
        let stem = file_name.strip_suffix(".a")?;
        let link_name = stem.strip_prefix("lib")?.to_string();
        Some((parent_dir, link_name))
    }
}

/// Performs the setup required to make `cargo bsan` work: Getting a custom-built libstd. Then sets
/// `BSAN_SYSROOT`. Skipped if `BSAN_SYSROOT` is already set, in which case we expect the user has
/// done all this already.
pub fn setup_sysroot(
    subcommand: &BsanCommand,
    rustc_version: &VersionMeta,
    deps: &Dependencies,
    llvm_tools: &LlvmTools,
    sysroot_dir: &Sysroot,
    env: &EnvConfig,
) {
    let only_setup = matches!(subcommand, BsanCommand::Setup);
    let ask_user = !only_setup;
    let print_rustflags = only_setup && has_arg_flag("--print-rustflags");
    let print_sysroot = only_setup && has_arg_flag("--print-sysroot"); // whether we just print the sysroot path
    let show_setup = only_setup && !print_sysroot && !print_rustflags;

    if !only_setup && let Some(sysroot) = std::env::var_os("BSAN_SYSROOT") {
        // Skip setup step if BSAN_SYSROOT is explicitly set, *unless* we are `cargo bsan setup`.
        if print_sysroot {
            println!("{}", sysroot.display());
        }
        return;
    }

    // Determine where the rust sources are located.  The env var trumps auto-detection.
    let rust_src_env_var = std::env::var_os("BSAN_LIB_SRC");
    let rust_src = match rust_src_env_var {
        Some(path) => {
            let path = PathBuf::from(path);
            // Make path absolute if possible.
            path.canonicalize().unwrap_or(path)
        }
        None => {
            // Check for `rust-src` rustup component.
            let rustup_src = rustc_build_sysroot::rustc_sysroot_src(rustc())
                .expect("could not determine sysroot source directory");
            if !rustup_src.exists() {
                // Ask the user to install the `rust-src` component, and use that.
                let mut cmd = Command::new("rustup");
                cmd.args(["component", "add", "rust-src"]);
                ask_to_run(
                    cmd,
                    ask_user,
                    "install the `rust-src` component for the selected toolchain",
                );
            }
            rustup_src
        }
    };
    if !rust_src.exists() {
        show_error!("given Rust source directory `{}` does not exist.", rust_src.display());
    }
    if rust_src.file_name().and_then(OsStr::to_str) != Some("library") {
        show_error!(
            "given Rust source directory `{}` does not seem to be the `library` subdirectory of \
             a Rust source checkout.",
            rust_src.display()
        );
    }

    let target = rustc_version.host.as_str();

    // Sysroot configuration and build details.
    let no_std = match std::env::var_os("BSAN_NO_STD") {
        None =>
        // No-std heuristic taken from rust/src/bootstrap/config.rs
        // (https://github.com/rust-lang/rust/blob/25b5af1b3a0b9e2c0c57b223b2d0e3e203869b2c/src/bootstrap/config.rs#L549-L555).
        {
            target.contains("-none")
                || target.contains("nvptx")
                || target.contains("switch")
                || target.contains("-uefi")
        }
        Some(val) => val != "0",
    };
    let sysroot_config = if no_std {
        SysrootConfig::NoStd
    } else {
        SysrootConfig::WithStd {
            std_features: ["panic-unwind", "backtrace"].into_iter().map(Into::into).collect(),
        }
    };
    let cargo_cmd = {
        let mut command = Cargo::cmd();
        // Use Miri as rustc to build a libstd compatible with us (and use the right flags).
        // We set ourselves (`cargo-bsan`) instead of bsan directly to be able to patch the flags
        // for `libpanic_abort` (usually this is done by bootstrap but we have to do it ourselves).
        // The `BSAN_CALLED_FROM_SETUP` will mean we dispatch to `phase_setup_rustc`.
        // However, when we are running in bootstrap, we cannot just overwrite `RUSTC`,
        // because we still need bootstrap to distinguish between host and target crates.
        // In that case we overwrite `RUSTC_REAL` instead which determines the rustc used
        // for target crates.
        let cargo_bsan_path = std::env::current_exe().expect("current executable path invalid");
        command.env("RUSTC", &cargo_bsan_path);

        command.env("BSAN_CALLED_FROM_SETUP", "1");
        // BSAN expects `BSAN_SYSROOT` to be set when invoked in target mode. Even if that directory is empty.
        command.env("BSAN_SYSROOT", sysroot_dir.as_os_str());
        // Make sure there are no other wrappers getting in our way (Cc
        // https://github.com/rust-lang/miri/issues/1421,
        // https://github.com/rust-lang/miri/issues/2429). Looks like setting
        // `RUSTC_WRAPPER` to the empty string overwrites `build.rustc-wrapper` set via
        // `config.toml`.
        command.env("RUSTC_WRAPPER", "");

        if show_setup {
            // Forward output. Even make it verbose, if requested.
            command.stdout(process::Stdio::inherit());
            command.stderr(process::Stdio::inherit());
            if env.verbose {
                command.arg("-v");
            }
            if env.quiet {
                command.arg("--quiet");
            }
        }
        deps.populate_env(&mut command);
        llvm_tools.populate_env(&mut command);
        env.populate_env(&mut command);
        command
    };
    // Disable debug assertions in the standard library -- Miri is already slow enough.
    // But keep the overflow checks, they are cheap. This completely overwrites flags
    // the user might have set, which is consistent with normal `cargo build` that does
    // not apply `RUSTFLAGS` to the sysroot either.
    let rustflags =
        &["-Cdebug-assertions=off", "-Coverflow-checks=on", "-Cdebuginfo=2", "-Cembed-bitcode"];

    let mut after_build_output = String::new(); // what should be printed when the build is done.
    let notify = || {
        if !env.quiet {
            eprint!("Preparing a sysroot for BorrowSanitizer (target: {target})");
            if env.verbose {
                eprint!(" in {}", sysroot_dir.display());
            }
            if show_setup {
                // Cargo will print things, so we need to finish this line.
                eprintln!("...");
                after_build_output = format!(
                    "A sysroot for BorrowSanitizer is now available in `{}`.\n",
                    sysroot_dir.display()
                );
            } else {
                // Keep all output on a single line.
                eprint!("... ");
                after_build_output = "done\n".to_string();
            }
        }
    };

    // Do the build.
    let status = SysrootBuilder::new(sysroot_dir, target)
        .build_mode(BuildMode::Build)
        .rustc_version(rustc_version.clone())
        .sysroot_config(sysroot_config)
        .rustflags(rustflags)
        .cargo(cargo_cmd)
        .when_build_required(notify)
        .build_from_source(&rust_src);

    match status {
        Ok(SysrootStatus::AlreadyCached) => {
            if !env.quiet && show_setup {
                eprintln!(
                    "A sysroot for BorrowSanitizer is already available in `{}`.",
                    sysroot_dir.display()
                );
            }
        }
        Ok(SysrootStatus::SysrootBuilt) => {
            // Print what `notify` prepared.
            eprint!("{after_build_output}");
        }
        Err(err) => show_error!("failed to build sysroot: {err:?}"),
    }

    if print_sysroot {
        // Print just the sysroot and nothing else to stdout; this way we do not need any escaping.
        println!("{}", sysroot_dir.display());
    }

    unsafe { env::set_var("BSAN_SYSROOT", sysroot_dir.as_os_str()) }
}
