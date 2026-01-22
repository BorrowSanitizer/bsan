use std::path;
use std::path::PathBuf;
use std::process::Command;

use rustc_version::VersionMeta;

use crate::arg::*;
use crate::setup::*;
use crate::util::*;
use crate::*;

pub fn phase_cargo_bsan(mut args: impl Iterator<Item = String>) {
    if has_arg_flag("--help") || has_arg_flag("-h") {
        show_help();
        return;
    }
    if has_arg_flag("--version") || has_arg_flag("-V") {
        show_version();
        return;
    }
    let Some(subcommand) = args.next() else {
        show_error!(
            "`cargo bsan` needs to be called with a subcommand (e.g `run`, `test`, `clean`)"
        );
    };

    let subcommand = match &*subcommand {
        "setup" => BSANCommand::Setup,
        "build" | "test" | "t" | "run" | "r" | "nextest" => BSANCommand::Forward(subcommand),
        "clean" => BSANCommand::Clean,
        _ => show_error!(
            "`cargo bsan` supports the following subcommands: `run`, `build`, `test`, `nextest`, `clean`, and `setup`."
        ),
    };

    let verbose = num_arg_flag("-v");
    let quiet = has_arg_flag("-q") || has_arg_flag("--quiet");

    // Determine the involved architectures.
    let rustc_version = VersionMeta::for_command(bsan_for_host()).unwrap_or_else(|err| {
        panic!("failed to determine underlying rustc version of BSAN ({:?}):\n{err:?}", bsan())
    });

    let targets = get_arg_flag_values("--target").collect::<Vec<_>>();

    // We only allow specifying the host as a target.
    if targets.len() > 1 || targets.iter().any(|t| t != &rustc_version.host) {
        show_error!("Cross-compilation is not supported.");
    }

    // If cleaning the target directory & sysroot cache,
    // delete them then exit. There is no reason to setup a new
    // sysroot in this execution.
    if let BSANCommand::Clean = subcommand {
        clean_sysroot_dir();
        clean_target_dir();
        return;
    }

    let bsan_sysroot = ensure_sysroot(&subcommand, &rustc_version, verbose, quiet);
    let bsan_path = find_bsan();

    if let BSANCommand::Setup = subcommand
        && has_arg_flag("--print-rustflags")
    {
        let mut cmd = bsan();
        cmd.env("PRINT_RUSTFLAGS", "1");
        debug_cmd("[cargo-bsan rustc]", verbose, &cmd);
        exec(cmd);
    }

    let cargo_cmd = match subcommand {
        BSANCommand::Forward(s) => s,
        BSANCommand::Clean => unreachable!(),
        BSANCommand::Setup => return,
    };

    let cargo_bsan_path = env::current_exe()
        .expect("current executable path invalid")
        .into_os_string()
        .into_string()
        .expect("current executable path is not valid UTF-8");

    let metadata = get_cargo_metadata();
    let mut cmd = cargo();
    cmd.arg(&cargo_cmd);
    // In nextest we have to also forward the main `verb`.
    if cargo_cmd == "nextest" {
        cmd.arg(
            args.next()
                .unwrap_or_else(|| show_error!("`cargo bsan nextest` expects a verb (e.g. `run`)")),
        );
    }

    cmd.arg("--target");
    cmd.arg(&rustc_version.host);

    let cargo_bsan_path_for_toml = escape_for_toml(&cargo_bsan_path);
    cmd.arg("--config")
        .arg(format!("target.'cfg(all())'.runner=[{cargo_bsan_path_for_toml}, 'runner']"));

    // Set `--target-dir` to `bsan` inside the original target directory.
    let target_dir = get_target_dir(&metadata);
    cmd.arg("--target-dir").arg(target_dir);

    // *After* we set all the flags that need setting, forward everything else. Make sure to skip
    // `--target-dir` (which would otherwise be set twice).
    for arg in
        ArgSplitFlagValue::from_string_iter(&mut args, "--target-dir").filter_map(Result::err)
    {
        cmd.arg(arg);
    }
    cmd.args(args);

    if env::var_os("RUSTC_WRAPPER").is_some() {
        println!(
            "WARNING: Ignoring `RUSTC_WRAPPER` environment variable, BSAN does not support wrapping."
        );
    }
    cmd.env("RUSTC_WRAPPER", &cargo_bsan_path);

    // If both RUSTC_WORKSPACE_WRAPPER and RUSTC_WRAPPER are set,
    // then both are executed in succession. Providing an independent
    // workspace-level wrapper is not supported, so we clear this variable.
    if env::var_os("RUSTC_WORKSPACE_WRAPPER").is_some() {
        println!(
            "WARNING: Ignoring `RUSTC_WORKSPACE_WRAPPER` environment variable, BSAN does not support wrapping."
        );
    }
    cmd.env_remove("RUSTC_WORKSPACE_WRAPPER");

    cmd.env("RUSTC", path::absolute(bsan_path).unwrap());

    // At this point, we've completed setup, so we have a sysroot.
    cmd.env("BSAN_SYSROOT", bsan_sysroot);
    if verbose > 0 {
        cmd.env("BSAN_VERBOSE", verbose.to_string()); // This makes the other phases verbose.
    }

    // Run cargo.
    debug_cmd("[cargo-bsan rustc]", verbose, &cmd);
    exec(cmd)
}

pub fn phase_runner(mut binary_args: impl Iterator<Item = String>) {
    let verbose = env::var("BSAN_VERBOSE")
        .map_or(0, |verbose| verbose.parse().expect("verbosity flag must be an integer"));

    let binary = binary_args.next().unwrap();

    let mut cmd = Command::new(binary);
    let llvm_symbolizer = get_host_sysroot_binary("llvm-symbolizer", verbose);
    cmd.env("BSAN_SYMBOLIZER", llvm_symbolizer);
    for arg in binary_args {
        cmd.arg(arg);
    }
    debug_cmd("[cargo-bsan runner]", verbose, &cmd);
    exec(cmd)
}

pub fn phase_rustc(args: impl Iterator<Item = String>, phase: RustcPhase) {
    /// Determines if we are being invoked (as rustc) to build a crate for
    /// the "target" architecture, in contrast to the "host" architecture.
    /// Host crates are for build scripts and proc macros and still need to
    /// be built like normal. Target crates need to be built with BorrowSanitizer
    /// instrumentation.
    ///
    /// Currently, we detect this by checking for "--target=", which is
    /// never set for host crates. This matches what rustc bootstrap does,
    /// which hopefully makes it "reliable enough". This relies on us always
    /// invoking cargo itself with `--target`, which `in_cargo_miri` ensures.
    fn is_target_crate() -> bool {
        get_arg_flag_value("--target").is_some()
    }

    let verbose = env::var("BSAN_VERBOSE")
        .map_or(0, |verbose| verbose.parse().expect("verbosity flag must be an integer"));

    let target_crate = is_target_crate();

    let mut cmd = bsan();
    // Arguments are treated very differently depending on whether this crate needs to be
    // instrumented by BorrowSanitizer or if it's for a build script / proc macro.
    if target_crate {
        if phase != RustcPhase::Setup {
            // Set the sysroot -- except during setup, where we don't have an existing sysroot yet
            // and where the bootstrap wrapper adds its own `--sysroot` flag so we can't set ours.
            cmd.arg("--sysroot").arg(env::var_os("BSAN_SYSROOT").unwrap());
        }
        // During setup, patch the panic runtime for `libpanic_abort` (mirroring what bootstrap usually does).
        if phase == RustcPhase::Setup
            && get_arg_flag_value("--crate-name").as_deref() == Some("panic_abort")
        {
            cmd.arg("-C").arg("panic=abort");
        }
    } else {
        // This is a host crate.
        // When we're running `cargo-bsan` from `x.py` we need to pass the sysroot explicitly
        // due to bootstrap complications.
        if let Some(sysroot) = env::var_os("BSAN_HOST_SYSROOT") {
            cmd.arg("--sysroot").arg(sysroot);
        }
    }
    // Forward everything else.
    cmd.args(args);
    cmd.env("BSAN_BE_RUSTC", if target_crate { "target" } else { "host" });

    if verbose > 0 {
        eprintln!("[cargo-bsan rustc] target_crate={target_crate}");
    }
    debug_cmd("[cargo-bsan rustc]", verbose, &cmd);
    exec(cmd);
}

fn ensure_sysroot(
    subcommand: &BSANCommand,
    rustc_version: &VersionMeta,
    verbose: usize,
    quiet: bool,
) -> PathBuf {
    let host_sysroot = get_host_sysroot_dir(verbose);

    let Some(bsan_plugin) = find_library("BSAN_PLUGIN", &host_sysroot, "libbsan_plugin.so") else {
        show_error!(
            "failed to locate the BorrowSanitizer LLVM plugin (libbsan_plugin.so) within the host sysroot."
        );
    };
    unsafe {
        env::set_var("BSAN_PLUGIN", bsan_plugin);
    }

    let Some(runtime_dir) = find_library("BSAN_RT", &host_sysroot, "libbsan_rt.a") else {
        show_error!(
            "failed to locate the BorrowSanitizer runtime (libbsan_rt.a) within the host sysroot."
        );
    };
    unsafe {
        env::set_var("BSAN_RT", runtime_dir);
    }

    setup_sysroot(subcommand, rustc_version.host.as_str(), rustc_version, verbose, quiet);
    get_target_sysroot_dir()
}
