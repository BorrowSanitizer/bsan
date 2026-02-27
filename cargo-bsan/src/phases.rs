use std::path::PathBuf;

use rustc_version::VersionMeta;

use crate::arg::*;
use crate::setup::*;
use crate::util::*;
use crate::*;

pub const BSAN_DEFAULT_ARGS: &[&str] = &[
    "-Copt-level=0",
    "-Zmir-opt-level=0",
    "-Zcodegen-emit-retag=true",
    "-Cforce-frame-pointers=yes",
    "-Zmir-preserve-ub",
    "-Zllvm-emit-lifetime-markers",
    "-Zinline-llvm=no",
    "-Cembed-bitcode=yes",
    "-Cdebuginfo=2",
];

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
        "setup" => BsanCommand::Setup,
        "build" | "test" | "t" | "run" | "r" | "nextest" | "rustc" => BsanCommand::Forward(subcommand),
        "clean" => BsanCommand::Clean,
        _ => show_error!(
            "`cargo bsan` supports the following subcommands: `run`, `build`, `test`, `nextest`, `clean`, and `setup`."
        ),
    };

    let verbose = num_arg_flag("-v");
    let quiet = has_arg_flag("-q") || has_arg_flag("--quiet");

    // Determine the involved architectures.
    let rustc_version = VersionMeta::for_command(rustc())
        .unwrap_or_else(|err| panic!("failed to determine underlying rustc version:\n{err:?}"));

    let targets = get_arg_flag_values("--target").collect::<Vec<_>>();

    // We only allow specifying the host as a target.
    if targets.len() > 1 || targets.iter().any(|t| t != &rustc_version.host) {
        show_error!("Cross-compilation is not supported.");
    }

    // If cleaning the target directory & sysroot cache,
    // delete them then exit. There is no reason to setup a new
    // sysroot in this execution.
    if let BsanCommand::Clean = subcommand {
        clean_sysroot_dir();
        clean_target_dir();
        return;
    }

    let bsan_sysroot = ensure_sysroot(&subcommand, &rustc_version, verbose, quiet);

    let cargo_cmd = match subcommand {
        BsanCommand::Forward(s) => s,
        BsanCommand::Clean => unreachable!(),
        BsanCommand::Setup => {
            if has_arg_flag("--print-rustflags") {
                println!("{}", bsan_rustflags().join(" "))
            }
            return;
        }
    };

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

    // If both RUSTC_WORKSPACE_WRAPPER and RUSTC_WRAPPER are set,
    // then both are executed in succession. Providing an independent
    // workspace-level wrapper is not supported, so we clear this variable.
    if env::var_os("RUSTC_WORKSPACE_WRAPPER").is_some() {
        println!(
            "WARNING: Ignoring `RUSTC_WORKSPACE_WRAPPER` environment variable, BSAN does not support wrapping."
        );
    }
    cmd.env_remove("RUSTC_WORKSPACE_WRAPPER");

    // At this point, we've completed setup, so we have a sysroot.
    cmd.env("BSAN_SYSROOT", &bsan_sysroot);

    if verbose > 0 {
        cmd.env("BSAN_VERBOSE", verbose.to_string()); // This makes the other phases verbose.
    }

    let llvm_symbolizer = get_host_sysroot_binary("llvm-symbolizer", verbose);
    cmd.env("BSAN_SYMBOLIZER", llvm_symbolizer);

    let mut rustflags = bsan_rustflags();
    let sysroot_flag = format!("--sysroot={}", bsan_sysroot.display());
    rustflags.push(format!("--sysroot={}", bsan_sysroot.display()));

    cmd.env("RUSTFLAGS", rustflags.join(" "));
    cmd.env("RUSTDOCFLAGS", sysroot_flag);
    // Run cargo.
    debug_cmd("[cargo-bsan rustc]", verbose, &cmd);
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

    let mut cmd = rustc();

    // Arguments are treated very differently depending on whether this crate needs to be
    // instrumented by BorrowSanitizer or if it's for a build script / proc macro.
    if target_crate {
        if phase != RustcPhase::Setup {
            // Set the sysroot -- except during setup, where we don't have an existing sysroot yet
            // and where the bootstrap wrapper adds its own `--sysroot` flag so we can't set ours.
            cmd.arg("--sysroot").arg(expect_env("BSAN_SYSROOT"));
        }
        // During setup, patch the panic runtime for `libpanic_abort` (mirroring what bootstrap usually does).
        if phase == RustcPhase::Setup
            && get_arg_flag_value("--crate-name").as_deref() == Some("panic_abort")
        {
            cmd.arg("-C").arg("panic=abort");
        }
    }

    if target_crate {
        cmd.args(bsan_rustflags());
    }

    // Forward everything else.
    cmd.args(args);

    if verbose > 0 {
        eprintln!("[cargo-bsan rustc] target_crate={target_crate}");
    }
    debug_cmd("[cargo-bsan rustc]", verbose, &cmd);
    exec(cmd);
}

fn ensure_sysroot(
    subcommand: &BsanCommand,
    rustc_version: &VersionMeta,
    verbose: usize,
    quiet: bool,
) -> PathBuf {
    let host_sysroot = get_host_sysroot_dir(verbose);
    let Some(bsan_plugin) = find_library("BSAN_PLUGIN", &host_sysroot, "libbsan_plugin.so") else {
        show_error!(
            "failed to locate the BorrowSanitizer LLVM plugin (libbsan_plugin.so) within the host sysroot: {}",
                host_sysroot.display()
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

fn bsan_rustflags() -> Vec<String> {
    let rt = expect_env_path("BSAN_RT");
    let plugin = expect_env_path("BSAN_PLUGIN");
    let rt_dir = rt.parent().unwrap();
    let mut additional_args = BSAN_DEFAULT_ARGS.iter().map(ToString::to_string).collect::<Vec<_>>();
    additional_args.push(format!("-Zllvm-plugins={}", plugin.display()));
    additional_args.push(format!("-L{}", rt_dir.display()));
    additional_args.push("-lstatic=bsan_rt".to_string());
    additional_args
}
