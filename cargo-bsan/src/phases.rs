use std::path::PathBuf;

use rustc_version::VersionMeta;

use crate::arg::*;
use crate::llvm::LlvmTools;
use crate::setup::*;
use crate::util::*;
use crate::*;

const CARGO_BSAN_HELP: &str = r"Runs binary crates and tests with BorrowSanitizer enabled.

Usage:
    cargo bsan [subcommand] [<cargo options>...] [--] [<program/test suite options>...]

Subcommands:
    run, r                   Run binaries
    test, t                  Run tests
    nextest                  Run tests with nextest (requires `cargo-nextest` to be installed)
    setup                    Only perform automatic setup, but without asking questions (for getting a proper libstd)
    clean                    Clean the BorrowSanitizer cache & target directory

The cargo options are exactly the same as for `cargo run` and `cargo test`, respectively.

Examples:
    cargo bsan run
    cargo bsan test -- test-suite-filter

    cargo bsan setup --print-sysroot
        This will print the path to the generated sysroot (and nothing else) on stdout.
        stderr will still contain progress information about how the build is doing.
";

fn show_help() {
    println!("{CARGO_BSAN_HELP}");
}

fn show_version() {
    print!("bsan {}", env!("CARGO_PKG_VERSION"));
    let version = format!("{} {}", env!("GIT_HASH"), env!("COMMIT_DATE"));
    if version.len() > 1 {
        print!(" ({version})");
    }
    println!();
}

pub const BSAN_DEFAULT_ARGS: &[&str] = &[
    "--cfg=bsan",
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
        .unwrap_or_else(|err| show_error!("Unknown `rustc` version: {err:?}"));

    let targets = get_arg_flag_values("--target").collect::<Vec<_>>();

    // We only allow specifying the host as a target.
    if targets.len() > 1 || targets.iter().any(|t| t != &rustc_version.host) {
        show_error!("Cross-compilation is not supported.");
    }
    let target_sysroot = Sysroot::target();
    let host_sysroot = Sysroot::host(verbose);

    // If cleaning the target directory & sysroot cache,
    // delete them then exit. There is no reason to setup a new
    // sysroot in this execution.
    if let BsanCommand::Clean = subcommand {
        clean_sysroot_dir(&target_sysroot);
        clean_target_dir();
        return;
    }

    let llvm_tools = LlvmTools::new(&rustc_version, &host_sysroot);
    let deps = Dependencies::setup(&host_sysroot);

    setup_sysroot(&subcommand, &rustc_version, &deps, &llvm_tools, &target_sysroot, verbose, quiet);

    let cargo_cmd = match subcommand {
        BsanCommand::Forward(s) => s,
        BsanCommand::Clean => unreachable!(),
        BsanCommand::Setup => {
            if has_arg_flag("--print-rustflags") {
                println!("{}", bsan_rustflags(&deps, &llvm_tools).join(" "))
            }
            return;
        }
    };

    let cargo_bsan_path = env::current_exe()
        .expect("current executable path invalid")
        .into_os_string()
        .into_string()
        .expect("current executable path is not valid UTF-8");

    let mut cmd = Cargo::cmd();
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
    let target_dir = match get_arg_flag_value("--target-dir") {
        Some(dir) => PathBuf::from(dir),
        None => Cargo::get_target_dir(),
    };
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

    if verbose > 0 {
        cmd.env("BSAN_VERBOSE", verbose.to_string()); // This makes the other phases verbose.
    }

    llvm_tools.populate_env(&mut cmd);
    deps.populate_env(&mut cmd);

    cmd.env("RUSTC", rustc_path());
    if let Some(orig_rustdoc) = env::var_os("RUSTDOC") {
        cmd.env("BSAN_ORIG_RUSTDOC", orig_rustdoc);
    }
    cmd.env("RUSTDOC", &cargo_bsan_path);

    cmd.env("BSAN_SYMBOLIZER", llvm_tools.llvm_symbolizer);
    cmd.env("BSAN_SYSROOT", &target_sysroot.as_os_str());

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

    let deps = Dependencies::from_env();
    let llvm_tools = LlvmTools::from_env();

    let verbose = env::var("BSAN_VERBOSE")
        .map_or(0, |verbose| verbose.parse().expect("verbosity flag must be an integer"));

    let target_crate = is_target_crate();

    let mut cmd = rustc();

    // Arguments are treated very differently depending on whether this crate needs to be
    // instrumented by BorrowSanitizer or if it's for a build script / proc macro.
    if target_crate {
        if phase == RustcPhase::Build {
            // We only set the sysroot during an explicit build step.
            // During setup, where we don't have an existing sysroot yet
            // and the bootstrap wrapper adds its own `--sysroot` flag, so we can't set ours.
            // Rustdoc already receives the sysroot via its dedicated phase, so we do not want
            // to set it twice.
            cmd.arg("--sysroot").arg(expect_env("BSAN_SYSROOT"));
        }
        // During setup, patch the panic runtime for `libpanic_abort`
        // (mirroring what bootstrap usually does).
        if phase == RustcPhase::Setup
            && get_arg_flag_value("--crate-name").as_deref() == Some("panic_abort")
        {
            cmd.arg("-C").arg("panic=abort");
        }
    }

    let in_rustdoc = phase == RustcPhase::Rustdoc;

    if target_crate {
        cmd.args(bsan_rustflags(&deps, &llvm_tools));
    }

    // Forward everything else.
    cmd.args(args);

    debug_cmd("[cargo-bsan rustc]", verbose, &cmd);
    if in_rustdoc {
        if verbose > 0 {
            eprintln!("[cargo-miri rustc inside rustdoc]");
        }
        exec_with_pipe(cmd);
    } else {
        if verbose > 0 {
            eprintln!("[cargo-bsan rustc] target_crate={target_crate}");
        }
        exec(cmd);
    }
}

fn bsan_rustflags(deps: &Dependencies, llvm_tools: &LlvmTools) -> Vec<String> {
    let rt_dir = deps.runtime.parent().unwrap();
    let mut additional_args = BSAN_DEFAULT_ARGS.iter().map(ToString::to_string).collect::<Vec<_>>();
    additional_args.push(format!("-Zllvm-plugins={}", deps.llvm_pass.display()));
    additional_args.push(format!("-L{}", rt_dir.display()));
    additional_args.push("-lstatic=bsan_rt".to_string());
    additional_args.push(format!("-Clinker={}", llvm_tools.clang.display()));
    additional_args.push(format!("-Clink-arg=-fuse-ld={}", llvm_tools.lld.display()));
    additional_args
}

pub fn phase_rustdoc(args: impl Iterator<Item = String>) {
    let verbose = env::var("BSAN_VERBOSE")
        .map_or(0, |verbose| verbose.parse().expect("verbosity flag must be an integer"));
    let mut cmd = rustdoc();
    cmd.args(args);

    // For each doctest, rustdoc starts two child processes: first the test is compiled,
    // then the produced executable is invoked. We want to reroute both of these to cargo-miri,
    // such that the first time we'll enter phase_cargo_rustc, and phase_cargo_runner second.
    //
    // rustdoc invokes the test-builder by forwarding most of its own arguments, which makes
    // it difficult to determine when phase_cargo_rustc should run instead of phase_cargo_rustdoc.
    // Furthermore, the test code is passed via stdin, rather than a temporary file, so we need
    // to let phase_cargo_rustc know to expect that. We'll use this environment variable as a flag:
    cmd.env("BSAN_CALLED_FROM_RUSTDOC", "1");

    // The `--test-builder` is an unstable rustdoc features,
    // which is disabled by default. We first need to enable them explicitly:
    cmd.arg("-Zunstable-options");

    // rustdoc needs to know the right sysroot.
    cmd.arg("--sysroot").arg(env::var_os("BSAN_SYSROOT").unwrap());

    // Make rustdoc call us back for the build.
    // (cargo already sets `--test-runtool` to us since we are the cargo test runner.)
    let cargo_bsan_path = env::current_exe().expect("current executable path invalid");
    cmd.arg("--test-builder").arg(&cargo_bsan_path); // invoked by forwarding most arguments

    debug_cmd("[cargo-bsan rustdoc]", verbose, &cmd);
    exec(cmd)
}
