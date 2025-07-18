use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use colored::*;
use regex::bytes::Regex;
use rustc_version::VersionMeta;
use ui_test::color_eyre::eyre::{Context, Result};
use ui_test::custom_flags::edition::Edition;
use ui_test::dependencies::DependencyBuilder;
use ui_test::spanned::Spanned;
use ui_test::{ignore_output_conflict, status_emitter, CommandBuilder, Config, Format, Match};

#[derive(Copy, Clone, Debug)]
enum Mode {
    Pass,
    /// Requires annotations
    Fail,
    Panic,
}

pub fn flagsplit(flags: &str) -> Vec<String> {
    // This code is taken from `RUSTFLAGS` handling in cargo.
    flags.split(' ').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
}

struct WithDependencies {
    bless: bool,
}

/// Does *not* set any args or env vars, since it is shared between the test runner and
/// run_dep_mode.
fn bsan_config(
    meta: &VersionMeta,
    path: &str,
    mode: Mode,
    with_dependencies: Option<WithDependencies>,
) -> Config {
    let mut program = CommandBuilder::rustc();
    program.program = bsan_path();
    let mut config = Config {
        host: Some(meta.host.to_owned()),
        target: Some(meta.host.to_owned()),
        program,
        out_dir: PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("bsan_ui"),
        ..Config::rustc(path)
    };

    config.comment_defaults.base().exit_status = match mode {
        Mode::Pass => Some(0),
        Mode::Fail => Some(1),
        Mode::Panic => Some(101),
    }
    .map(Spanned::dummy)
    .into();

    config.comment_defaults.base().require_annotations =
        Spanned::dummy(matches!(mode, Mode::Fail)).into();

    config.comment_defaults.base().normalize_stderr =
        stderr_filters().iter().map(|(m, p)| (m.clone(), p.to_vec())).collect();
    config.comment_defaults.base().normalize_stdout =
        stdout_filters().iter().map(|(m, p)| (m.clone(), p.to_vec())).collect();

    config.comment_defaults.base().add_custom("edition", Edition("2021".into()));

    if let Some(WithDependencies { bless }) = with_dependencies {
        let sysroot =
            env::var("BSAN_SYSROOT").expect("BSAN_SYSROOT must be set to run the ui test suite");

        config.comment_defaults.base().set_custom(
            "dependencies",
            DependencyBuilder {
                program: CommandBuilder {
                    // Set the `cargo-miri` binary, which we expect to be in the same folder as the `miri` binary.
                    // (It's a separate crate, so we don't get an env var from cargo.)
                    program: bsan_path()
                        .with_file_name(format!("cargo-bsan{}", env::consts::EXE_SUFFIX)),
                    args: ["bsan", "run"].into_iter().map(Into::into).collect(),
                    envs: vec![
                        ("RUSTFLAGS".into(), None),
                        ("BSAN_SYSROOT".into(), Some(sysroot.as_str().into())),
                    ],
                    ..CommandBuilder::cargo()
                },
                crate_manifest_path: Path::new("test_dependencies").join("Cargo.toml"),
                build_std: None,
                bless_lockfile: bless,
            },
        );
    }
    config
}

fn run_tests(
    mode: Mode,
    path: &str,
    meta: &VersionMeta,
    with_dependencies: bool,
    tmpdir: &Path,
) -> Result<()> {
    // Handle command-line arguments.
    let mut args = ui_test::Args::test()?;
    args.bless |= env::var_os("RUSTC_BLESS").is_some_and(|v| v != "0");

    let with_dependencies = with_dependencies.then_some(WithDependencies { bless: args.bless });

    let mut config = bsan_config(meta, path, mode, with_dependencies);
    config.with_args(&args);
    config.bless_command = Some("./xb ui --bless".into());

    if env::var_os("BSAN_SKIP_UI_CHECKS").is_some() {
        assert!(!args.bless, "cannot use RUSTC_BLESS and MIRI_SKIP_UI_CHECKS at the same time");
        config.output_conflict_handling = ignore_output_conflict;
    }
    // Let the tests know where to store temp files (they might run for a different target, which can make this hard to find).
    config.program.envs.push(("BSAN_TEMP".into(), Some(tmpdir.to_owned().into())));
    // If a test ICEs, we want to see a backtrace.
    config.program.envs.push(("RUST_BACKTRACE".into(), Some("1".into())));

    // Add some flags we always want.
    config.program.args.insert(
        0,
        format!(
            "--sysroot={}",
            env::var("BSAN_SYSROOT").expect("BSAN_SYSROOT must be set to run the ui test suite")
        )
        .into(),
    );
    config.program.args.push("-Dwarnings".into());
    config.program.args.push("-Dunused".into());
    config.program.args.push("-Ainternal_features".into());
    if let Ok(extra_flags) = env::var("BSANFLAGS") {
        for flag in extra_flags.split_whitespace() {
            config.program.args.push(flag.into());
        }
    }
    config.program.args.push("-Zui-testing".into());

    eprintln!("   Compiler: {}", config.program.display());
    ui_test::run_tests_generic(
        // Only run one test suite. In the future we can add all test suites to one `Vec` and run
        // them all at once, making best use of systems with high parallelism.
        vec![config],
        // The files we're actually interested in (all `.rs` files).
        ui_test::default_file_filter,
        // This could be used to overwrite the `Config` on a per-test basis.
        |_, _| {},
        // No GHA output as that would also show in the main rustc repo.
        match args.format {
            Format::Terse => status_emitter::Text::quiet(),
            Format::Pretty => status_emitter::Text::verbose(),
        },
    )
}

macro_rules! regexes {
    ($name:ident: $($regex:expr => $replacement:expr,)*) => {
        fn $name() -> &'static [(Match, &'static [u8])] {
            static S: OnceLock<Vec<(Match, &'static [u8])>> = OnceLock::new();
            S.get_or_init(|| vec![
                $((Regex::new($regex).unwrap().into(), $replacement.as_bytes()),)*
            ])
        }
    };
}

regexes! {
    stdout_filters:
    // Windows file paths
    r"\\"                           => "/",
    // erase borrow tags
    "<[0-9]+>"                      => "<TAG>",
    "<[0-9]+="                      => "<TAG=",
}

regexes! {
    stderr_filters:
    // erase line and column info
    r"\.rs:[0-9]+:[0-9]+(: [0-9]+:[0-9]+)?" => ".rs:LL:CC",
    // erase alloc ids
    "alloc[0-9]+"                    => "ALLOC",
    // erase thread ids
    r"unnamed-[0-9]+"               => "unnamed-ID",
    // erase borrow tags
    "<[0-9]+>"                       => "<TAG>",
    "<[0-9]+="                       => "<TAG=",
    // normalize width of Tree Borrows diagnostic borders (which otherwise leak borrow tag info)
    "(─{50})─+"                      => "$1",
    // erase whitespace that differs between platforms
    r" +at (.*\.rs)"                 => " at $1",
    // erase generics in backtraces
    "([0-9]+: .*)::<.*>"             => "$1",
    // erase long hexadecimals
    r"0x[0-9a-fA-F]+[0-9a-fA-F]{2,2}" => "$$HEX",
    // erase specific alignments
    "alignment [0-9]+"               => "alignment ALIGN",
    "[0-9]+ byte alignment but found [0-9]+" => "ALIGN byte alignment but found ALIGN",
    // erase thread caller ids
    r"call [0-9]+"                  => "call ID",
    // erase platform module paths
    r"\bsys::([a-z_]+)::[a-z]+::"   => "sys::$1::PLATFORM::",
    // Windows file paths
    r"\\"                           => "/",
    // erase Rust stdlib path
    "[^ \n`]*/(rust[^/]*|checkout)/library/" => "RUSTLIB/",
    // erase platform file paths
    r"\bsys/([a-z_]+)/[a-z]+\b"     => "sys/$1/PLATFORM",
    // erase paths into the crate registry
    r"[^ ]*/\.?cargo/registry/.*/(.*\.rs)"  => "CARGO_REGISTRY/.../$1",
}

enum Dependencies {
    WithDependencies,
    WithoutDependencies,
}

use Dependencies::*;

fn ui(
    mode: Mode,
    path: &str,
    meta: &VersionMeta,
    with_dependencies: Dependencies,
    tmpdir: &Path,
) -> Result<()> {
    let msg = format!("## Running ui tests in {path}.");
    eprintln!("{}", msg.green().bold());

    let with_dependencies = match with_dependencies {
        WithDependencies => true,
        WithoutDependencies => false,
    };
    run_tests(mode, path, meta, with_dependencies, tmpdir)
        .with_context(|| format!("ui tests in {path} failed"))
}

fn bsan_path() -> PathBuf {
    let driver = env::var("BSAN_DRIVER").expect("BSAN_DRIVER must be set to run the ui test suite");
    PathBuf::from(driver)
}

fn get_version_info() -> VersionMeta {
    let mut cmd = Command::new(bsan_path());
    cmd.env("BSAN_BE_RUSTC", "host");
    VersionMeta::for_command(cmd).expect("Failed to parse rustc version info")
}

fn main() -> Result<()> {
    ui_test::color_eyre::install()?;
    let tmpdir = tempfile::Builder::new().prefix("bsan-uitest-").tempdir()?;
    let meta = get_version_info();
    let _args = std::env::args_os();

    ui(Mode::Pass, "tests/pass", &meta, WithoutDependencies, tmpdir.path())?;
    ui(Mode::Pass, "tests/pass-dep", &meta, WithDependencies, tmpdir.path())?;
    ui(Mode::Panic, "tests/panic", &meta, WithDependencies, tmpdir.path())?;
    ui(Mode::Fail, "tests/fail", &meta, WithoutDependencies, tmpdir.path())?;
    ui(Mode::Fail, "tests/fail-dep", &meta, WithDependencies, tmpdir.path())?;
    Ok(())
}
