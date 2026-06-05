use std::env;
use std::ffi::OsString;
use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use colored::*;
use regex::bytes::Regex;
use rustc_version::VersionMeta;
use ui_test::color_eyre::eyre::{Context, Result};
use ui_test::custom_flags::edition::Edition;
use ui_test::dependencies::DependencyBuilder;
use ui_test::spanned::Spanned;
use ui_test::status_emitter::StatusEmitter;
use ui_test::{CommandBuilder, Config, Match};

mod fix_utils;

use fix_utils::{kill_descendants, FixEmitter, FixResult};

const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Copy, Clone, Debug)]
enum Mode {
    Pass,
    /// Requires annotations
    Fail,
}

pub fn flagsplit(flags: &str) -> Vec<String> {
    // This code is taken from `RUSTFLAGS` handling in cargo.
    flags.split(' ').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
}

struct WithDependencies {
    bless: bool,
}

fn bsan_config(
    target: &VersionMeta,
    path: &str,
    mode: Mode,
    with_dependencies: Option<WithDependencies>,
) -> Config {
    // The BorrowSanitizer driver is rustc-like, so we create a default builder for rustc and modify it
    let mut program = CommandBuilder::rustc();
    let flags = expect_env("BSAN_RUSTFLAGS");
    let flags = flagsplit(&flags).into_iter().map(OsString::from).collect::<Vec<_>>();
    program.args.extend_from_slice(&flags);

    let mut config = Config {
        target: Some(target.host.to_owned()),
        program,
        out_dir: PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("bsan_ui"),
        threads: std::env::var("BSAN_TEST_THREADS")
            .ok()
            .map(|threads| NonZero::new(threads.parse().unwrap()).unwrap()),
        ..Config::rustc(path)
    };

    config.comment_defaults.base().exit_status = match mode {
        Mode::Pass => Some(0),
        Mode::Fail => Some(1),
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
        config.comment_defaults.base().set_custom(
            "dependencies",
            DependencyBuilder {
                program: CommandBuilder {
                    // Set the `cargo-bsan` binary, which we expect to be in the same
                    // folder as the `bsan-driver` binary.
                    // (It's a separate crate, so we don't get an env var from cargo.)
                    program: path_from_env("CARGO_BSAN"),
                    // There is no `cargo bsan build` so we just use `cargo bsan run`.
                    args: ["bsan", "run"].into_iter().map(Into::into).collect(),
                    // Reset `RUSTFLAGS` to work around <https://github.com/rust-lang/rust/pull/119574#issuecomment-1876878344>.
                    envs: vec![("RUSTFLAGS".into(), None)],
                    ..CommandBuilder::cargo()
                },
                crate_manifest_path: Path::new("tests/deps").join("Cargo.toml"),
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
    target: &VersionMeta,
    with_dependencies: bool,
    tmpdir: &Path,
    fix_mode: bool,
) -> Result<FixResult> {
    // Handle/ command-line arguments.
    let mut args = ui_test::Args::test()?;
    args.bless |= env::var_os("RUSTC_BLESS").is_some_and(|v| v != "0");

    let with_dependencies = with_dependencies.then_some(WithDependencies { bless: args.bless });

    let mut config = bsan_config(target, path, mode, with_dependencies);
    config.with_args(&args);
    config.bless_command = Some("./xb test --bless".into());

    // Let the tests know where to store temp files (they might run for a different target, which can make this hard to find).
    config.program.envs.push(("BSAN_TEMP".into(), Some(tmpdir.to_owned().into())));
    // If a test ICEs, we want to see a backtrace.
    config.program.envs.push(("RUST_BACKTRACE".into(), Some("1".into())));
    config.program.envs.push(("BSAN_OPTIONS".into(), Some("stacktrace_max_len=3".into())));
    config
        .program
        .envs
        .push(("BSAN_SYMBOLIZER".into(), Some(path_from_env("BSAN_SYMBOLIZER").into())));

    // Add some flags we always want.
    config
        .program
        .args
        .push(format!("--sysroot={}", path_from_env("BSAN_SYSROOT").display()).into());

    config.program.args.push("-Dwarnings".into());
    config.program.args.push("-Dunused".into());
    config.program.args.push("-Ainternal_features".into());

    config.program.args.push("-Zui-testing".into());

    // Timeout and custom handler enabled for fix mode
    if fix_mode {
        static COLLECTED: OnceLock<Mutex<Vec<(PathBuf, Vec<u8>)>>> = OnceLock::new();
        let finished = Arc::new(AtomicBool::new(false));
        let last_progress = Arc::new(AtomicU64::new(0));
        let start = Instant::now();
        let abort_check = config.abort_check.clone();
        let root_pid = unsafe { libc::getpid() };
        let finished_guard = Arc::clone(&finished);
        let last_progress_guard = Arc::clone(&last_progress);
        std::thread::spawn(move || loop {
            std::thread::sleep(TIMEOUT);
            if finished_guard.load(Ordering::SeqCst) {
                return;
            }
            let elapsed = start.elapsed().as_secs();
            let last = last_progress_guard.load(Ordering::SeqCst);
            if elapsed.saturating_sub(last) >= TIMEOUT.as_secs() {
                abort_check.abort();
                kill_descendants(root_pid);
                return;
            }
        });

        COLLECTED.get_or_init(|| Mutex::new(Vec::new()));
        // Clear in case of re-use
        COLLECTED.get().unwrap().lock().unwrap().clear();
        config.output_conflict_handling = |path, actual, _errors, _config| {
            COLLECTED.get().unwrap().lock().unwrap().push((path.to_path_buf(), actual.to_vec()));
        };

        let failed = Arc::new(AtomicUsize::new(0));
        let aborted = Arc::new(AtomicUsize::new(0));
        let emitter = FixEmitter::new(
            Box::<dyn StatusEmitter>::from(args.format),
            Arc::clone(&failed),
            Arc::clone(&aborted),
            Arc::clone(&last_progress),
            start,
        );

        eprintln!("   Compiler: {}", config.program.display());
        // We don't care about this report, since we're generating our own with `FixResult`
        let _ = ui_test::run_tests_generic(
            vec![config],
            ui_test::default_file_filter,
            |_, _| {},
            Box::new(emitter),
        );
        finished.store(true, Ordering::SeqCst);
        let failed = failed.load(Ordering::SeqCst);
        let aborted = aborted.load(Ordering::SeqCst);
        let results = COLLECTED.get().unwrap().lock().unwrap().clone();
        return Ok(FixResult { failed, aborted, results });
    }

    // Regular UI tests without timeout
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
        Box::<dyn StatusEmitter>::from(args.format),
    )?;
    Ok(FixResult::default())
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
    // normalize width of bars surrounding source locations
    r"(?m)^ +\|" => "   |",
    // erase line numbers in source locations
    r"(?m)^ *[0-9]+ *\|" => "LL |",
    // erase line and column info
    r"\.(rs|c|cpp):[0-9]+:[0-9]+(: [0-9]+:[0-9]+)?" => ".rs:LL:CC",
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
    // erase platform file paths and line numbers
    r"\bsys/([a-z_]+)/[a-z]+\.rs:\d+:\d+\b" => "sys/$1/PLATFORM.rs:l:c",
    // erase platform dependent line retrieved
    r"(-->\s+\S+/PLATFORM\.rs:l:c)\n\s*\|\s*\n\s*\d+\s*\|.*\n\s*\|\s*\n" => "$1\n",
    // erase paths into the crate registry
    r"[^ ]*/\.?cargo/registry/.*/(.*\.(rs|c|cpp))"  => "CARGO_REGISTRY/.../$1",
    // normalize workspace paths to relative
    r"(/.*/tests/)([^ \n]+)" => "bsan/tests/$2",
    r"::h[0-9a-f]{16}\b" => "::HASH",
}

#[allow(unused)]
enum Dependencies {
    WithDependencies,
    WithoutDependencies,
}

use Dependencies::*;

fn ui(
    mode: Mode,
    path: &str,
    target: &VersionMeta,
    with_dependencies: Dependencies,
    tmpdir: &Path,
    fix_mode: bool,
) -> Result<FixResult> {
    let msg = format!("## Running ui tests in {path} for {}", target.host);
    eprintln!("{}", msg.green().bold());

    let with_dependencies = match with_dependencies {
        WithDependencies => true,
        WithoutDependencies => false,
    };
    run_tests(mode, path, target, with_dependencies, tmpdir, fix_mode)
        .with_context(|| format!("ui tests in {path} for {} failed", target.host))
}
fn expect_env(var: &str) -> String {
    env::var(var).expect(&format!("`{}` must be set to run BorrowSanitizer's ui tests.", var))
}

fn path_from_env(var: &str) -> PathBuf {
    let val = expect_env(var);
    let path = PathBuf::from(&val);
    path.try_exists().expect(&format!("`{var}` was set to a nonexistant path: `{val}`"));
    path
}

fn parse_env_count(var: &str) -> Option<usize> {
    env::var(var)
        .ok()
        .map(|val| val.trim().to_string())
        .filter(|val| !val.is_empty())
        .and_then(|val| val.parse::<usize>().ok())
}

fn get_version_info() -> VersionMeta {
    let cmd = Command::new("rustc");
    VersionMeta::for_command(cmd).expect("Failed to parse rustc version info")
}

fn check_for_fix(mode: Mode) -> Result<FixResult> {
    let target = get_version_info();
    let tmpdir = tempfile::Builder::new().prefix("bsan-uitest-").tempdir()?;
    let path = match mode {
        Mode::Pass => "tests/miri-tests/should-pass",
        Mode::Fail => "tests/miri-tests/should-fail",
    };

    ui(mode, path, &target, WithoutDependencies, tmpdir.path(), true)
}

fn print_errors(result: FixResult) {
    for (path, output) in result.results {
        if output.is_empty() || !output.starts_with(b"error: Undefined Behavior:") {
            continue;
        }
        let src = path.with_extension("").with_extension("").with_extension("rs");
        eprintln!("  ✗ Test failed with output: {}", src.display());
        let output = String::from_utf8_lossy(&output);
        for line in output.lines() {
            eprintln!("    {}", line);
        }
        eprintln!();
    }
}

fn main() -> Result<()> {
    ui_test::color_eyre::install()?;

    if env::var("BSAN_SP").is_ok() || env::var("BSAN_SF").is_ok() {
        let sp_count = parse_env_count("BSAN_SP");
        let sf_count = parse_env_count("BSAN_SF");
        let sp_run = sp_count.map(|count| (count, check_for_fix(Mode::Pass)));
        let sf_run = sf_count.map(|count| (count, check_for_fix(Mode::Fail)));
        if let Some((count, Ok(result))) = sp_run {
            let ok = count.saturating_sub(result.failed + result.aborted);
            eprintln!(
                "SHOULD-PASS: {}/{} tests correctly passed with no errors ({} aborted after {}s).\n",
                ok,
                count,
                result.aborted,
                TIMEOUT.as_secs()
            );
            print_errors(result);
        }
        if let Some((count, Ok(result))) = sf_run {
            let ok = count.saturating_sub(result.failed + result.aborted);
            eprintln!(
                "SHOULD-FAIL: {}/{} tests failed with bsan errors ({} aborted after {}s).\n",
                ok,
                count,
                result.aborted,
                TIMEOUT.as_secs()
            );
            print_errors(result);
        }
        return Ok(());
    }

    let target = get_version_info();
    let tmpdir = tempfile::Builder::new().prefix("bsan-uitest-").tempdir()?;
    ui(Mode::Pass, "tests/pass", &target, WithoutDependencies, tmpdir.path(), false)?;
    ui(Mode::Pass, "tests/pass-dep", &target, WithDependencies, tmpdir.path(), false)?;
    ui(Mode::Pass, "tests/miri-tests/pass", &target, WithoutDependencies, tmpdir.path(), false)?;
    if std::env::var("BSAN_ONLY_PASS").is_err() {
        ui(Mode::Fail, "tests/fail", &target, WithoutDependencies, tmpdir.path(), false)?;
        ui(Mode::Fail, "tests/fail-dep", &target, WithDependencies, tmpdir.path(), false)?;
        ui(
            Mode::Fail,
            "tests/miri-tests/fail",
            &target,
            WithoutDependencies,
            tmpdir.path(),
            false,
        )?;
    }
    Ok(())
}
