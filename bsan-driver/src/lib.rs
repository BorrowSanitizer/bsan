#![feature(rustc_private)]

extern crate rustc_driver;

use std::env;
use std::path::PathBuf;
use std::process::exit;

pub fn show_error_(msg: &impl std::fmt::Display) -> ! {
    eprintln!("{msg}");
    std::process::exit(1)
}

macro_rules! show_error {
    ($($tt:tt)*) => { show_error_(&format_args!($($tt)*)) };
}

pub const BSAN_BUG_REPORT_URL: &str = "https://github.com/BorrowSanitizer/bsan/issues/new";
pub const BSAN_DEFAULT_ARGS: &[&str] = &[
    "--cfg=bsan",
    "-Copt-level=0",
    "-Zmir-opt-level=0",
    "-Cpasses=bsan",
    "-Zcodegen-emit-retag=true",
    "-Cforce-frame-pointers=yes",
    "-Zmir-preserve-ub",
    "-Zllvm-emit-lifetime-markers",
    "-Zinline-llvm=no",
    "-Cembed-bitcode=yes",
    "-Cdebuginfo=2",
    "-Zverify-llvm-ir",
];

static BSAN_RT_EXPECTED: &str = "libbsan_rt.a";
static BSAN_PLUGIN_EXPECTED: &str = "libbsan_plugin.so";

pub struct Config {
    args: Vec<String>,
}

impl Config {
    pub fn new(raw_args: Vec<String>) -> Self {
        let (mut args, target_crate) = {
            if env::var("PRINT_RUSTFLAGS").is_ok() {
                println!("{}", Self::bsan_rustflags().join(" "));
                exit(0);
            }
            // If the `BSAN_BE_RUSTC` environment variable is set, we are being invoked as
            // rustc to build a crate for either the "target" architecture, or the "host"
            // architecture. In this case, "target" and "host" are the same platform, since we do not
            // support cross-compilation. However, "target" also indicates that the program needs
            // to be instrumented, while "host" indicates that it is a build script or procedural
            // macro, which we can skip.
            if let Ok(crate_kind) = env::var("BSAN_BE_RUSTC") {
                let is_target = match crate_kind.as_str() {
                    "host" => false,
                    "target" => true,
                    _ => show_error!("Invalid value for `BSAN_BE_RUSTC`: {crate_kind:?}"),
                };
                (raw_args, is_target)
            } else {
                (raw_args, false)
            }
        };
        if target_crate {
            args.splice(1..1, Self::bsan_rustflags());
        }
        Self { args }
    }

    fn bsan_rustflags() -> Vec<String> {
        let rt = assert_env_file("BSAN_RT", BSAN_RT_EXPECTED);
        let rt = rt.parent().unwrap().to_path_buf();
        let plugin = assert_env_file("BSAN_PLUGIN", BSAN_PLUGIN_EXPECTED);
        let mut additional_args =
            BSAN_DEFAULT_ARGS.iter().map(ToString::to_string).collect::<Vec<_>>();
        additional_args.push(format!("-Zllvm-plugins={}", plugin.display()));
        additional_args.push(format!("-L{}", rt.display()));
        additional_args.push("-lstatic=bsan_rt".to_string());
        additional_args
    }
}

fn assert_env_file(key: &str, expected_file_name: &str) -> PathBuf {
    let rt_var = env::var(key);
    if rt_var.is_err() {
        show_error!("Missing value for variable `{key}`.");
    }
    let rt = PathBuf::from(rt_var.unwrap());
    if !rt.exists() {
        show_error!("The path specified in `{key}` does not exist: {}.", rt.display());
    }
    if !rt.is_file() || !rt.file_name().unwrap().eq(expected_file_name) {
        show_error!(
            "Expected `{key}` to be the path to `{expected_file_name}`, but found: {}",
            rt.display()
        );
    }
    rt
}

struct BSanCallBacks {}
impl rustc_driver::Callbacks for BSanCallBacks {}

/// Execute a compiler with the given CLI arguments and callbacks.
pub fn run_compiler(config: Config) -> ! {
    rustc_driver::run_compiler(&config.args, &mut BSanCallBacks {});
    std::process::exit(0)
}
