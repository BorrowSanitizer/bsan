#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_session;

mod callbacks;
use std::env;
use std::path::PathBuf;

pub use callbacks::BSanCallBacks;

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
    "-Zmir-emit-retag=full",
    "-Cforce-frame-pointers=yes",
    "-Zalways-encode-mir",
    "-Zmir-preserve-ub",
    "-Zemit-lifetime-markers",
    "-Zcodegen-emit-retag",
    "-Zinline-llvm=no",
    "-Zinline-mir=no",
];

static BSAN_RT_EXPECTED: &str = "libbsan_rt.a";
static BSAN_PLUGIN_EXPECTED: &str = "libbsan_plugin.so";

pub struct Config {
    args: Vec<String>,
    callbacks: BSanCallBacks,
}

impl Config {
    pub fn new(raw_args: Vec<String>) -> Self {
        let (mut args, target_crate) = {
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
            } else if env::var("RUSTC_WRAPPER").is_ok() {
                // Otherwise, we're being invoked through RUSTC_WRAPPER. This means that our first
                // argument is the path to *this* binary, so we skip it. This is where we can parse
                // any BorrowSanitizer-specific arguments and use them to change our instrumentation
                // or activate other useful features. We also need to skip any arguments that come
                // after the "--" separator, since these will be passed to the compiled binary
                // when it executes.
                let mut rustc_args = vec![];
                for arg in raw_args.iter().skip(1) {
                    if arg == "--" {
                        break;
                    } else {
                        rustc_args.push(arg.to_string());
                    }
                }
                (rustc_args, true)
            } else {
                (raw_args, true)
            }
        };
        if target_crate {
            let rt = assert_env_file("BSAN_RT", BSAN_RT_EXPECTED);
            let rt = rt.parent().unwrap().to_path_buf();

            let plugin = assert_env_file("BSAN_PLUGIN", BSAN_PLUGIN_EXPECTED);

            let mut additional_args =
                BSAN_DEFAULT_ARGS.iter().map(ToString::to_string).collect::<Vec<_>>();
            additional_args.push(format!("-Zllvm-plugins={}", plugin.display()));
            additional_args.push(format!("-L{}", rt.display()));
            additional_args.push("-lstatic=bsan_rt".to_string());
            args.splice(1..1, additional_args);
        }
        Self { args, callbacks: BSanCallBacks {} }
    }
}

fn assert_env_file(key: &str, expected_file_name: &str) -> PathBuf {
    let rt_var = env::var(key);
    if rt_var.is_err() {
        show_error!("Missing value for variable `{key}`.");
    }
    let rt = PathBuf::from(rt_var.unwrap());
    if !rt.exists() {
        show_error!("The path specified in `BSAN_RT` does not exist: {}.", rt.display());
    }
    if !rt.is_file() || !rt.file_name().unwrap().eq(expected_file_name) {
        show_error!(
            "Expected `BSAN_RT` to be the path to `{expected_file_name}`, but found: {}",
            rt.display()
        );
    }
    rt
}

/// Execute a compiler with the given CLI arguments and callbacks.
pub fn run_compiler(mut config: Config) -> ! {
    rustc_driver::run_compiler(&config.args, &mut config.callbacks);
    std::process::exit(0)
}
