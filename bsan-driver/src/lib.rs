#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_session;
mod callbacks;
use std::env;

pub use callbacks::BSanCallBacks;
pub const BSAN_BUG_REPORT_URL: &str = "https://github.com/BorrowSanitizer/rust/issues/new";

pub const BSAN_DEFAULT_ARGS: &[&str] =
    &["--cfg=bsan", "-Copt-level=0", "-Zmir-opt-level=0", "-Cpasses=bsan", "-Zmir-emit-retag=full"];

/// Execute a compiler with the given CLI arguments and callbacks.
pub fn run_compiler(mut args: Vec<String>, target_crate: bool, callbacks: &mut BSanCallBacks) -> ! {
    if target_crate {
        let mut additional_args =
            BSAN_DEFAULT_ARGS.iter().map(ToString::to_string).collect::<Vec<_>>();

        let plugin = env::var("BSAN_PLUGIN").expect("BSAN_PLUGIN environment variable not set.");
        additional_args.push(format!("-Zllvm-plugins={plugin}"));

        let runtime =
            env::var_os("BSAN_RT_DIR").expect("BSAN_RT_DIR environment variable not set.");
        let rt = runtime.to_string_lossy();
        additional_args.push(format!("-L{rt}"));
        additional_args.push("-lstatic=bsan_rt".to_string());

        args.splice(1..1, additional_args);
    }
    rustc_driver::run_compiler(&args, callbacks);
    std::process::exit(0)
}
