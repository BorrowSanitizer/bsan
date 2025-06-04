#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_session;

use std::env;

use rustc_session::config::ErrorOutputType;
use rustc_session::EarlyDiagCtxt;

const BSAN_BUG_REPORT_URL: &str = "https://github.com/BorrowSanitizer/bsan/issues/new";

fn main() {
    // Initialize logging, diagnostics, and ICE hook.
    env_logger::init();
    let early_dcx = EarlyDiagCtxt::new(ErrorOutputType::default());
    rustc_driver::install_ice_hook(BSAN_BUG_REPORT_URL, |_| ());

    let args = rustc_driver::args::raw_args(&early_dcx);
    let (args, target_crate) = {
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
                _ => panic!("invalid `BSAN_BE_RUSTC` value: {crate_kind:?}"),
            };
            (args, is_target)
        } else {
            // Otherwise, we're being invoked through RUSTC_WRAPPER. This means that our first
            // argument is the path to *this* binary, so we skip it. This is where we can parse
            // any BorrowSanitizer-specific arguments and use them to change our instrumentation
            // or activate other useful features. We also need to skip any arguments that come
            // after the "--" separator, since these will be passed to the compiled binary
            // when it executes.
            let mut rustc_args = vec![];
            for arg in args.iter().skip(1) {
                if arg == "--" {
                    break;
                } else {
                    rustc_args.push(arg.to_string());
                }
            }
            (rustc_args, true)
        }
    };
    rustc_driver::install_ice_hook(rustc_driver::DEFAULT_BUG_REPORT_URL, |_| ());
    bsan_driver::run_compiler(args, target_crate, &mut bsan_driver::BSanCallBacks {})
}
