#![feature(rustc_private)]
extern crate rustc_driver;
extern crate rustc_session;

use rustc_session::config::ErrorOutputType;
use rustc_session::EarlyDiagCtxt;

fn main() {
    env_logger::init();
    let early_dcx = EarlyDiagCtxt::new(ErrorOutputType::default());
    rustc_driver::install_ice_hook(bsan_driver::BSAN_BUG_REPORT_URL, |_| ());

    let raw_args = rustc_driver::args::raw_args(&early_dcx);
    let config = bsan_driver::Config::new(raw_args);

    bsan_driver::run_compiler(config)
}
