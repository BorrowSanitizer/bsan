#![feature(rustc_private)]

mod arg;
mod llvm;
mod phases;
mod setup;
mod util;

use std::env;

use phases::*;

use crate::util::*;

fn main() {
    env_logger::init();
    let mut args = env::args();

    // Skip binary name.
    args.next().unwrap();

    if env::var_os("BSAN_CALLED_FROM_SETUP").is_some() {
        phase_rustc(args, RustcPhase::Setup);
        return;
    }

    let Some(first) = args.next() else {
        show_error!(
            "`cargo-bsan` called without first argument; please only invoke this binary through `cargo bsan`"
        )
    };

    match first.as_str() {
        "bsan" => phase_cargo_bsan(args),
        arg if arg == env::var("RUSTC").unwrap_or_else(|_| {
            show_error!(
                "`cargo-bsan` called without RUSTC set; please only invoke this binary through `cargo bsan`"
            )
        }) => {
            // If the first arg is equal to the RUSTC env variable (which should be set at this
            // point), then we need to behave as rustc. This is the somewhat counter-intuitive
            // behavior of having both RUSTC and RUSTC_WRAPPER set
            // (see https://github.com/rust-lang/cargo/issues/10886).
            phase_rustc(args, RustcPhase::Build)
        }
        _ => {
            show_error!(
                "`cargo-bsan` failed to recognize which phase of the build process this is, please report a bug.\nThe command-line arguments were: {:#?}",
                Vec::from_iter(env::args()),
            );
        }
    }
}
