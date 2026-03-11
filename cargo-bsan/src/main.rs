mod arg;
mod llvm;
mod phases;
mod setup;
mod util;

use std::{env, iter};

use phases::*;

use crate::util::*;

/// Returns `true` if our flags look like they may be for rustdoc, i.e., this is cargo calling us to
/// be rustdoc. It's hard to be sure as cargo does not have a RUSTDOC_WRAPPER or an env var that
/// would let us get a clear signal.
fn looks_like_rustdoc() -> bool {
    // The `--test-run-directory` flag only exists for rustdoc and cargo always passes it. Perfect!
    env::args().any(|arg| arg == "--test-run-directory")
}

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

    // The way rustdoc invokes rustc is indistinguishable from the way cargo invokes rustdoc by the
    // arguments alone. `phase_cargo_rustdoc` sets this environment variable to let us disambiguate.
    if env::var_os("BSAN_CALLED_FROM_RUSTDOC").is_some() {
        // ...however, we then also see this variable when rustdoc invokes us as the testrunner!
        // In that case the first argument is `runner` and there are no more arguments.
        match first.as_str() {
            flag if flag.starts_with("--") || flag.starts_with("@") => {
                // This is probably rustdoc invoking us to build the test. But we need to get `first`
                // "back onto the iterator", it is some part of the rustc invocation.
                phase_rustc(iter::once(first).chain(args), RustcPhase::Rustdoc);
            }
            _ => {
                show_error!(
                    "`cargo-bsan` failed to recognize which phase of the build process this is, please report a bug.\n\
                    We are inside BSAN_CALLED_FROM_RUSTDOC.\n\
                    The command-line arguments were: {:#?}",
                    Vec::from_iter(env::args()),
                );
            }
        }
        return;
    }

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
        _ if looks_like_rustdoc() => {
            // This is probably rustdoc. But we need to get `first` "back onto the iterator",
            // it is some part of the rustdoc invocation.
            phase_rustdoc(iter::once(first).chain(args));
        }
        _ => {
            show_error!(
                "`cargo-bsan` failed to recognize which phase of the build process this is, please report a bug.\nThe command-line arguments were: {:#?}",
                Vec::from_iter(env::args()),
            );
        }
    }
}
