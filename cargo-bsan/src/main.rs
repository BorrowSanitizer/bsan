#![feature(rustc_private)]

mod arg;
mod phases;
mod setup;
mod util;

use std::env;

use log::debug;
use phases::*;

use crate::util::*;

const CARGO_BSAN_HELP: &str = r"Runs binary crates and tests with BorrowSanitizer enabled.

Usage:
    cargo bsan [subcommand] [<cargo options>...] [--] [<program/test suite options>...]

Subcommands:
    run, r                   Run binaries
    test, t                  Run tests
    nextest                  Run tests with nextest (requires cargo-nextest installed)
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
        // If there is actually something here, print it.
        print!(" ({version})");
    }
    println!();
}

fn main() {
    env_logger::init();
    let mut args = env::args();
    debug!("args: {args:?}",);

    // Skip binary name.
    args.next().unwrap();
    // Dispatch running as part of sysroot compilation.
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

        arg if Some(arg) == env::var("RUSTC").as_ref().ok().map(|s| s.as_str()) => {
            // If the first arg is equal to the RUSTC env variable (which should be set at this
            // point), then we need to behave as rustc. This is the somewhat counter-intuitive
            // behavior of having both RUSTC and RUSTC_WRAPPER set
            // (see https://github.com/rust-lang/cargo/issues/10886).
            phase_rustc(args, RustcPhase::Build)
        }

        _ => show_help(),
    }
}
