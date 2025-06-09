// Our build script combines many preexisting components from Miri's build script
// and the Rust compiler's bootstrap script.
#![feature(io_error_more)]
use anyhow::Result;
use clap::{command, Parser};
use commands::Component;
//mod commands;
mod commands;
mod env;
mod setup;
mod utils;

static TOOLCHAIN_NAME: &str = "bsan";

#[derive(Clone, Debug, Parser)]
pub enum Command {
    /// Ensures that all dependencies have been installed.
    Setup,
    /// Removes `target` directory
    Clean,
    /// Execute all tests and build steps in CI.
    Ci {
        /// Flags that are passed through to each subcommand.
        #[arg(trailing_var_arg = true, allow_hyphen_values(true))]
        args: Vec<String>,
    },
    /// Build documentation.
    Doc {
        /// Components to document
        #[arg(value_enum, hide_default_value(true), default_values_t = all_components!())]
        components: Vec<Component>,
        /// Flags that are passed through to `cargo doc`.
        #[arg(allow_hyphen_values(true), last(true))]
        args: Vec<String>,
    },
    /// Execute a binary within the target bindir of the sysroot.
    Bin {
        binary_name: String,
        /// Args that are passed through to the executable.
        #[arg(trailing_var_arg = true, allow_hyphen_values(true))]
        args: Vec<String>,
    },
    /// Instrument an LLVM bitcode file using the BorrowSanitizer pass
    Opt {
        /// Flags that are passed through to `opt`.
        #[arg(trailing_var_arg = true, allow_hyphen_values(true))]
        args: Vec<String>,
    },
    /// Format all sources and tests.
    Fmt {
        /// Flags that are passed through to `rustfmt`.
        #[arg(allow_hyphen_values(true), last(true))]
        args: Vec<String>,
    },
    /// Build BorrowSanitizer.
    Build {
        /// Components to build
        #[arg(value_enum, hide_default_value(true), default_values_t = all_components!())]
        components: Vec<Component>,
        /// Flags that are passed through to `cargo build`.
        #[arg(allow_hyphen_values(true), last(true))]
        args: Vec<String>,
    },
    /// Check BorrowSanitizer.
    Check {
        /// Components to check
        #[arg(value_enum, hide_default_value(true), default_values_t = all_components!())]
        components: Vec<Component>,
        /// Flags that are passed through to `cargo check`.
        #[arg(allow_hyphen_values(true), last(true))]
        args: Vec<String>,
    },
    /// Check components with Clippy.
    Clippy {
        /// Components to lint
        #[arg(value_enum, hide_default_value(true), default_values_t = all_components!())]
        components: Vec<Component>,
        /// Flags that are passed through to `cargo clippy`.
        #[arg(allow_hyphen_values(true), last(true))]
        args: Vec<String>,
    },
    /// Run unit tests.
    Test {
        /// Components to test.
        #[arg(value_enum, hide_default_value(true), default_values_t = all_components!())]
        components: Vec<Component>,
        /// Flags that are passed through to the test harness.
        #[arg(allow_hyphen_values(true), last(true))]
        args: Vec<String>,
    },
    /// Run UI tests.
    UI {
        /// Update stdout/stderr reference files.
        #[arg(long)]
        bless: bool,
    },
    /// Installs binaries into the custom toolchain.
    Install {
        /// Components to install
        #[arg(value_enum, hide_default_value(true), default_values_t = all_components!())]
        components: Vec<Component>,
        /// Flags that are passed through to `cargo install`.
        #[arg(allow_hyphen_values(true), last(true))]
        args: Vec<String>,
    },
}

#[derive(Parser)]
#[command(after_help = "Environment variables:
  CARGO_EXTRA_FLAGS: Pass extra flags to all cargo invocations")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

fn main() -> Result<()> {
    let args = std::env::args();
    let args = Cli::parse_from(args);
    args.command.exec()?;
    Ok(())
}
