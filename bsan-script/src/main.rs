// Our build script combines many preexisting components from Miri's build script
// and the Rust compiler's bootstrap script.
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use commands::Component;
//mod commands;
mod commands;
mod env;
mod setup;
mod stats;
mod utils;

static TOOLCHAIN_NAME: &str = "bsan";
static DEPENDENCIES: &[&str] = &["cmake", "ninja", "curl", "clang", "clang-tidy", "python3"];
static TARGETS: &[&str] = &["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"];

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
        #[arg(long)]
        allow_unsafe_deps: bool,
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
    /// Instrument a Rust program with BorrowSanitizer.
    /// Emits both LLVM IR (*.ll) and MIR
    Inst {
        file: String,
        #[arg(long)]
        debug: bool,
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
        /// Check that files are formatted.
        #[arg(long)]
        check: bool,
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
        /// Retain the current sysroot, instead of rebuilding
        /// it from scratch.
        #[arg(long)]
        keep_sysroot: bool,

        #[arg(long)]
        allow_unsafe_deps: bool,
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
    Miri {
        /// Components to test.
        #[arg(value_enum, hide_default_value(true), default_values_t = all_components!())]
        components: Vec<Component>,
        /// Flags that are passed through to the test harness.
        #[arg(allow_hyphen_values(true), last(true))]
        args: Vec<String>,
    },
    /// Try all `should-*` tests
    Fix {
        /// Retain the current sysroot, instead of rebuilding
        /// it from scratch.
        #[arg(long)]
        keep_sysroot: bool,
    },
    /// Show repository test metrics (counts of passing/failing/false positives/negatives)
    Stats,
}

#[derive(Parser)]
#[command(after_help = "Environment variables:
  CARGO_EXTRA_FLAGS: Pass extra flags to all cargo invocations")]
pub struct Cli {
    /// Path to the local directory where the toolchain will be installed.
    #[arg(long)]
    install_from: Option<PathBuf>,
    /// Silence build output
    #[arg(short, long)]
    quiet: bool,
    /// Skips prompts, defaulting to "yes" in most cases.
    #[arg(short, long)]
    skip: bool,
    /// Installs the toolchain into the given directory
    #[arg(long)]
    toolchain_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

fn main() -> Result<()> {
    let args = std::env::args();
    let cli = Cli::parse_from(args);
    cli.command.exec(cli.quiet, cli.skip, cli.toolchain_dir, cli.install_from)?;
    Ok(())
}
