use std::fs::canonicalize;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use rustc_version::VersionMeta;
use xshell::{cmd, Shell};

pub fn show_error_(msg: &impl std::fmt::Display) -> ! {
    eprintln!("fatal error: {msg}");
    std::process::exit(1)
}

macro_rules! show_error {
    ($($tt:tt)*) => { crate::utils::show_error_(&format_args!($($tt)*)) };
}
pub(crate) use show_error;

#[inline]
pub fn is_running_on_ci() -> bool {
    std::env::var("GITHUB_ACTIONS").is_ok_and(|e| e == "true")
}

pub fn root_dir() -> Result<PathBuf> {
    const BSAN_SCRIPT_ROOT_DIR: &str = env!("CARGO_MANIFEST_DIR");
    Ok(canonicalize(BSAN_SCRIPT_ROOT_DIR)?.parent().unwrap().into())
}

/// Queries the active toolchain for the repository.
pub fn active_toolchain() -> Result<String> {
    let sh = Shell::new()?;
    sh.change_dir(root_dir()?);
    let stdout = cmd!(sh, "rustup show active-toolchain").read()?;
    Ok(stdout.split_whitespace().next().context("Could not obtain active Rust toolchain")?.into())
}

pub fn version_meta(sh: &Shell, toolchain: &str) -> Result<VersionMeta> {
    let target_output = cmd!(sh, "rustc +{toolchain} --version --verbose").quiet().read()?;
    rustc_version::version_meta_for(&target_output).map_err(|e| anyhow!("{e}"))
}

#[allow(dead_code)]
pub fn flagsplit(flags: &str) -> Vec<String> {
    // This code is taken from `RUSTFLAGS` handling in cargo.
    flags.split(' ').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
}

pub fn dylib_suffix(meta: &VersionMeta) -> &str {
    if meta.host.contains("apple-darwin") {
        "dylib"
    } else if meta.host.contains("windows") {
        show_error!("Target {} is not supported.", &meta.host);
    } else {
        "so"
    }
}
