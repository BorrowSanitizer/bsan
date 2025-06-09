use std::fs::{self};
use std::path::Path;
use anyhow::Result;
use path_macro::path;
use rustc_version::VersionMeta;
use xshell::{cmd, Shell};

use crate::env::BsanConfig;
use crate::utils::{self, active_toolchain, show_error, version_meta};
use crate::TOOLCHAIN_NAME;

pub fn setup(sh: &Shell,
    host: &VersionMeta,
    config: &BsanConfig,
    toolchain_dir: &Path) -> Result<VersionMeta> {
    // If we have the `bsan` toolchain installed, then we've either already
    // run the setup script, or we're in our Docker container, which has all of
    // the dependencies that we need. Once we set the active toolchain, we can
    // bail out. 
    if let Ok(meta) = version_meta(sh, TOOLCHAIN_NAME) 
        && Some(&config.sha) == host.commit_hash.as_ref() {
        if active_toolchain()? != TOOLCHAIN_NAME {
            cmd!(sh, "rustup override set {TOOLCHAIN_NAME}").run()?;
        }
        return Ok(meta);
    }

    // First, check if the current platform is supported.
    let current_target = &host.host;
    if !config.targets.contains(&host.host) {
        show_error!("The current target `{current_target}` is not supported.");
    }

    // Then, let's make sure that we have all of the right dependencies
    for dep in config.dependencies.iter() {
        if which::which(dep).is_err() {
            show_error!("Unable to find `{dep}`, is it installed?");
        }
    }

    // If we've passed these checks, then let's do the expensive step of
    // downloading and installing our custom toolchain.
    toolchain(sh, host, config, toolchain_dir)
}


fn toolchain(
    sh: &Shell,
    host: &VersionMeta,
    config: &BsanConfig,
    toolchain_dir: &Path,
) -> Result<VersionMeta> {

    let target = &host.host;
    let version = &config.version;
    let archive_postfix: String = format!("{version}-{target}.tar.xz");
    let artifact_url = path!(&config.artifact_url / &config.tag);
    let help_on_error = "Failed to download the custom Rust toolchain.";

    let tmp_dir = path!(toolchain_dir / ".tmp");
    if tmp_dir.exists() {
        fs::remove_dir_all(&tmp_dir)?;
    }
    fs::create_dir_all(&tmp_dir)?;

    let download_unpack_install = |prefix: &str| -> Result<()> {
        // Download the .tar.xz file
        let tar_file = format!("{prefix}-{archive_postfix}");
        let tar_path = path!(toolchain_dir / tar_file);
        utils::download_file(sh, &path!(artifact_url / tar_file), &tar_path, help_on_error)?;

        // Unpack it into a .tmp subdirectory
        let out_dir = path!(toolchain_dir / ".tmp" / prefix);
        utils::unpack(&tar_path, &out_dir, "")?;
        fs::remove_file(&tar_path)?;

        // Install it into the toolchain directory
        cmd!(sh, "{out_dir}/install.sh --prefix=\"\" --destdir={toolchain_dir}").quiet().run()?;
        fs::remove_dir_all(&out_dir)?;
        Ok(())
    };

    download_unpack_install("rust")?;
    download_unpack_install("rustc-dev")?;
    download_unpack_install("rust-dev")?;
    download_unpack_install("rust-src")?;

    cmd!(sh, "rustup toolchain uninstall {TOOLCHAIN_NAME}").quiet().run()?;
    cmd!(sh, "rustup toolchain link {TOOLCHAIN_NAME} {toolchain_dir}").quiet().run()?;
    cmd!(sh, "rustup override set {TOOLCHAIN_NAME}").quiet().run()?;

    version_meta(sh, TOOLCHAIN_NAME)
}
