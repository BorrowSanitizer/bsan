use std::fs::{self};
use std::path::{Path, PathBuf};

use anyhow::Result;
use path_macro::path;
use rustc_version::VersionMeta;
use xshell::{cmd, Shell};

use crate::env::BsanConfig;
use crate::utils::{
    self, active_toolchain, ensure_directory_is_empty, prompt_user_unless, show_error,
    version_meta, PromptResult,
};
use crate::TOOLCHAIN_NAME;

static INSTALL_PROMPT: &str = "You need to install the latest version of our custom Rust toolchain (`bsan`) to build BorrowSanitizer. Continue?";

pub struct ToolchainConfig {
    pub llvm_cmake: LLVMCmake,
    pub meta: VersionMeta,
}

pub fn setup_toolchain(
    sh: &Shell,
    host: &VersionMeta,
    config: &mut BsanConfig,
    toolchain_dir: &Path,
    root_dir: &Path,
    skip_prompt: bool,
) -> Result<ToolchainConfig> {
    let meta = ensure_toolchain(sh, host, config, toolchain_dir, skip_prompt)?;
    let llvm_cmake = ensure_llvm(sh, root_dir)?;
    Ok(ToolchainConfig { llvm_cmake, meta })
}
fn ensure_toolchain(
    sh: &Shell,
    host: &VersionMeta,
    config: &mut BsanConfig,
    toolchain_dir: &Path,
    skip_prompt: bool,
) -> Result<VersionMeta> {
    // If we have the `bsan` toolchain installed, then we've either already
    // run the setup script, or we're in our Docker container, which has all of
    // the dependencies that we need. Once we set the active toolchain, we can
    // bail out.
    let metadata = if let Ok(meta) = version_meta(sh, TOOLCHAIN_NAME)
        && let Some(ref commit_hash) = meta.commit_hash
        && commit_hash == &config.sha
    {
        if active_toolchain()? != TOOLCHAIN_NAME {
            cmd!(sh, "rustup override set {TOOLCHAIN_NAME}").run()?;
        }
        Some(meta)
    } else {
        None
    };

    // Let's make sure that we have all of the right dependencies
    for dep in config.dependencies.iter() {
        if which::which(dep).is_err() {
            show_error!("Unable to find `{dep}`, is it installed?");
        }
    }

    if let Some(meta) = metadata {
        return Ok(meta);
    } else {
        // First, check if the current platform is supported.
        let current_target = &host.host;
        if !config.targets.contains(&host.host) {
            show_error!("The current target `{current_target}` is not supported.");
        }
        // If we've passed these checks, then let's do the expensive step of
        // downloading and installing our custom toolchain.
        if let Some(PromptResult::Yes) = prompt_user_unless(skip_prompt, INSTALL_PROMPT)? {
            fs::create_dir_all(toolchain_dir)?;
            install_toolchain(sh, host, config, toolchain_dir)
        } else {
            std::process::exit(0)
        }
    }
}

fn install_toolchain(
    sh: &Shell,
    host: &VersionMeta,
    config: &mut BsanConfig,
    toolchain_dir: &Path,
) -> Result<VersionMeta> {
    cmd!(sh, "rustup toolchain uninstall {TOOLCHAIN_NAME}").quiet().run()?;

    let target = &host.host;
    let version = &config.version;
    let archive_postfix: String = version.to_string();
    let artifact_url = path!(&config.artifact_url / &config.tag);
    let help_on_error = "Failed to download the custom Rust toolchain.";

    let tmp_dir = sh.create_temp_dir()?;

    let download_unpack_install = |prefix: &str, needs_target: bool| -> Result<()> {
        // Download the .tar.xz file

        let mut tar_file_name = format!("{prefix}-{archive_postfix}");
        if needs_target {
            tar_file_name = format!("{tar_file_name}-{target}");
        }
        let tar_file = format!("{tar_file_name}.tar.xz");

        let tar_path = path!(tmp_dir.path() / tar_file);
        utils::download_file(sh, &path!(artifact_url / tar_file), &tar_path, help_on_error)?;

        // Unpack it into a .tmp subdirectory
        let out_dir = path!(tmp_dir.path() / prefix);
        utils::unpack(&tar_path, &out_dir, "")?;
        fs::remove_file(&tar_path)?;

        // Install it into the toolchain directory
        cmd!(sh, "{out_dir}/install.sh --prefix=\"\" --destdir={toolchain_dir}").quiet().run()?;
        fs::remove_dir_all(&out_dir)?;
        Ok(())
    };

    download_unpack_install("rust", true)?;
    download_unpack_install("rustc-dev", true)?;
    download_unpack_install("rust-dev", true)?;
    download_unpack_install("rust-src", false)?;

    let meta = version_meta(sh, TOOLCHAIN_NAME)?;
    config.sha =
        meta.commit_hash.clone().expect("Unable to resolve commit hash for latest toolchain.");
    config.version = meta.semver.to_string();

    cmd!(sh, "rustup override set {TOOLCHAIN_NAME}").quiet().run()?;
    Ok(meta)
}

pub struct LLVMCmake {
    pub common: PathBuf,
    pub llvm: PathBuf,
}

pub fn ensure_llvm(sh: &Shell, root_dir: &Path) -> Result<LLVMCmake> {
    let llvm_dir = path!(root_dir / "llvm-project");
    let llvm_git_dir = path!(llvm_dir / ".git");
    let llvm_gitmodules_dir = path!(".git" / "modules" / "llvm-project");

    let llvm_sparse = root_dir.join("llvm-sparse");
    if !llvm_sparse.exists() {
        show_error!("Unable to find `llvm-sparse` file in the root of the repository.")
    }

    if !(llvm_git_dir.exists() && llvm_gitmodules_dir.exists()) {
        cmd!(sh, "git submodule init {llvm_dir}").run()?;

        ensure_directory_is_empty(&llvm_dir)?;
        ensure_directory_is_empty(&llvm_gitmodules_dir)?;

        let url = cmd!(sh, "git config submodule.llvm-project.url")
            .output()
            .map(|o| String::from_utf8(o.stdout))?
            .unwrap_or_else(|_| {
                show_error!("Unable to resolve the URL of the `llvm-project` submodule.")
            });
        let url = url.trim();

        let branch = cmd!(sh, "git config -f .gitmodules submodule.llvm-project.branch")
            .output()
            .map(|o| String::from_utf8(o.stdout))?
            .unwrap_or_else(|_| {
                show_error!("Unable to resolve the target branch of the `llvm-project` submodule.")
            });
        let branch = branch.trim();

        cmd!(
            sh,
            "git clone --filter=blob:none --no-checkout --depth=1 --branch={branch} {url} {llvm_dir}"
        )
        .run()?;

        cmd!(sh, "git submodule absorbgitdirs {llvm_dir}").run()?;
    }

    let mut sparse_checkout = path!(llvm_gitmodules_dir / "info");
    fs::create_dir_all(&sparse_checkout)?;
    sparse_checkout.push("sparse-checkout");
    if !sparse_checkout.exists() {
        cmd!(sh, "ln -s {llvm_sparse} {sparse_checkout}").run()?;
        cmd!(sh, "git -C llvm-project config core.sparseCheckout true").run()?;
        cmd!(sh, "git --git-dir=llvm-project/.git --work-tree=llvm-project checkout").run()?;
    }

    let link_source = path!(root_dir / "bsan-rt" / "llvm-wrapper");
    let link_target = path!(llvm_dir / "compiler-rt" / "lib" / "bsan");

    if !link_target.exists() {
        cmd!(sh, "ln -s {link_source} {link_target}").run()?;
    }

    Ok(LLVMCmake { llvm: path!(llvm_dir / "llvm" / "cmake"), common: path!(llvm_dir / "cmake") })
}
