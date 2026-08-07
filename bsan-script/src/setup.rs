use std::fs::{self};
use std::path::{Path, PathBuf};

use anyhow::Result;
use path_macro::path;
use rustc_version::VersionMeta;
use xshell::{cmd, Shell};

use crate::env::BsanConfig;
use crate::utils::{
    self, active_toolchain, prompt_user_unless, show_error, version_meta, PromptResult,
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
    build_dir: &Path,
    toolchain_dir: &Path,
    root_dir: &Path,
    skip_prompt: bool,
    local_dir: Option<PathBuf>,
) -> Result<ToolchainConfig> {
    let meta = ensure_toolchain(sh, host, config, toolchain_dir, skip_prompt, local_dir)?;
    let llvm_cmake = ensure_llvm_cmake(sh, config, host, build_dir, root_dir)?;
    Ok(ToolchainConfig { llvm_cmake, meta })
}
fn ensure_toolchain(
    sh: &Shell,
    host: &VersionMeta,
    config: &mut BsanConfig,
    toolchain_dir: &Path,
    mut skip_prompt: bool,
    local_dir: Option<PathBuf>,
) -> Result<VersionMeta> {
    // If we have the `bsan` toolchain installed, then we've either already
    // run the setup script, or we're in our Docker container, which has all of
    // the dependencies that we need. Once we set the active toolchain, we can
    // bail out.
    let metadata = if let Ok(meta) = version_meta(sh, TOOLCHAIN_NAME)
        && let Some(ref commit_hash) = meta.commit_hash
        && commit_hash == &config.rust_sha
        && local_dir.is_none()
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
        Ok(meta)
    } else {
        // First, check if the current platform is supported.
        let current_target = &host.host;
        if !config.targets.contains(&host.host) {
            show_error!("The current target `{current_target}` is not supported.");
        }
        // If we've passed these checks, then let's do the expensive step of
        // downloading and installing our custom toolchain.
        skip_prompt = skip_prompt || local_dir.is_some();
        if let Some(PromptResult::Yes) = prompt_user_unless(skip_prompt, INSTALL_PROMPT)? {
            fs::create_dir_all(toolchain_dir)?;
            install_toolchain(sh, host, config, toolchain_dir, local_dir.as_deref())
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
    local_dir: Option<&Path>,
) -> Result<VersionMeta> {
    cmd!(sh, "rustup toolchain uninstall {TOOLCHAIN_NAME}").quiet().run()?;

    let target = &host.host;
    let artifact_url = path!(&config.artifact_url / config.rust_sha);
    let help_on_error = "Failed to download the custom Rust toolchain.";

    let tmp_dir = sh.create_temp_dir()?;

    let download_unpack_install = |prefix: &str, needs_target: bool| -> Result<()> {
        // Download the .tar.xz file
        let mut tar_file_name = format!("{prefix}-nightly");
        if needs_target {
            tar_file_name = format!("{tar_file_name}-{target}");
        }
        let tar_file = format!("{tar_file_name}.tar.xz");

        let tar_path = if let Some(local_dir) = local_dir {
            path!(local_dir / tar_file)
        } else {
            let tar_path = path!(tmp_dir.path() / tar_file);
            utils::download_file(sh, &path!(artifact_url / tar_file), &tar_path, help_on_error)?;
            tar_path
        };

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
    download_unpack_install("rust-dev", true)?;
    download_unpack_install("rust-src", false)?;

    let meta = version_meta(sh, TOOLCHAIN_NAME)?;
    cmd!(sh, "rustup override set {TOOLCHAIN_NAME}").quiet().run()?;
    Ok(meta)
}

pub struct LLVMCmake {
    pub common: PathBuf,
    pub llvm: PathBuf,
}

pub fn ensure_llvm_cmake(
    sh: &Shell,
    config: &BsanConfig,
    host: &VersionMeta,
    build_dir: &Path,
    root_dir: &Path,
) -> Result<LLVMCmake> {
    let target = &host.host;

    let tmp_dir = sh.create_temp_dir()?;
    let help_on_error = "Failed to download the custom rust-dev artifacts.";
    let artifact_url = path!(&config.artifact_url / config.rust_sha);

    let download_unpack_install = |prefix: &str, needs_target: bool| -> Result<()> {
        // Download the .tar.xz file
        let mut tar_file_name = format!("{prefix}-nightly");
        if needs_target {
            tar_file_name = format!("{tar_file_name}-{target}");
        }
        let tar_file = format!("{tar_file_name}.tar.xz");


        let tar_path = path!(tmp_dir.path() / tar_file);
        utils::download_file(sh, &path!(artifact_url / tar_file), &tar_path, help_on_error)?;


        // Unpack it into a .tmp subdirectory
        let out_dir = path!(build_dir / prefix);
        utils::unpack(&tar_path, &out_dir, "")?;
        fs::remove_file(&tar_path)?;
        Ok(())
    };
    download_unpack_install("rust-dev",true);

    let compiler_rt_src = path!(build_dir / "compiler-rt");
    if !compiler_rt_src.exists() {
        show_error!(
            "Unable to locate the source for `compiler-rt` within the sysroot for the `bsan` toolchain."
        );
    }

    let llvm_sparse = path!(root_dir / "bsan-script" / "etc" / "llvm-sparse");
    if !llvm_sparse.exists() {
        show_error!(
            "Unable to locate sparse checkout config file `llvm-sparse` in `bsan-script/etc/`."
        );
    }
    let tmp_dir = sh.create_temp_dir()?;
    let tmp_dir = tmp_dir.path();

    let url = &config.llvm_url;
    let sha = &config.llvm_sha;
    let lockfile = path!(build_dir / ".llvm.lock");

    if !(lockfile.exists() && fs::read_to_string(&lockfile)?.eq(sha)) {
        let _tmp = sh.push_dir(&tmp_dir);
        cmd!(sh, "git init -q .").run()?;
        cmd!(sh, "git remote add origin {url}").run()?;

        cmd!(sh, "git sparse-checkout set --no-cone --stdin")
            .stdin(sh.read_file(&llvm_sparse)?)
            .run()?;

        cmd!(sh, "git fetch -q --depth=1 --filter=tree:0 origin {sha}").run()?;
        cmd!(sh, "git checkout -q FETCH_HEAD").run()?;

        for subdir in ["llvm", "cmake"] {
            cmd!(sh, "cp -fr {subdir} {build_dir}").run()?;
        }
        fs::write(lockfile, sha)?;
    }

    let link_source = path!(root_dir / "bsan-rt" / "llvm-wrapper");
    let link_target = path!(build_dir / "compiler-rt" / "lib" / "bsan");
    if !link_target.exists() {
        cmd!(sh, "ln -fs {link_source} {link_target}").quiet().run()?;
    }
    Ok(LLVMCmake {
        llvm: path!(build_dir / "llvm" / "cmake"),
        common: path!(build_dir / "cmake"),
    })
}
