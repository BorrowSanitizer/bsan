use std::fs::canonicalize;
use std::io;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use path_macro::path;
use rustc_version::VersionMeta;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
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

#[derive(PartialEq)]
pub enum PromptResult {
    Yes, // y/Y/yes
    No,  // n/N/no
         //Print, // p/P/print
}

/// Prompt a user for a answer, looping until they enter an accepted input or nothing
pub fn prompt_user(prompt: &str) -> io::Result<Option<PromptResult>> {
    let mut input = String::new();
    loop {
        print!("{prompt} ");
        io::stdout().flush()?;
        input.clear();
        io::stdin().read_line(&mut input)?;
        match input.trim().to_lowercase().as_str() {
            "y" | "yes" => return Ok(Some(PromptResult::Yes)),
            "n" | "no" => return Ok(Some(PromptResult::No)),
            "" => return Ok(Some(PromptResult::Yes)),
            _ => {
                show_error!("Unrecognized option '{}'\nNOTE: press Ctrl+C to exit", input.trim());
            }
        };
    }
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

// Installs git hooks
pub fn install_git_hooks(root_dir: &PathBuf) -> Result<()> {
    #[derive(Debug, PartialEq, EnumIter)]
    enum GitHook {
        PreCommit,
        PrePush,
    }

    impl GitHook {
        fn value(&self) -> String {
            match *self {
                GitHook::PreCommit => String::from("pre-commit"),
                GitHook::PrePush => String::from("pre-push"),
            }
        }
    }

    let git_hooks_dir = path!(root_dir / ".git" / "hooks");

    let install_hook = |hook: GitHook| {
        let hooks_dir = path!(root_dir / "bsan-script" / "etc");
        let hook_name = hook.value();
        println!("Installing {:?} hook...", &hook_name);

        let hook_path = hooks_dir.join(hook_name.to_string() + ".sh");

        if !hook_path.exists() {
            show_error!("{} script {:?} not found", &hook_name, &hook_path);
        }

        match std::fs::symlink_metadata(path!(&git_hooks_dir / &hook_name)) {
            Ok(metadata) => {
                if metadata.is_symlink() {
                    println!("{:?} hook is already symlinked (added). If you wish to reinstall, remove symlink from {:?}", &hook_name, &git_hooks_dir);
                    return;
                }
            }
            // TODO: Handle NotFound error and propagate other errors
            Err(_) => {}
        };

        let hook_script = hook_name.to_string() + ".sh";
        // We don't support development on Windows yet
        match std::os::unix::fs::symlink(
            path!(hooks_dir / hook_script),
            path!(&git_hooks_dir / &hook_name),
        ) {
            Err(e) => show_error!("Failed to symlink {} script\nFS ERROR: {e}", &hook_name),
            _ => {
                // Check for successful symlink

                match std::fs::symlink_metadata(path!(&git_hooks_dir / &hook_name)) {
                    Ok(metadata) => {
                        if !metadata.is_symlink() {
                            show_error!("Failed to add {:?} hook. Failed symlink", &hook_name);
                        }
                        println!("Successfully added {:?} hook", &hook_name);
                    }
                    Err(e) => show_error!("{:?}", e),
                }
            }
        };
    };

    if prompt_user("Would you like to install git hooks? [Y/n]")?.unwrap() == PromptResult::No {
        return Ok(());
    }

    for hook in GitHook::iter() {
        let hook_name = hook.value();
        if prompt_user(&format!("Would you like to install {} hook? [Y/n]", &hook_name))?.unwrap()
            == PromptResult::No
        {
            continue;
        }

        install_hook(hook);
    }

    Ok(())
}
