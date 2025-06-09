use std::fs::{self, canonicalize, File};
use std::io;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use path_macro::path;
use rustc_version::VersionMeta;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use xshell::{cmd, Cmd, Shell};
use xz2::bufread::XzDecoder;

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
}

/// Prompt a user for a answer, looping until they enter an accepted input or nothing
pub fn prompt_user(prompt: &str) -> Result<Option<PromptResult>> {
    if is_running_on_ci() {
        return Ok(Some(PromptResult::Yes));
    } else {
        let mut input = String::new();
        print!("{prompt} ");
        io::stdout().flush()?;
        input.clear();
        io::stdin().read_line(&mut input)?;
        match input.trim().to_lowercase().as_str() {
            "y" | "yes" => return Ok(Some(PromptResult::Yes)),
            "n" | "no" => return Ok(Some(PromptResult::No)),
            "" => return Ok(Some(PromptResult::Yes)),
            _ => {
                eprintln!("Unrecognized option '{}'.", input.trim());
                Ok(None)
            }
        }
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

        let hook_path = path!(hooks_dir / format!("{hook_name}.sh"));

        if !hook_path.exists() {
            show_error!("{} script {:?} not found", &hook_name, &hook_path);
        }

        if let Ok(metadata) = std::fs::symlink_metadata(path!(&git_hooks_dir / &hook_name))
            && metadata.is_symlink()
        {
            println!("{:?} hook is already symlinked (added). If you wish to reinstall, remove symlink from {:?}", &hook_name, &git_hooks_dir);
            return;
        }

        let hook_script = format!("{hook_name}.sh");
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

static CURL_FLAGS: &[&str] = &[
    // follow redirect
    "--location",
    // timeout if speed is < 10 bytes/sec for > 30 seconds
    "--speed-time",
    "30",
    "--speed-limit",
    "10",
    // timeout if cannot connect within 30 seconds
    "--connect-timeout",
    "30",
    // if there is an error, don't restart the download,
    // instead continue where it left off.
    "--continue-at",
    "-",
    // retry up to 3 times.  note that this means a maximum of 4
    // attempts will be made, since the first attempt isn't a *re*try.
    "--retry",
    "3",
    // show errors, even if --silent is specified
    "--show-error",
    // set timestamp of downloaded file to that of the server
    "--remote-time",
    // fail on non-ok http status
    "--fail",
];

fn extract_curl_version(out: &[u8]) -> semver::Version {
    let out = String::from_utf8_lossy(out);
    // The output should look like this: "curl <major>.<minor>.<patch> ..."
    out.lines()
        .next()
        .and_then(|line| line.split(" ").nth(1))
        .and_then(|version| semver::Version::parse(version).ok())
        .unwrap_or(semver::Version::new(1, 0, 0))
}

fn curl_version(sh: &Shell) -> semver::Version {
    let curl = cmd!(sh, "curl -V");
    let Ok(out) = curl.output() else { return semver::Version::new(1, 0, 0) };
    let out = out.stdout;
    extract_curl_version(&out)
}

pub fn download_file(
    sh: &Shell,
    url: &Path,
    destination: &Path,
    help_on_error: &str,
) -> Result<()> {
    println!("downloading {}", url.display());

    if destination.exists() {
        fs::remove_file(destination)?;
    }

    let mut curl: Cmd<'_> = cmd!(sh, "curl");
    curl = curl.args([
        // output file
        "--output",
        destination.to_str().unwrap(),
    ]);
    curl = curl.args(CURL_FLAGS);
    curl = curl.arg(url);

    if is_running_on_ci() {
        curl = curl.arg("--silent");
    } else {
        curl = curl.arg("--progress-bar");
    }
    // --retry-all-errors was added in 7.71.0, don't use it if curl is old.
    if curl_version(sh) >= semver::Version::new(7, 71, 0) {
        curl = curl.arg("--retry-all-errors");
    }

    if curl.quiet().run().is_err() {
        if !help_on_error.is_empty() {
            show_error!("{help_on_error}");
        }
        std::process::exit(1);
    }
    Ok(())
}

pub fn unpack(tarball: &Path, dst: &Path, pattern: &str) -> Result<()> {
    if !dst.exists() {
        std::fs::create_dir_all(dst)?;
    }
    println!("extracting {}", tarball.display());
    // `tarball` ends with `.tar.xz`; strip that suffix
    // example: `rust-dev-nightly-x86_64-unknown-linux-gnu`
    let uncompressed_filename =
        Path::new(tarball.file_name().expect("missing tarball filename")).file_stem().unwrap();
    let directory_prefix = Path::new(Path::new(uncompressed_filename).file_stem().unwrap());

    // decompress the file
    let data = File::open(tarball)?;
    let decompressor = XzDecoder::new(BufReader::new(data));
    let mut tar = tar::Archive::new(decompressor);

    for member in tar.entries()? {
        let mut member = member?;
        let original_path = member.path()?.into_owned();
        if original_path == directory_prefix {
            continue;
        }
        let mut short_path = original_path.strip_prefix(directory_prefix)?;
        short_path = short_path.strip_prefix(pattern).unwrap_or(short_path);
        let dst_path = dst.join(short_path);

        if !member.unpack_in(dst)? {
            panic!("path traversal attack ??");
        }
        let src_path = dst.join(original_path);
        if src_path.is_dir() && dst_path.exists() {
            continue;
        }
        move_file(src_path, dst_path)?;
    }
    let dst_dir = dst.join(directory_prefix);
    if dst_dir.exists() {
        fs::remove_dir_all(&dst_dir)?;
    }
    Ok(())
}

/// Rename a file if from and to are in the same filesystem or
/// copy and remove the file otherwise
fn move_file<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> io::Result<()> {
    match fs::rename(&from, &to) {
        Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
            std::fs::copy(&from, &to)?;
            std::fs::remove_file(&from)
        }
        r => r,
    }
}
