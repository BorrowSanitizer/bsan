// The contents of this file have been copied, for the most part,
// from the Rust compiler's bootstrap script.
// https://github.com/rust-lang/rust/blob/master/src/bootstrap/src/core/download.rs

use std::fs::{self, File};
use std::io::{self, BufReader, Write};
use std::path::Path;

use anyhow::Result;
use path_macro::path;
use rustc_version::VersionMeta;
use xshell::{cmd, Cmd, Shell};
use xz2::bufread::XzDecoder;

use crate::env::BsanConfig;
use crate::utils::{self, active_toolchain, is_running_on_ci, show_error, version_meta};
use crate::TOOLCHAIN_NAME;

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

fn download_file(sh: &Shell, url: &Path, destination: &Path, help_on_error: &str) -> Result<()> {
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

    if utils::is_running_on_ci() {
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

fn unpack(tarball: &Path, dst: &Path, pattern: &str) -> Result<()> {
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

pub fn toolchain(
    sh: &Shell,
    host: &VersionMeta,
    config: &BsanConfig,
    toolchain_dir: &Path,
) -> Result<VersionMeta> {
    if let Ok(meta) = version_meta(sh, TOOLCHAIN_NAME) {
        if active_toolchain()? != TOOLCHAIN_NAME {
            cmd!(sh, "rustup override set {TOOLCHAIN_NAME}").run()?;
        }
        return Ok(meta);
    }

    let version = &config.rustc_version;
    let target = &host.host;
    let archive_postfix: String = format!("{version}-dev-{target}.tar.xz");
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
        download_file(sh, &path!(artifact_url / tar_file), &tar_path, help_on_error)?;

        // Unpack it into a .tmp subdirectory
        let out_dir = path!(toolchain_dir / ".tmp" / prefix);
        unpack(&tar_path, &out_dir, "")?;
        fs::remove_file(&tar_path)?;

        // Install it into the toolchain directory
        cmd!(sh, "{out_dir}/install.sh --prefix=\"\" --destdir={toolchain_dir}").quiet().run()?;
        fs::remove_dir_all(&out_dir)?;
        Ok(())
    };

    download_unpack_install("rust")?;
    download_unpack_install("rustc-dev")?;
    download_unpack_install("rust-dev")?;

    cmd!(sh, "rustup toolchain uninstall {TOOLCHAIN_NAME}").quiet().run()?;
    cmd!(sh, "rustup toolchain link {TOOLCHAIN_NAME} {toolchain_dir}").quiet().run()?;
    cmd!(sh, "rustup override set {TOOLCHAIN_NAME}").quiet().run()?;

    version_meta(sh, TOOLCHAIN_NAME)
}

#[allow(dead_code)]
pub fn ask_to_run(cmd: Cmd<'_>, ask: bool, text: &str) -> Result<()> {
    // Disable interactive prompts in CI (GitHub Actions, Travis, AppVeyor, etc).
    // Azure doesn't set `CI` though (nothing to see here, just Microsoft being Microsoft),
    // so we also check their `TF_BUILD`.
    let is_ci = is_running_on_ci();
    if ask && !is_ci {
        let mut buf = String::new();
        print!("I will run `{cmd}` to {text}. Proceed? [Y/n] ");
        io::stdout().flush().unwrap();
        io::stdin().read_line(&mut buf).unwrap();
        match buf.trim().to_lowercase().as_ref() {
            // Proceed.
            "" | "y" | "yes" => {}
            "n" | "no" => show_error!("aborting as per your request"),
            a => show_error!("invalid answer `{}`", a),
        };
    } else {
        eprintln!("Running `{cmd:?}` to {text}.");
    }
    cmd.run()?;
    Ok(())
}
