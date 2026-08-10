use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use regex::Regex;
use rustc_version::{LlvmVersion, VersionMeta};

use crate::util::{assert_host_bin, expect_env_path, show_error, show_error_cmd, Sysroot};

fn rustc_lld(sysroot_target_bindir: &Path) -> PathBuf {
    let lld_binary = |prefix: &str| format!("{}.lld", prefix);
    cfg_if::cfg_if! {
        if #[cfg(target_family = "unix")] {
            sysroot_target_bindir.join("gcc-ld").join(lld_binary("ld"))
        } else {
            show_error!("Only unix targets are supported.");
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LlvmTools {
    pub clang: PathBuf,
    pub llvm_symbolizer: PathBuf,
    pub lld: PathBuf,
    pub llvm_config: PathBuf,
}

impl LlvmTools {
    pub fn new(rustc_version: &VersionMeta, host_sysroot: &Sysroot) -> Self {
        let rustc_llvm_version = rustc_version.llvm_version.clone().unwrap_or_else(|| {
            show_error!("Unable to resolve the LLVM version for the current `rustc`.")
        });

        let llvm_config = assert_host_bin(host_sysroot, "llvm-config");
        assert_rustc_llvm_version(&llvm_config, &rustc_llvm_version);

        let clang = assert_host_bin(host_sysroot, &format!("clang-{}", rustc_llvm_version.major));
        assert_rustc_llvm_version(&clang, &rustc_llvm_version);

        let sysroot_target_dir = host_sysroot.target_dir(rustc_version);
        let sysroot_target_bindir = sysroot_target_dir.join("bin");

        let lld = rustc_lld(&sysroot_target_bindir);
        assert_rustc_llvm_version(&lld, &rustc_llvm_version);

        // llvm-symbolizer is versioned independent to LLVM
        let llvm_symbolizer = assert_host_bin(host_sysroot, "llvm-symbolizer");

        LlvmTools { clang, llvm_symbolizer, lld, llvm_config }
    }

    pub fn populate_env(&self, cmd: &mut Command) {
        cmd.env("LLVM_SYMBOLIZER", &self.clang);
        cmd.env("LLD", &self.lld);
        cmd.env("LLVM_CONFIG", &self.lld);
        // bindgen's clang-sys dependency requires these variables
        // to be set so that it uses our clang to parse headers.
        cmd.env("LIBCLANG_PATH", self.llvm_libdir());
        cmd.env("CLANG_PATH", &self.clang);
    }

    pub fn from_env() -> Self {
        let clang = expect_env_path("CLANG_PATH");
        let llvm_symbolizer = expect_env_path("LLVM_SYMBOLIZER");
        let lld = expect_env_path("LLD");
        let llvm_config = expect_env_path("LLVM_CONFIG");
        Self { clang, llvm_symbolizer, lld, llvm_config }
    }

    pub fn llvm_libdir(&self) -> PathBuf {
        let mut cmd = Command::new(&self.llvm_config);
        cmd.arg("--libdir");

        let Some(path) = command_output(&mut cmd) else {
            show_error_cmd!(cmd, "Unable to resolve the LLVM `lib` directory using `llvm-config`.");
        };
        let path = PathBuf::from(path);
        if !path.try_exists().unwrap() {
            show_error_cmd!(
                cmd,
                "The `lib` directory returned by `llvm-config` does not exist: {}",
                path.display()
            );
        }
        path
    }
}

fn assert_rustc_llvm_version(binary: &PathBuf, expected: &LlvmVersion) -> LlvmVersion {
    let mut cmd = Command::new(binary);
    cmd.arg("--version");
    let output = command_output(&mut cmd).unwrap_or_else(|| {
        show_error_cmd!(cmd, "Unable to obtain the LLVM version.");
    });

    // If the command above executed successfully, then we have a
    // valid path to a binary_file.
    let binary_name = binary.file_name().unwrap();

    let version = try_parse_llvm_version(&output).unwrap_or_else(|| {
        show_error!("Unable to parse LLVM version for `{}`, found:\n{output}", binary.display());
    });

    if version != *expected {
        show_error!(
            "Mismatched LLVM versions between `rustc` ({}) and `{}` ({})",
            expected,
            binary_name.display(),
            version
        );
    }
    version
}

fn command_output(cmd: &mut Command) -> Option<String> {
    let output = cmd.output().ok()?;
    let output = String::from_utf8(output.stdout).ok()?;
    Some(String::from(output.trim()))
}

fn try_parse_llvm_version(version_string: &str) -> Option<LlvmVersion> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let version_regex = RE.get_or_init(|| Regex::new(r"(\d+)\.(\d+).\d+").expect("Invalid regex"));
    let captures = version_regex.captures(version_string)?;
    (captures.len() == 3).then(|| {
        let major = captures.get(1)?.as_str().parse().ok()?;
        let minor = captures.get(2)?.as_str().parse().ok()?;
        Some(LlvmVersion { major, minor })
    })?
}
