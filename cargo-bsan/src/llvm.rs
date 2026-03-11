use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use regex::Regex;
use rustc_version::{LlvmVersion, VersionMeta};

use crate::util::{assert_host_binary, show_error, Sysroot};

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
    pub version: LlvmVersion,
    pub clang: PathBuf,
    pub llvm_symbolizer: PathBuf,
    pub lld: PathBuf,
}

impl LlvmTools {
    pub fn new(rustc_version: &VersionMeta, host_sysroot: &Sysroot) -> Self {
        let rustc_llvm_version = rustc_version.llvm_version.clone().unwrap_or_else(|| {
            show_error!("Unable to resolve the LLVM version for the current `rustc`.")
        });

        let clang =
            assert_host_binary(host_sysroot, &format!("clang-{}", rustc_llvm_version.major));
        let llvm_symbolizer = assert_host_binary(host_sysroot, "llvm-symbolizer");

        let clang_llvm_version = assert_llvm_version(&clang);

        if rustc_llvm_version != clang_llvm_version {
            show_error!(
                "Mismatched LLVM versions between `rustc` ({}) and `clang` ({})",
                rustc_llvm_version,
                clang_llvm_version
            );
        }

        let sysroot_target_dir = host_sysroot.target_dir(rustc_version);

        let sysroot_target_bindir = sysroot_target_dir.join("bin");

        let lld = rustc_lld(&sysroot_target_bindir);

        let lld_llvm_version = assert_llvm_version(&lld);

        if rustc_llvm_version != lld_llvm_version {
            show_error!(
                "Mismatched LLVM versions between `rustc` ({}) and `lld` ({})",
                rustc_llvm_version,
                lld_llvm_version
            );
        }

        LlvmTools { version: rustc_llvm_version, clang, llvm_symbolizer, lld }
    }

    pub fn populate_env(&self, cmd: &mut Command) {
        cmd.env("CC", &self.clang);
        cmd.env("CXX", &self.clang);
        cmd.env("LLD", &self.lld);
    }

    #[allow(unused)]
    pub fn carry_env(cmd: &mut Command) {
        for env in ["LLD", "CC", "CXX", "CFLAGS", "CXXFLAGS", "CPPFLAGS"] {
            if let Some(val) = env::var_os(env) {
                cmd.env(env, val);
            }
        }
    }
}

fn assert_llvm_version(binary: &PathBuf) -> LlvmVersion {
    let output = command_output(Command::new(binary).arg("--version")).unwrap_or_else(|| {
        show_error!("Unable to obtain the LLVM version for `{}`", binary.display());
    });

    try_parse_llvm_version(&output).unwrap_or_else(|| {
        show_error!("Unable to parse LLVM version for `{}`, found:\n{output}", binary.display());
    })
}

fn command_output(cmd: &mut Command) -> Option<String> {
    cmd.output().ok().and_then(|output| String::from_utf8(output.stdout).ok())
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
