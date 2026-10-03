use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::{env, fs, io};

use regex::Regex;
use rustc_version::{LlvmVersion, VersionMeta};

use crate::phases::{bsan_cflags, bsan_ldflags};
use crate::setup::{Dependencies, EnvConfig};
use crate::util::{assert_host_bin, expect_env_path, show_error, show_error_cmd, Sysroot, *};

/// Tools that need to be installed on the host to build libcxx.
pub const HOST_TOOLS: &[&str] = &["cmake", "ninja"];

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
    pub libclang_dir: PathBuf,
    pub llvm_symbolizer: PathBuf,
    pub lld: PathBuf,
}

impl LlvmTools {
    pub fn new(rustc_version: &VersionMeta, host_sysroot: &Sysroot) -> Self {
        let rustc_llvm_version = rustc_version.llvm_version.clone().unwrap_or_else(|| {
            show_error!("Unable to resolve the LLVM version for the current `rustc`.")
        });

        let clang = assert_host_bin(host_sysroot, &format!("clang-{}", rustc_llvm_version.major));
        assert_rustc_llvm_version(&clang, &rustc_llvm_version);

        let sysroot_libdir: PathBuf = host_sysroot.lib();
        let sysroot_target_dir: PathBuf = host_sysroot.target_dir(rustc_version);
        let sysroot_target_bindir = sysroot_target_dir.join("bin");

        let lld = rustc_lld(&sysroot_target_bindir);
        assert_rustc_llvm_version(&lld, &rustc_llvm_version);

        // llvm-symbolizer is versioned independent to LLVM
        let llvm_symbolizer = assert_host_bin(host_sysroot, "llvm-symbolizer");

        LlvmTools { clang, libclang_dir: sysroot_libdir, llvm_symbolizer, lld }
    }

    pub fn populate_env(&self, cmd: &mut Command) {
        cmd.env("LLVM_SYMBOLIZER", &self.clang);
        cmd.env("LLD", &self.lld);
        // bindgen's clang-sys dependency requires these variables
        // to be set so that it uses our clang to parse headers.
        cmd.env("LIBCLANG_PATH", &self.libclang_dir);
        cmd.env("CLANG_PATH", &self.clang);
    }

    pub fn from_env() -> Self {
        let libclang_dir = expect_env_path("LIBCLANG_PATH");
        let clang = expect_env_path("CLANG_PATH");
        let llvm_symbolizer = expect_env_path("LLVM_SYMBOLIZER");
        let lld = expect_env_path("LLD");
        Self { clang, libclang_dir, llvm_symbolizer, lld }
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

pub struct LibCxx;
impl LibCxx {
    /// Where libcxx is installed within the target sysroot.
    fn install_dir(sysroot: &Path) -> PathBuf {
        sysroot.join("libcxx")
    }

    /// Written once the installation is complete.
    fn stamp(install_dir: &Path) -> PathBuf {
        install_dir.join(".installed")
    }

    /// Returns the libcxx installation, if there is one.
    pub fn locate() -> Option<PathBuf> {
        if let Some(dir) = env::var_os("BSAN_LIBCXX") {
            return (!dir.is_empty()).then(|| dir.into());
        }
        let install_dir = Self::install_dir(Path::new(&env::var_os("BSAN_SYSROOT")?));
        Self::stamp(&install_dir).exists().then_some(install_dir)
    }

    /// Builds libcxx for `cargo bsan setup --build-libcxx`, replacing any existing installation.
    pub fn build(deps: &Dependencies, llvm_tools: &LlvmTools, env: &EnvConfig) {
        for tool in HOST_TOOLS {
            if which::which(tool).is_err() {
                show_error!("Unable to build libc++: `{tool}` is not installed.");
            }
        }
        let clang = &llvm_tools.clang;
        let clangxx = clang.with_file_name("clang++");
        if !clangxx.exists() {
            show_error!("Unable to build libc++: `{}` does not exist.", clangxx.display());
        }
        // `./xb setup` installs the LLVM sources that we need into the toolchain's sysroot.
        let runtimes = clang.ancestors().nth(2).unwrap().join("runtimes");

        let install_dir = Self::install_dir(&Sysroot::target(env));
        let stamp = Self::stamp(&install_dir);
        let _ = fs::remove_dir_all(&install_dir);
        fs::create_dir_all(&install_dir).unwrap_or_else(|err| {
            show_error!("failed to create `{}`: {err}", install_dir.display())
        });

        let run = |cmd: &mut Command| {
            debug_cmd("[cargo-bsan libcxx]", env.verbose, cmd);
            // Keep stdout clean for the `--print-*` flags.
            let status = cmd.stdin(Stdio::null()).stdout(io::stderr()).status();
            if !status.is_ok_and(|status| status.success()) {
                show_error!("Failed to build libc++.\n - using: {cmd:?}");
            }
        };

        if !env.quiet {
            eprintln!("Building an instrumented libc++ in `{}`...", install_dir.display());
        }

        // Instrument libcxx with the same flags that we pass to clang. We only build static
        // libraries, which resolve their references to the runtime from the instrumented
        // program, so the runtime is only linked into executables (e.g. CMake's compiler checks).
        let cflags = bsan_cflags(deps).join(" ");
        let ldflags = bsan_ldflags(env, deps, llvm_tools).join(" ");

        let build_dir = tempfile::tempdir()
            .unwrap_or_else(|err| show_error!("failed to create build directory: {err}"));
        let cmake_build = || {
            let mut cmd = Command::new("cmake");
            // Make sure that we do not pick up our compiler wrapper, or flags meant for it.
            for var in ["CC", "CXX", "CFLAGS", "CXXFLAGS", "LDFLAGS"] {
                cmd.env_remove(var);
            }
            cmd
        };
        let defines = [
            ("LLVM_ENABLE_RUNTIMES", "libcxx;libcxxabi;libunwind"),
            ("CMAKE_BUILD_TYPE", "Release"),
            ("CMAKE_INSTALL_PREFIX", &install_dir.display().to_string()),
            ("CMAKE_C_COMPILER", &clang.display().to_string()),
            ("CMAKE_CXX_COMPILER", &clangxx.display().to_string()),
            ("CMAKE_C_FLAGS", &cflags),
            ("CMAKE_CXX_FLAGS", &cflags),
            ("CMAKE_EXE_LINKER_FLAGS", &ldflags),
            ("LIBCXX_ENABLE_SHARED", "OFF"),
            ("LIBCXXABI_ENABLE_SHARED", "OFF"),
            ("LIBUNWIND_ENABLE_SHARED", "OFF"),
            // Merge libc++abi into `libc++.a`, so that `-lc++` is all that we need to link.
            ("LIBCXX_ENABLE_STATIC_ABI_LIBRARY", "ON"),
        ];
        run(cmake_build()
            .args(["-G", "Ninja", "-S"])
            .arg(&runtimes)
            .arg("-B")
            .arg(build_dir.path())
            .args(defines.iter().map(|(key, value)| format!("-D{key}={value}"))));
        let targets = ["install-cxx", "install-cxxabi", "install-unwind"];
        run(cmake_build().arg("--build").arg(build_dir.path()).arg("--target").args(targets));

        fs::write(&stamp, "")
            .unwrap_or_else(|err| show_error!("failed to write `{}`: {err}", stamp.display()));
        if !env.quiet {
            eprintln!("libc++ is now available in `{}`.", install_dir.display());
        }
    }
}
