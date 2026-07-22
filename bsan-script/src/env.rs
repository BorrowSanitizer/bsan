use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use path_macro::path;
use serde::{Deserialize, Serialize};
use xshell::{cmd, Cmd, Shell};

use crate::commands::Buildable;
use crate::setup::ToolchainConfig;
use crate::utils::{active_libdir, active_sysroot, active_toolchain, show_error};
use crate::{setup, utils, TOOLCHAIN_NAME};

#[allow(dead_code)]
pub struct BsanEnv {
    /// Installation configuration for the toolchain.
    pub toolchain_config: ToolchainConfig,
    /// The target bin directory within the sysroot, which contains LLVM tool binaries.
    pub target_bindir: PathBuf,
    /// The sysroot of the nightly toolchain.
    pub sysroot: PathBuf,
    /// The build directory
    pub build_dir: PathBuf,
    /// The root of the repository checkout we are working in.
    pub root_dir: PathBuf,
    /// The shell we use.
    pub sh: Shell,
    /// Repository-wide configuration
    config: BsanConfig,
    /// Extra flags to pass to cargo.
    cargo_extra_flags: Vec<String>,
    /// Controls whether binaries are built in debug or release mode
    mode: Mode,
    /// Silence output
    pub quiet: bool,
    pub skip: bool,
}

#[derive(Copy, Clone, Eq, PartialEq, Default)]
pub enum Mode {
    #[default]
    Debug,
    Release,
}

impl Mode {
    pub fn release(release: bool) -> Self {
        if release {
            Mode::Release
        } else {
            Mode::Debug
        }
    }

    fn opt_level(&self) -> u32 {
        match self {
            Mode::Debug => 0,
            Mode::Release => 3,
        }
    }

    fn debug_info(&self) -> bool {
        match self {
            Mode::Debug => true,
            Mode::Release => false,
        }
    }

    fn cargo_output_dir(&self) -> &str {
        match self {
            Mode::Debug => "debug",
            Mode::Release => "release",
        }
    }

    fn profile(&self) -> &str {
        match self {
            Mode::Debug => "Debug",
            Mode::Release => "Release",
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BsanConfig {
    pub artifact_url: String,
    pub tag: String,
    pub sha: String,
    pub version: String,
    pub dependencies: Vec<String>,
    pub targets: Vec<String>,
    pub llvm_branch: String,
    pub llvm_url: String,
}

impl BsanConfig {
    fn from_file(path: &Path) -> Result<BsanConfig> {
        let contents: String = std::fs::read_to_string(path)?;
        let contents: BsanConfig = toml::from_str(&contents)?;
        Ok(contents)
    }

    fn save(&self, path: &Path) -> Result<()> {
        let contents: String = toml::to_string(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }
}

impl BsanEnv {
    pub fn new(
        quiet: bool,
        skip: bool,
        toolchain_dir: Option<PathBuf>,
        install_from: Option<PathBuf>,
    ) -> Result<Self> {
        let sh = Shell::new()?;
        let root_dir = utils::root_dir()?;
        let host = utils::version_meta(&sh, &active_toolchain()?)?;

        let deps_dir = toolchain_dir.unwrap_or_else(|| {
            let sysroot = active_sysroot().unwrap();
            if let Some(parent) = sysroot.parent() {
                path!(parent / "bsan")
            } else {
                show_error!(
                    "Please specify an installation directory for our toolchain using `xb --toolchain-dir=[dir]`."
                )
            }
        });

        let config_path = path!(root_dir / "config.toml");
        let mut config = BsanConfig::from_file(&config_path)?;
        let toolchain_config = setup::setup_toolchain(
            &sh,
            &host,
            &mut config,
            &deps_dir,
            &root_dir,
            skip,
            install_from,
        )?;
        config.save(&config_path)?;

        let build_dir = path!(root_dir / "target");
        // Hard-code the target dir, since we rely on all binaries ending up in the same spot.
        sh.set_var("CARGO_TARGET_DIR", &build_dir);

        let sysroot = active_sysroot()?;
        let target_libdir = active_libdir()?;

        let mut target_bindir = path!(target_libdir);
        assert!(target_bindir.pop());
        target_bindir.push("bin");

        // Compute rustflags.
        let rustflags = {
            let mut flags = OsString::new();
            // We set the rpath so that Miri finds the private rustc libraries it needs.
            // (This only makes sense on Unix.)
            if cfg!(unix) {
                flags.push("-C link-args=-Wl,-rpath,");
                flags.push(&path!(target_libdir));
            }
            // Enable rustc-specific lints (ignored without `-Zunstable-options`).
            flags.push(
                " -Zunstable-options -Wrustc::internal -Wrust_2018_idioms -Wunused_lifetimes",
            );
            // Add user-defined flags.
            if let Some(value) = std::env::var_os("RUSTFLAGS") {
                flags.push(" ");
                flags.push(value);
            }
            flags
        };

        sh.set_var("RUSTFLAGS", rustflags);
        // Get extra flags for cargo.
        let cargo_extra_flags = std::env::var("CARGO_EXTRA_FLAGS").unwrap_or_default();
        let mut cargo_extra_flags = utils::flagsplit(&cargo_extra_flags);
        if cargo_extra_flags.iter().any(|a| a == "--release" || a.starts_with("--profile")) {
            // This makes binaries end up in different paths, let's not do that.
            show_error!(
                "Passing `--release` or `--profile` in `CARGO_EXTRA_FLAGS` will totally confuse bsan-script, please don't do that."
            );
        }
        // Also set `-Zroot-dir` for cargo, to print diagnostics relative to the miri dir.
        cargo_extra_flags.push(format!("-Zroot-dir={}", root_dir.display()));

        Ok(Self {
            sh,
            toolchain_config,
            sysroot,
            target_bindir,
            build_dir,
            root_dir,
            config,
            cargo_extra_flags,
            mode: Mode::Debug,
            quiet,
            skip,
        })
    }

    pub fn with_flags<F, T>(&mut self, var: &str, flags: &[&str], f: F) -> Result<T>
    where
        F: Fn(&mut BsanEnv) -> Result<T>,
    {
        let prev_flags = self.sh.var(var).ok().unwrap_or(String::from(""));
        let mut curr_flags = prev_flags.clone();
        for flag in flags {
            curr_flags.push(' ');
            curr_flags.push_str(flag);
        }
        self.sh.set_var(var, curr_flags);
        let result = f(&mut *self)?;
        self.sh.set_var(var, prev_flags);
        Ok(result)
    }

    pub fn in_mode<F, T>(&mut self, m: Mode, f: F) -> Result<T>
    where
        F: Fn(&mut BsanEnv) -> Result<T>,
    {
        let prev = self.mode;
        self.mode = m;
        let r = f(&mut *self)?;
        self.mode = prev;
        Ok(r)
    }

    pub fn cd<F, T>(&mut self, dir: &Path, f: F) -> Result<T>
    where
        F: Fn(&mut BsanEnv) -> Result<T>,
    {
        let current_dir = self.sh.current_dir();
        self.sh.change_dir(dir);
        let result = f(&mut *self);
        self.sh.change_dir(current_dir);
        result
    }

    pub fn copy_to_sysroot_libdir(&self, file: &Path) -> Result<()> {
        let file_name = file.file_name().expect("Expected a path to a file.");
        let sysroot = path!(self.sysroot / "lib" / file_name);
        fs::copy(file, sysroot)?;
        Ok(())
    }

    fn cargo_cmd(&self, crate_dir: impl AsRef<OsStr>, cmd: &str) -> Cmd<'_> {
        let BsanEnv { cargo_extra_flags, .. } = self;
        let manifest_path = path!(self.root_dir / crate_dir.as_ref() / "Cargo.toml");
        self.cargo_cmd_base(cmd)
            .arg(format!("--manifest-path={}", manifest_path.display()))
            .args(cargo_extra_flags)
    }

    fn cargo_cmd_base(&self, cmd: &str) -> Cmd<'_> {
        let cmd = cmd!(self.sh, "cargo +{TOOLCHAIN_NAME} {cmd}").quiet();
        if self.quiet {
            cmd.arg("--quiet")
        } else {
            cmd
        }
    }

    pub fn host_binary(&self, binary_name: &str) -> PathBuf {
        if !self.config.dependencies.contains(&binary_name.to_string()) {
            show_error!(
                "`{binary_name}` is not available as a host dependency. Try adding it to `config.toml`. "
            );
        } else {
            PathBuf::from(binary_name)
        }
    }
    pub fn target_binary(&self, binary_name: &str) -> PathBuf {
        let target_bindir = &self.target_bindir;
        let binary = path!(target_bindir / binary_name);
        if !binary.exists() {
            show_error!(
                "Unable to locate binary `{binary_name}` within the target bindir ({target_bindir:?})."
            );
        } else {
            binary
        }
    }

    pub fn sysroot_binary(&self, binary_name: &str) -> PathBuf {
        let bin_dir = path!(self.sysroot / "bin");
        let binary = path!(bin_dir / binary_name);
        if !binary.exists() {
            show_error!(
                "Unable to locate binary `{binary_name}` within the sysroot bindir ({bin_dir:?})."
            );
        } else {
            binary
        }
    }

    pub fn assert_artifact(&self, artifact_name: &str) -> PathBuf {
        let artifact_subdir = self.mode.cargo_output_dir();
        let build_dir = path!(self.build_dir / artifact_subdir);
        let artifact_path = path!(build_dir / artifact_name);
        if !artifact_path.exists() {
            show_error!(
                "Unable to locate artifact `{artifact_name}` in build directory ({build_dir:?})"
            );
        } else {
            artifact_path
        }
    }

    pub fn fmt(&self, check: bool) -> Result<()> {
        let mut cmd = self.cargo_cmd_base("fmt");
        if check {
            cmd = cmd.arg("--check");
        }
        cmd.run()?;
        Ok(())
    }

    pub fn check(&self, crate_dir: impl AsRef<OsStr>, args: &[String]) -> Result<()> {
        self.cargo_cmd(crate_dir, "check").arg("--all-targets").args(args).run()?;
        Ok(())
    }

    pub fn doc(&self, crate_dir: impl AsRef<OsStr>, args: &[String]) -> Result<()> {
        let mut cmd = self.cargo_cmd(crate_dir, "doc").args(args);
        if !args.iter().any(|s| s.as_str() == "--no-deps") {
            cmd = cmd.arg("--no-deps");
        };
        cmd.run()?;
        Ok(())
    }

    pub fn clippy(&self, crate_dir: impl AsRef<OsStr>, args: &[String]) -> Result<()> {
        let mut cmd = self.cargo_cmd(crate_dir, "clippy").arg("--all-targets").args(args);
        if !args.iter().any(|s| s.as_str() == "--no-deps") {
            cmd = cmd.arg("--no-deps");
        };
        cmd.run()?;
        Ok(())
    }

    pub fn artifact_dir(&self) -> PathBuf {
        let artifact_subdir = self.mode.cargo_output_dir();
        path!(self.build_dir / artifact_subdir)
    }

    pub fn test(&self, crate_dir: impl AsRef<OsStr>, args: &[String]) -> Result<()> {
        self.cargo_cmd(crate_dir, "test").args(args).run()?;
        Ok(())
    }

    pub fn miri(&self, crate_dir: impl AsRef<OsStr>, args: &[String]) -> Result<()> {
        let BsanEnv { cargo_extra_flags, .. } = self;
        let manifest_path = path!(self.root_dir / crate_dir.as_ref() / "Cargo.toml");
        self.cargo_cmd_base("miri")
            .arg("test")
            .arg(format!("--manifest-path={}", manifest_path.display()))
            .args(cargo_extra_flags)
            .args(args)
            .run()?;
        Ok(())
    }

    pub fn build(&self, crate_dir: impl AsRef<OsStr>, args: &[String]) -> Result<()> {
        let mut cmd = self.cargo_cmd(crate_dir, "build").args(args);
        if matches!(self.mode, Mode::Release) {
            cmd = cmd.arg("--release");
        }
        cmd.run()?;
        Ok(())
    }

    pub fn build_artifact(&mut self, b: impl Buildable, args: &[String]) -> Result<PathBuf> {
        b.build(self, args).map(|a| a.unwrap())
    }

    pub fn cc_cmd(&self) -> Cmd<'_> {
        cmd!(self.sh, "cc").quiet()
    }

    pub fn cc(&self) -> cc::Build {
        let mut cfg = cc::Build::new();
        cfg.cargo_debug(false)
            .cargo_metadata(false)
            .cargo_output(false)
            .target(&self.toolchain_config.meta.host)
            .host(&self.toolchain_config.meta.host)
            .debug(self.mode.debug_info())
            .warnings_into_errors(true)
            .opt_level(self.mode.opt_level());
        cfg
    }

    pub fn llvm_cmake(
        &self,
        path: &Path,
        out_dir: &Path,
        include_dirs: &[PathBuf],
    ) -> Result<cmake::Config> {
        let llvm_config = self.sysroot_binary("llvm-config");
        let cxxflags = cmd!(self.sh, "{llvm_config}").arg("--cxxflags").output()?.stdout;
        let cxxflags: String = String::from_utf8(cxxflags)?;

        let includes = include_dirs
            .iter()
            .map(|dir| format!("-I{}", dir.display()))
            .collect::<Vec<_>>()
            .join(" ");

        let cxxflags = format!("{} {}", includes, cxxflags.trim());
        let mut cfg = cmake::Config::new(path);
        cfg.profile(self.mode.profile());
        cfg.target(&self.toolchain_config.meta.host);
        cfg.host(&self.toolchain_config.meta.host);
        cfg.out_dir(out_dir);
        cfg.generator("Ninja");
        cfg.define("CMAKE_CXX_FLAGS", cxxflags.trim());

        Ok(cfg)
    }

    pub fn install(
        &self,
        crate_dir: impl AsRef<OsStr>,
        args: impl IntoIterator<Item = impl AsRef<OsStr>>,
    ) -> Result<()> {
        let BsanEnv { cargo_extra_flags, .. } = self;
        let path = path!(self.root_dir / crate_dir.as_ref());
        cmd!(
            self.sh,
            "cargo +{TOOLCHAIN_NAME} install {cargo_extra_flags...} --path {path} --force {args...}"
        )
        .run()?;
        Ok(())
    }
}
