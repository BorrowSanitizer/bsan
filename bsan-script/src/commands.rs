use std::fs;
use std::ops::Deref;
use std::path::PathBuf;

use anyhow::Result;
use clap::ValueEnum;
use path_macro::path;
use xshell::cmd;

use crate::Command;
use crate::env::{BsanEnv, Mode};
use crate::utils::{self, install_git_hooks, show_error};
use crate::Command;

impl Command {
    pub fn exec(self) -> Result<()> {
        let mut env = BsanEnv::new()?;
        let env = &mut env;
        match self {
            Command::Setup => Self::setup(env),
            Command::Clean => Self::clean(env),
            Command::Ci { args } => Self::ci(env, &args),
            Command::Doc { components, args } => components.iter().try_for_each(|c| {
                c.doc(env, &args)?;
                Ok(())
            }),
            Command::Bin { binary_name, args } => Self::bin(env, binary_name, &args),
            Command::Opt { args } => Self::opt(env, &args),
            Command::Fmt { args } => Self::fmt(env, &args),
            Command::Build { components, args } => components.iter().try_for_each(|c| {
                c.build(env, &args)?;
                Ok(())
            }),
            Command::Check { components, args } => components.iter().try_for_each(|c| {
                c.check(env, &args)?;
                Ok(())
            }),
            Command::Clippy { components, args } => {
                components.iter().try_for_each(|c| c.clippy(env, &args))
            }
            Command::Test { components, args } => {
                components.iter().try_for_each(|c| c.test(env, &args))
            }
            Command::Install { components, args } => {
                components.iter().try_for_each(|c| c.install(env, &args))
            }
            Command::UI { bless } => Self::ui(env, bless),
        }
    }

    fn setup(env: &mut BsanEnv) -> Result<()> {
        install_git_hooks(&env.root_dir)?;

        Ok(())
    }

    fn fmt(env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.fmt(args)
    }

    fn ui(env: &mut BsanEnv, _bless: bool) -> Result<()> {
        env.in_mode(Mode::Release, |env| {
            let driver = BsanDriver.build(env, &[])?;
            let cargo_bsan = CargoBsan.build(env, &[])?;
            let bsan_rt = BsanRuntime.build(env, &[])?;
            let plugin = BsanLLVMPlugin.build(env, &[])?;

            env.sh.set_var("BSAN_PLUGIN", plugin);
            env.sh.set_var("BSAN_DRIVER", driver);
            env.sh.set_var("BSAN_RT_SYSROOT", bsan_rt.parent().unwrap());
            env.sh.set_var("BSAN_SYSROOT", path!(&env.build_dir / "sysroot"));

            cmd!(env.sh, "{cargo_bsan} bsan setup").run()?;
            cmd!(env.sh, "cargo test -p bsan --test ui").run()?;
            Ok(())
        })
    }

    fn ci(env: &mut BsanEnv, args: &[String]) -> Result<()> {
        let components = crate::all_components!();
        // We want to ensure that all formatting steps are completed for every component
        // before we try running more expensive checks, like unit and integration tests.
        Self::fmt(env, &["--check".to_string()])?;
        components.iter().try_for_each(|c| c.clippy(env, args))?;
        components.iter().try_for_each(|c| c.test(env, args))?;
        Self::ui(env, false)
    }

    fn clean(env: &mut BsanEnv) -> Result<()> {
        fs::remove_dir_all(&env.build_dir)?;
        Ok(())
    }

    fn bin(env: &mut BsanEnv, binary_name: String, flags: &[String]) -> Result<()> {
        let binary_name = env.target_binary(&binary_name);
        cmd!(env.sh, "{binary_name} {flags...}").run()?;
        Ok(())
    }

    fn opt(env: &mut BsanEnv, args: &[String]) -> Result<()> {
        let pass = BsanLLVMPlugin.build(env, &[])?;
        let pass = pass.to_str().unwrap();
        let opt = env.target_binary("opt");
        let _ =
            cmd!(env.sh, "{opt} --load-pass-plugin={pass} -passes=bsan {args...}").quiet().run();
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum Component {
    BsanDriver,
    CargoBsan,
    BsanRuntime,
    BsanLLVMPass,
    BsanShared,
}

#[macro_export]
macro_rules! all_components {
    () => {
        [
            Component::BsanDriver,
            Component::CargoBsan,
            Component::BsanRuntime,
            Component::BsanLLVMPass,
            Component::BsanShared,
        ]
    };
}

impl Deref for Component {
    type Target = dyn Buildable;

    fn deref(&self) -> &Self::Target {
        match self {
            Component::BsanDriver => &BsanDriver,
            Component::CargoBsan => &CargoBsan,
            Component::BsanRuntime => &BsanRuntime,
            Component::BsanLLVMPass => &BsanLLVMPlugin,
            Component::BsanShared => &BsanShared,
        }
    }
}

pub trait Buildable {
    fn artifact(&self) -> &'static str;

    fn doc(&self, env: &mut BsanEnv, args: &[String]) -> Result<()>;

    fn build(&self, env: &mut BsanEnv, args: &[String]) -> Result<PathBuf>;

    fn test(&self, env: &mut BsanEnv, args: &[String]) -> Result<()>;

    fn clippy(&self, env: &mut BsanEnv, args: &[String]) -> Result<()>;

    fn install(&self, env: &mut BsanEnv, args: &[String]) -> Result<()>;

    fn check(&self, env: &mut BsanEnv, args: &[String]) -> Result<()>;
}

macro_rules! impl_component {
    ($struct_name:ident, $artifact_name:expr) => {
        struct $struct_name;

        impl Buildable for $struct_name {
            #[inline(always)]
            fn artifact(&self) -> &'static str {
                $artifact_name
            }

            fn doc(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
                env.doc(self.artifact(), args)
            }

            fn build(&self, env: &mut BsanEnv, args: &[String]) -> Result<PathBuf> {
                let artifact = self.artifact();
                env.build(artifact, args, true)?;
                Ok(env.assert_artifact(artifact))
            }

            fn clippy(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
                env.clippy(self.artifact(), args)
            }

            fn install(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
                env.install(self.artifact(), args)
            }

            fn check(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
                env.check(self.artifact(), args)
            }

            fn test(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
                env.test(self.artifact(), args)
            }
        }
    };
}

impl_component!(BsanDriver, "bsan-driver");
impl_component!(CargoBsan, "cargo-bsan");
impl_component!(BsanShared, "bsan-shared");

static RT_FLAGS: &[&str] =
    &["-Cpanic=abort", "-Zpanic_abort_tests", "-Cembed-bitcode=yes", "-Clto"];

struct BsanRuntime;

impl Buildable for BsanRuntime {
    fn artifact(&self) -> &'static str {
        "libbsan_rt.a"
    }

    fn doc(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.doc("bsan-rt", args)
    }

    fn build(&self, env: &mut BsanEnv, args: &[String]) -> Result<PathBuf> {
        env.with_rust_flags(RT_FLAGS, |env| env.build("bsan-rt", args, true))?;
        let artifact = env.assert_artifact(self.artifact());
        let llvm_objcopy = env.target_binary("llvm-objcopy");
        cmd!(env.sh, "{llvm_objcopy} -w -G __bsan_*").arg(&artifact).quiet().run()?;
        Ok(artifact)
    }

    fn test(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.with_rust_flags(RT_FLAGS, |env| env.test("bsan-rt", args))
    }

    fn clippy(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.with_rust_flags(RT_FLAGS, |env| env.clippy("bsan-rt", args))
    }

    fn install(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.in_mode(Mode::Release, |env| {
            let runtime = self.build(env, args)?;
            env.copy_to_sysroot_libdir(&runtime)
        })
    }

    fn check(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.with_rust_flags(RT_FLAGS, |env| env.check("bsan-rt", args))
    }
}

struct BsanLLVMPlugin;

impl Buildable for BsanLLVMPlugin {
    fn artifact(&self) -> &'static str {
        #[cfg(target_os = "macos")]
        let artifact = "libbsan_plugin.dylib";
        #[cfg(target_os = "linux")]
        let artifact = "libbsan_plugin.so";
        artifact
    }

    fn doc(&self, _env: &mut BsanEnv, _args: &[String]) -> Result<()> {
        Ok(())
    }

    fn build(&self, env: &mut BsanEnv, _args: &[String]) -> Result<PathBuf> {
        let cxxflags = env.llvm_config().arg("--cxxflags").output()?.stdout;

        let mut cfg = env.cc();
        cfg.warnings(false);

        for flag in String::from_utf8(cxxflags)?.split_whitespace() {
            cfg.flag(flag);
        }

        let out_dir = env.artifact_dir();
        fs::create_dir_all(&out_dir)?;

        let src_dir = path!(&env.root_dir / "bsan-pass");

        let objects = cfg
            .file(path!(src_dir / "BorrowSanitizer.cpp"))
            .include(src_dir)
            .cpp(true)
            .cpp_link_stdlib(None)
            .out_dir(&out_dir)
            .pic(true)
            .compile_intermediates();

        let rust_ver = env.meta.semver.to_string();
        let llvm_ver = env.meta.llvm_version.as_ref().unwrap().major;
        let suffix = utils::dylib_suffix(&env.meta);
        let lib_llvm = format!("libLLVM-{llvm_ver}-rust-{rust_ver}.{suffix}");

        let lib_dir: PathBuf = path!(&env.rust_dev / "lib");
        let lib_llvm: PathBuf = path!(lib_dir / lib_llvm);

        if !lib_llvm.exists() {
            show_error!("Unable to locate LLVM within rust_dev artifacts ({lib_llvm:?}).")
        }

        let library_path = path!(out_dir / self.artifact());

        let cmd = cmd!(
            env.sh,
            "cc --shared {objects...} {lib_llvm} -o {library_path} -Wl,-rpath={lib_dir}"
        )
        .quiet();
        cmd.run()?;
        Ok(library_path)
    }

    fn test(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.with_rust_flags(RT_FLAGS, |env| env.test("bsan-rt", args))
    }

    fn clippy(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.with_rust_flags(RT_FLAGS, |env| env.clippy("bsan-rt", args))
    }

    fn install(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.in_mode(Mode::Release, |env| {
            let pass = self.build(env, args)?;
            env.copy_to_sysroot_libdir(&pass)
        })
    }

    fn check(&self, _env: &mut BsanEnv, _args: &[String]) -> Result<()> {
        Ok(())
    }
}
