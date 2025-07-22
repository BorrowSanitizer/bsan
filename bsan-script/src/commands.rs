use std::fs;
use std::ops::Deref;
use std::path::PathBuf;

use anyhow::Result;
use clap::ValueEnum;
use path_macro::path;
use xshell::cmd;

use crate::env::{BsanEnv, Mode};
use crate::utils::install_git_hooks;
use crate::Command;

impl Command {
    pub fn exec(self, quiet: bool, skip: bool, toolchain_dir: Option<String>) -> Result<()> {
        let mut env = BsanEnv::new(quiet, skip, toolchain_dir)?;
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
            Command::Miri { components, args } => components.iter().try_for_each(|c| {
                c.miri(env, &args)?;
                Ok(())
            }),
        }
    }

    fn setup(env: &mut BsanEnv) -> Result<()> {
        // We assume that users who are skipping prompts will not want to
        // install git hooks. This also lets us avoid setting hooks by default
        // when building our Docker image.
        if !env.skip {
            install_git_hooks(&env.root_dir)?;
        }

        Ok(())
    }

    fn fmt(env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.fmt(args)
    }

    fn ui(env: &mut BsanEnv, _bless: bool) -> Result<()> {
        env.in_mode(Mode::Release, |env| {
            let args = &[];
            let driver = env.build_artifact(BsanDriver, args)?;
            let cargo_bsan = env.build_artifact(CargoBsan, args)?;
            let runtime = env.build_artifact(BsanRt, args)?;
            let plugin = env.build_artifact(BsanPass, args)?;

            env.sh.set_var("BSAN_PLUGIN", plugin);
            env.sh.set_var("BSAN_DRIVER", driver);
            env.sh.set_var("BSAN_RT_DIR", runtime.parent().unwrap());
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
        components.iter().try_for_each(|c| c.miri(env, args))?;
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
        let pass = env.build_artifact(BsanPass, args)?;
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
    BsanRt,
    BsanPass,
    BsanShared,
}

#[macro_export]
macro_rules! all_components {
    () => {
        [
            Component::BsanDriver,
            Component::CargoBsan,
            Component::BsanRt,
            Component::BsanPass,
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
            Component::BsanRt => &BsanRt,
            Component::BsanPass => &BsanPass,
            Component::BsanShared => &BsanShared,
        }
    }
}

pub trait Buildable {
    fn artifact(&self) -> &'static str;

    fn doc(&self, env: &mut BsanEnv, args: &[String]) -> Result<()>;

    fn build(&self, env: &mut BsanEnv, args: &[String]) -> Result<Option<PathBuf>>;

    fn test(&self, env: &mut BsanEnv, args: &[String]) -> Result<()>;

    fn clippy(&self, env: &mut BsanEnv, args: &[String]) -> Result<()>;

    fn install(&self, env: &mut BsanEnv, args: &[String]) -> Result<()>;

    fn check(&self, env: &mut BsanEnv, args: &[String]) -> Result<()>;

    fn miri(&self, env: &mut BsanEnv, args: &[String]) -> Result<()>;
}

macro_rules! impl_component {
    ($struct_name:ident, $artifact_name:expr, $should_install:expr, $should_miri:expr) => {
        struct $struct_name;

        impl Buildable for $struct_name {
            #[inline]
            fn artifact(&self) -> &'static str {
                $artifact_name
            }

            fn doc(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
                env.doc(self.artifact(), args)
            }

            fn build(&self, env: &mut BsanEnv, args: &[String]) -> Result<Option<PathBuf>> {
                let artifact = self.artifact();
                env.build(artifact, args)?;
                if $should_install {
                    Ok(Some(path!(env.artifact_dir() / artifact)))
                } else {
                    Ok(None)
                }
            }

            fn clippy(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
                env.clippy(self.artifact(), args)
            }

            fn install(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
                if $should_install {
                    env.install(self.artifact(), args)
                } else {
                    Ok(()) // Or `Err(anyhow!("Installation not supported"))` if you want it to fail
                }
            }

            fn check(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
                env.check(self.artifact(), args)
            }

            fn test(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
                env.test(self.artifact(), args)
            }

            fn miri(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
                if $should_miri {
                    env.miri(self.artifact(), args)
                } else {
                    Ok(())
                }
            }
        }
    };
}

impl_component!(BsanDriver, "bsan-driver", true, false);
impl_component!(CargoBsan, "cargo-bsan", true, false);
impl_component!(BsanShared, "bsan-shared", false, true);

static RT_FLAGS: &[&str] =
    &["-Cpanic=abort", "-Zpanic_abort_tests", "-Cembed-bitcode=yes", "-Clto"];

struct BsanRt;

impl Buildable for BsanRt {
    fn artifact(&self) -> &'static str {
        "libbsan_rt.a"
    }

    fn doc(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.doc("bsan-rt", args)
    }

    fn build(&self, env: &mut BsanEnv, args: &[String]) -> Result<Option<PathBuf>> {
        env.with_flags("RUSTFLAGS", RT_FLAGS, |env| env.build("bsan-rt", args))?;
        let artifact = env.assert_artifact(self.artifact());
        let llvm_objcopy = env.target_binary("llvm-objcopy");
        cmd!(env.sh, "{llvm_objcopy} -w -G __bsan_* -G __BSAN_*").arg(&artifact).quiet().run()?;
        Ok(Some(path!(env.artifact_dir() / artifact)))
    }

    fn test(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.with_flags("RUSTFLAGS", RT_FLAGS, |env| env.test("bsan-rt", args))
    }

    fn clippy(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.with_flags("RUSTFLAGS", RT_FLAGS, |env| env.clippy("bsan-rt", args))
    }

    fn install(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.in_mode(Mode::Release, |env| {
            self.build(env, args)?;
            let runtime = env.assert_artifact(self.artifact());
            env.copy_to_sysroot_libdir(&runtime)
        })
    }

    fn check(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.with_flags("RUSTFLAGS", RT_FLAGS, |env| env.check("bsan-rt", args))
    }

    fn miri(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.with_flags("MIRIFLAGS", &["-Zmiri-permissive-provenance"], |env| {
            env.miri("bsan-rt", args)
        })
    }
}

struct BsanPass;

impl Buildable for BsanPass {
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

    fn build(&self, env: &mut BsanEnv, _args: &[String]) -> Result<Option<PathBuf>> {
        let source_dir = path!(env.root_dir / "bsan-pass");
        let mut cfg = env.cmake(source_dir);

        let cxxflags = env.llvm_config().arg("--cxxflags").output()?.stdout;
        let cxxflags: String = String::from_utf8(cxxflags)?;

        cfg.define("CMAKE_CXX_FLAGS", cxxflags.trim());
        cfg.build_target("bsan_plugin");
        cfg.pic(true);
        let path = cfg.build();
        Ok(Some(path!(path / "build" / self.artifact())))
    }

    fn test(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.with_flags("RUSTFLAGS", RT_FLAGS, |env| env.test("bsan-rt", args))
    }

    fn clippy(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.with_flags("RUSTFLAGS", RT_FLAGS, |env| env.clippy("bsan-rt", args))
    }

    fn install(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.in_mode(Mode::Release, |env| {
            let pass = self.build(env, args)?.expect("LLVM pass was not built.");
            env.copy_to_sysroot_libdir(&pass)
        })
    }

    fn check(&self, _env: &mut BsanEnv, _args: &[String]) -> Result<()> {
        Ok(())
    }

    fn miri(&self, _env: &mut BsanEnv, _args: &[String]) -> Result<()> {
        Ok(())
    }
}
