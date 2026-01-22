use std::fs;
use std::ops::Deref;
use std::path::PathBuf;

use anyhow::Result;
use clap::ValueEnum;
use cmake::Config;
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
            Command::Fmt { check } => Self::fmt(env, check),
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
            Command::Inst { file, debug, args } => Self::inst(env, file, debug, &args),
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

    fn fmt(env: &mut BsanEnv, check: bool) -> Result<()> {
        env.fmt(check)?;
        BsanPass::fmt(env, check)?;
        CompilerRt::fmt(env, check)
    }

    fn ui(env: &mut BsanEnv, bless: bool) -> Result<()> {
        env.in_mode(Mode::Release, |env| {
            let args = &[];
            let driver = env.build_artifact(BsanDriver, args)?;
            let cargo_bsan = env.build_artifact(CargoBsan, args)?;
            let runtime = env.build_artifact(BsanRt, args)?;
            let plugin = env.build_artifact(BsanPass, args)?;

            let symbolizer = env.sysroot_binary("llvm-symbolizer");

            env.sh.set_var("BSAN_PLUGIN", plugin);
            env.sh.set_var("BSAN_DRIVER", driver);
            env.sh.set_var("BSAN_RT", runtime);
            env.sh.set_var("BSAN_SYSROOT", path!(&env.build_dir / "sysroot"));
            env.sh.set_var("BSAN_SYMBOLIZER", symbolizer);

            cmd!(env.sh, "{cargo_bsan} bsan setup").run()?;
            let add_bless = if bless { "--bless" } else { "" };
            cmd!(env.sh, "cargo test -p bsan --test ui -- {add_bless}").run()?;
            cmd!(env.sh, "python3 tests/test-cargo-bsan/run_test.py").run()?;
            Ok(())
        })
    }

    fn ci(env: &mut BsanEnv, args: &[String]) -> Result<()> {
        let components = crate::all_components!();
        // We want to ensure that all formatting steps are completed for every component
        // before we try running more expensive checks, like unit and integration tests.
        Self::fmt(env, true)?;
        components.iter().try_for_each(|c| c.test(env, args))?;
        components.iter().try_for_each(|c| c.clippy(env, args))?;
        //components.iter().try_for_each(|c| c.miri(env, args))?;
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
        cmd!(env.sh, "{opt} --load-pass-plugin={pass} -passes=bsan {args...}").quiet().run()?;
        Ok(())
    }

    fn inst(env: &mut BsanEnv, file: String, debug: bool, args: &[String]) -> Result<()> {
        let plugin = env.build_artifact(BsanPass, &[])?;

        let runtime = if debug {
            env.build_artifact(BsanRt, &["--features".to_string(), "debug".to_string()])?
        } else {
            env.build_artifact(BsanRt, &[])?
        };

        let driver = env.build_artifact(BsanDriver, &[])?;
        let cargo_bsan = env.build_artifact(CargoBsan, &[])?;

        let sysroot_dir = path!(&env.build_dir / "sysroot");

        env.sh.set_var("BSAN_PLUGIN", plugin);
        env.sh.set_var("BSAN_DRIVER", &driver);
        env.sh.set_var("BSAN_RT", runtime);
        env.sh.set_var("BSAN_SYSROOT", &sysroot_dir);

        cmd!(env.sh, "{cargo_bsan} bsan setup").run()?;

        cmd!(env.sh, "{driver} {file}")
            .env("BSAN_BE_RUSTC", "target")
            .args(args)
            .arg(format!("--sysroot={}", sysroot_dir.display()))
            .quiet()
            .run()?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum Component {
    BsanDriver,
    CargoBsan,
    BsanRt,
    BsanRtCore,
    CompilerRt,
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
            Component::BsanRtCore,
            Component::CompilerRt,
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
            Component::BsanRtCore => &BsanRtCore,
            Component::CompilerRt => &CompilerRt,
            Component::BsanPass => &BsanPass,
            Component::BsanShared => &BsanShared,
        }
    }
}

pub trait Buildable {
    fn artifact(&self, env: &BsanEnv) -> String;

    fn build(&self, env: &mut BsanEnv, args: &[String]) -> Result<Option<PathBuf>>;

    fn install(&self, _env: &mut BsanEnv, _args: &[String]) -> Result<()> {
        Ok(())
    }

    fn doc(&self, _env: &mut BsanEnv, _args: &[String]) -> Result<()> {
        Ok(())
    }

    fn test(&self, _env: &mut BsanEnv, _args: &[String]) -> Result<()> {
        Ok(())
    }

    fn clippy(&self, _env: &mut BsanEnv, _args: &[String]) -> Result<()> {
        Ok(())
    }

    fn check(&self, _env: &mut BsanEnv, _args: &[String]) -> Result<()> {
        Ok(())
    }

    fn miri(&self, _env: &mut BsanEnv, _args: &[String]) -> Result<()> {
        Ok(())
    }
}

macro_rules! impl_component {
    ($struct_name:ident, $artifact_name:expr, $should_install:expr, $should_miri:expr) => {
        struct $struct_name;

        impl Buildable for $struct_name {
            #[inline]
            fn artifact(&self, _env: &BsanEnv) -> String {
                $artifact_name.into()
            }

            fn doc(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
                env.doc(self.artifact(env), args)
            }

            fn build(&self, env: &mut BsanEnv, args: &[String]) -> Result<Option<PathBuf>> {
                let artifact = self.artifact(env);
                env.build(&artifact, args)?;
                if $should_install {
                    Ok(Some(path!(env.artifact_dir() / artifact)))
                } else {
                    Ok(None)
                }
            }

            fn clippy(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
                env.clippy(self.artifact(env), args)
            }

            fn install(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
                if $should_install {
                    env.install(self.artifact(env), args)
                } else {
                    Ok(()) // Or `Err(anyhow!("Installation not supported"))` if you want it to fail
                }
            }

            fn check(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
                env.check(self.artifact(env), args)
            }

            fn test(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
                env.test(self.artifact(env), args)
            }

            fn miri(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
                if $should_miri {
                    env.miri(self.artifact(env), args)
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

static RT_FLAGS: &[&str] = &[
    "-Cpanic=abort",
    "-Zpanic_abort_tests",
    "-Cembed-bitcode=yes",
    "-Clto",
    "-Cforce-frame-pointers=yes",
    "-Crelocation-model=pic",
];

struct BsanRt;

impl Buildable for BsanRt {
    fn artifact(&self, _env: &BsanEnv) -> String {
        "libbsan_rt.a".into()
    }

    fn doc(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.doc("bsan-rt", args)
    }

    fn build(&self, env: &mut BsanEnv, args: &[String]) -> Result<Option<PathBuf>> {
        let llvm_ar = env.target_binary("llvm-ar");
        let clang = "clang";

        let llvm_wrapper = env.build_artifact(CompilerRt, &[])?;
        let rust_runtime = env.build_artifact(BsanRtCore, args)?;

        let dest_archive = path!(env.artifact_dir() / self.artifact(env));
        let tmp_dir = env.sh.create_temp_dir()?;

        env.cd(tmp_dir.path(), |env| {
            let merged_obj = path!(tmp_dir.path() / "bsan_rt_merged.o");
            // Use system-wide clang to invoke the linker driver
            // to create a relocatable object from existing archives.
            cmd!(env.sh, "{clang}")
                .arg(format!("-Wl,--whole-archive"))
                .arg(&rust_runtime)
                .arg(&llvm_wrapper)
                .arg("-r")
                .arg("-o")
                .arg(&merged_obj)
                .run()?;

            env.sh.remove_path(&dest_archive)?;

            // Create a new archive with the merged object file.
            cmd!(env.sh, "{llvm_ar} rcs {dest_archive} {merged_obj}").quiet().run()?;
            Ok(())
        })?;

        Ok(Some(dest_archive))
    }

    fn install(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.in_mode(Mode::Release, |env| {
            self.build(env, args)?;
            let runtime = env.assert_artifact(&self.artifact(env));
            env.copy_to_sysroot_libdir(&runtime)
        })
    }
}

struct CompilerRt;
impl CompilerRt {
    fn cmake(env: &mut BsanEnv) -> Result<Config> {
        let output_dir = path!(env.artifact_dir() / "compiler-rt");
        let src_dir = path!(env.sysroot / "compiler-rt");
        let crt_include = path!(src_dir / "include");
        let sanitizer_common = path!(src_dir / "lib");

        let mut cfg = env.llvm_cmake(&src_dir, &output_dir, &[crt_include, sanitizer_common])?;
        cfg.define("LLVM_MAIN_SRC_DIR", &env.sysroot);
        cfg.define("COMPILER_RT_SANITIZERS_TO_BUILD", "bsan");
        cfg.define("COMPILER_RT_HAS_BSAN", "TRUE");
        cfg.define("COMPILER_RT_HAS_LLVMTESTINGSUPPORT", "FALSE");
        cfg.define("LLVM_COMMON_CMAKE_UTILS", &env.toolchain_config.llvm_cmake.common);
        cfg.define("LLVM_CMAKE_DIR", &env.toolchain_config.llvm_cmake.llvm);
        cfg.build_target(&CompilerRt.artifact(env));
        Ok(cfg)
    }

    fn fmt(env: &mut BsanEnv, check: bool) -> Result<()> {
        let mut cfg = Self::cmake(env)?;
        if check {
            cfg.build_target("clang-format-check");
        } else {
            cfg.build_target("clang-format");
        }
        cfg.build();
        Ok(())
    }
}

impl Buildable for CompilerRt {
    fn artifact(&self, env: &BsanEnv) -> String {
        let host = &env.toolchain_config.meta.host;
        let arch = host
            .split("-")
            .next()
            .expect(&format!("Invalid target triple: `{}`", env.toolchain_config.meta.host));
        format!("libclang_rt.bsan-{}.a", arch)
    }

    fn build(&self, env: &mut BsanEnv, args: &[String]) -> Result<Option<PathBuf>> {
        let mut cfg = Self::cmake(env)?;
        args.iter().for_each(|arg| {
            cfg.build_arg(arg);
        });
        let target_dir = path!(cfg.build() / "build" / "lib" / "linux");
        let target = path!(target_dir / self.artifact(env));
        Ok(Some(target))
    }
}

struct BsanRtCore;

impl Buildable for BsanRtCore {
    fn artifact(&self, _env: &BsanEnv) -> String {
        "libbsan_rt_core.a".into()
    }

    fn doc(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.doc("bsan-rt", args)
    }

    fn build(&self, env: &mut BsanEnv, args: &[String]) -> Result<Option<PathBuf>> {
        let rust_runtime = env.with_flags("RUSTFLAGS", RT_FLAGS, |env| {
            env.build("bsan-rt", args)?;
            Ok(env.assert_artifact(&self.artifact(env)))
        })?;

        Ok(Some(rust_runtime))
    }

    fn test(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        /*let tsan_extended_rustflags = RT_FLAGS
        .iter()
        .cloned()
        .chain(["-Zsanitizer=thread -Cunsafe-allow-abi-mismatch=sanitizer"].iter().cloned())
        .collect::<Vec<&str>>();*/
        let tsan_extended_rustflags = RT_FLAGS;
        env.with_flags("RUSTFLAGS", &tsan_extended_rustflags, |env| env.test("bsan-rt", args))
    }

    fn clippy(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.with_flags("RUSTFLAGS", RT_FLAGS, |env| env.clippy("bsan-rt", args))
    }

    fn check(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.with_flags("RUSTFLAGS", RT_FLAGS, |env| env.check("bsan-rt", args))
    }

    fn miri(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.with_flags(
            "MIRIFLAGS",
            &["-Zmiri-permissive-provenance", "-Zmiri-disable-alignment-check"],
            |env| env.miri("bsan-rt", args),
        )
    }
}

struct BsanPass;

impl BsanPass {
    fn cmake(env: &mut BsanEnv) -> Result<Config> {
        let source_dir = path!(env.root_dir / "bsan-pass");
        let output_dir = path!(env.artifact_dir() / "bsan-pass");
        let cfg = env.llvm_cmake(&source_dir, &output_dir, &[])?;
        Ok(cfg)
    }

    fn fmt(env: &mut BsanEnv, check: bool) -> Result<()> {
        let mut cfg = BsanPass::cmake(env)?;
        if check {
            cfg.build_target("clang-format-check");
        } else {
            cfg.build_target("clang-format");
        }
        cfg.build();
        Ok(())
    }
}

impl Buildable for BsanPass {
    fn artifact(&self, _env: &BsanEnv) -> String {
        #[cfg(target_os = "macos")]
        let artifact = "libbsan_plugin.dylib";
        #[cfg(target_os = "linux")]
        let artifact = "libbsan_plugin.so";
        artifact.into()
    }

    fn doc(&self, _env: &mut BsanEnv, _args: &[String]) -> Result<()> {
        Ok(())
    }

    fn build(&self, env: &mut BsanEnv, _args: &[String]) -> Result<Option<PathBuf>> {
        let mut cfg = BsanPass::cmake(env)?;
        cfg.build_target("bsan_plugin");
        cfg.pic(true);
        let path = cfg.build();
        Ok(Some(path!(path / "build" / self.artifact(env))))
    }

    fn test(&self, _env: &mut BsanEnv, _args: &[String]) -> Result<()> {
        Ok(())
    }

    fn clippy(&self, _env: &mut BsanEnv, _args: &[String]) -> Result<()> {
        Ok(())
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
