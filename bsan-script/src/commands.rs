use std::fs;
use std::ops::Deref;
use std::path::PathBuf;

use anyhow::Result;
use clap::ValueEnum;
use cmake::Config;
use path_macro::path;
use xshell::cmd;

use crate::env::{BsanEnv, Mode};
use crate::stats::*;
use crate::utils::install_git_hooks;
use crate::Command;

impl Command {
    pub fn exec(
        self,
        quiet: bool,
        skip: bool,
        toolchain_dir: Option<PathBuf>,
        install_from: Option<PathBuf>,
    ) -> Result<()> {
        let mut env = BsanEnv::new(quiet, skip, toolchain_dir, install_from)?;
        let env = &mut env;
        match self {
            Command::Setup => Self::setup(env),
            Command::Clean => Self::clean(env),
            Command::Ci { args, allow_unsafe_deps } => Self::ci(env, &args, allow_unsafe_deps),
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
            Command::UI { bless, keep_sysroot, allow_unsafe_deps } => {
                Self::ui(env, bless, keep_sysroot, allow_unsafe_deps)
            }
            Command::Miri { components, args } => components.iter().try_for_each(|c| {
                c.miri(env, &args)?;
                Ok(())
            }),
            Command::Inst { file, debug, args } => Self::inst(env, file, debug, &args),
            Command::Fix { keep_sysroot } => Self::fix(env, keep_sysroot),
            Command::Stats => Self::stats(env),
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

    fn ui(
        env: &mut BsanEnv,
        bless: bool,
        keep_sysroot: bool,
        allow_unsafe_deps: bool,
    ) -> Result<()> {
        let config = TestConfig { keep_sysroot, allow_unsafe_deps, bless, fix: false };

        run_tests(env, config)?;

        crate::all_components!().iter().try_for_each(|c| c.install(env, &[]))?;

        let cargo_test_path = path!(env.build_dir / "bsan");
        cmd!(env.sh, "rm -rf {cargo_test_path}").run()?;
        cmd!(env.sh, "python3 tests/test-cargo-bsan/run_test.py").run()?;
        Self::stats(env)?;

        Ok(())
    }

    fn ci(env: &mut BsanEnv, args: &[String], allow_unsafe_deps: bool) -> Result<()> {
        let components = crate::all_components!();
        env.with_flags("RUSTFLAGS", &["-Dwarnings"], |env| {
            // We want to ensure that all formatting steps are completed for every component
            // before we try running more expensive checks, like unit and integration tests.
            Self::fmt(env, true)?;
            components.iter().try_for_each(|c| c.clippy(env, args))?;
            components.iter().try_for_each(|c| c.test(env, args))?;
            //components.iter().try_for_each(|c| c.miri(env, args))?;
            Self::ui(env, false, false, allow_unsafe_deps)
        })
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
        env.in_mode(Mode::Release, |env| {
            let plugin = env.build_artifact(BsanPass, &[])?;

            let rust_runtime = if debug {
                env.build_artifact(BsanRt, &["--features".to_string(), "debug".to_string()])?
            } else {
                env.build_artifact(BsanRt, &[])?
            };

            let llvm_runtime = env.build_artifact(CompilerRt, &[])?;
            let cargo_bsan = env.build_artifact(CargoBsan, &[])?;
            let sysroot_dir = path!(&env.build_dir / "sysroot");

            let env_guards = vec![
                env.sh.push_env("BSAN_PLUGIN", &plugin),
                env.sh.push_env("BSAN_RT_RUST", &rust_runtime),
                env.sh.push_env("BSAN_RT_LLVM", &llvm_runtime),
                env.sh.push_env("BSAN_SYSROOT", &sysroot_dir),
            ];

            cmd!(env.sh, "{cargo_bsan} bsan setup").run()?;
            let flags = cmd!(env.sh, "{cargo_bsan} bsan setup --print-rustflags").output()?;
            let flags = String::from_utf8(flags.stdout)?;
            let flags = flags.split_whitespace().collect::<Vec<_>>();

            cmd!(env.sh, "rustc {file}")
                .args(flags)
                .args(args)
                .arg(format!("--sysroot={}", sysroot_dir.display()))
                .quiet()
                .run()?;

            drop(env_guards);

            Ok(())
        })
    }

    fn stats(env: &mut BsanEnv) -> Result<()> {
        let root = &env.root_dir;
        let pass = count_rs(&path!(root / "tests" / "pass"))?
            + count_rs(&path!(root / "tests" / "pass-dep"))?;
        let miri_pass = count_rs(&path!(root / "tests" / "miri-tests" / "pass"))?;
        let fail = count_rs(&path!(root / "tests" / "fail"))?
            + count_rs(&path!(root / "tests" / "fail-dep"))?;
        let miri_fail = count_rs(&path!(root / "tests" / "miri-tests" / "fail"))?;
        let mirilli_fail = count_rs(&path!(root / "tests" / "fail-dep" / "mirilli"))?;
        let miri_should_pass = count_rs(&path!(root / "tests" / "miri-tests" / "should-pass"))?;
        let miri_should_fail = count_rs(&path!(root / "tests" / "miri-tests" / "should-fail"))?;
        let total_pass = pass + miri_pass + miri_should_pass;
        let total_fail = fail + miri_fail + miri_should_fail;
        let total = total_pass + total_fail;

        println!();
        println!(
            "True negative (pass) tests: {} ({})",
            pass + miri_pass,
            fmt_percent(pass + miri_pass, total_pass)
        );
        println!("  ├─ original tests: {}", pass);
        println!("  └─ miri tests: {}", miri_pass);
        println!(
            "True positive (fail) tests: {} ({})",
            fail + miri_fail,
            fmt_percent(fail + miri_fail, total_fail)
        );
        println!("  ├─ original tests: {}", fail);
        println!("  ├─ mirilli tests: {}", mirilli_fail);
        println!("  └─ miri tests: {}", miri_fail);

        println!(
            "False positive (should pass) tests: {} ({})",
            miri_should_pass,
            fmt_percent(miri_should_pass, total_pass)
        );
        let should_pass_root = path!(root / "tests" / "miri-tests" / "should-pass");
        if should_pass_root.exists() {
            print_tree(&should_pass_root, "  ")?;
        }

        println!(
            "False negative (should fail) tests: {} ({})",
            miri_should_fail,
            fmt_percent(miri_should_fail, total_fail)
        );
        let should_fail_root = path!(root / "tests" / "miri-tests" / "should-fail");
        if should_fail_root.exists() {
            print_tree(&should_fail_root, "  ")?;
        }

        println!(
            "{}/{} ({}) of tests are covered.",
            total - miri_should_fail - miri_should_pass,
            total,
            fmt_percent(total - miri_should_fail - miri_should_pass, total)
        );

        Ok(())
    }

    fn fix(env: &mut BsanEnv, keep_sysroot: bool) -> Result<()> {
        let config = TestConfig { keep_sysroot, bless: false, fix: true, allow_unsafe_deps: false };
        run_tests(env, config)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct TestConfig {
    /// Record test output as canonical
    bless: bool,
    /// If tests that "should" fail or pass have the correct
    /// output, then move them into the corresponding folder.
    fix: bool,
    /// Use the current sysroot, if it exists, to build test
    /// cases.
    keep_sysroot: bool,
    /// Build tests that have dependencies. This includes tests
    /// with known security vulnerabilities or undefined behaviors
    /// that we can recreate with BorrowSanitizer. This should only
    /// be used in CI, or in a secure environment.
    allow_unsafe_deps: bool,
}

fn run_tests(env: &mut BsanEnv, config: TestConfig) -> Result<(), anyhow::Error> {
    let sysroot_dir = path!(&env.build_dir / "sysroot");
    if !config.keep_sysroot {
        cmd!(env.sh, "rm -rf {sysroot_dir}").quiet().run()?;
        // The cached build of the test suite's dependencies goes stale for the
        // same reasons as the sysroot: Cargo does not know to rebuild it when
        // the instrumentation pass changes.
        let dep_cache = path!(&env.build_dir / "tmp" / "bsan_ui");
        cmd!(env.sh, "rm -rf {dep_cache}").quiet().run()?;
    }
    env.sh.set_var("BSAN_SYSROOT", &sysroot_dir);
    env.in_mode(Mode::Release, |env| {
        let args = &[];
        let mut env_guards = vec![];
        let cargo_bsan = env.build_artifact(CargoBsan, args)?;
        let rust_runtime = env.build_artifact(BsanRt, args)?;
        let llvm_runtime = env.build_artifact(CompilerRt, args)?;

        let pass = env.build_artifact(BsanPass, args)?;
        let symbolizer = env.sysroot_binary("llvm-symbolizer");

        env_guards.push(env.sh.push_env("BSAN_RT_RUST", &rust_runtime));
        env_guards.push(env.sh.push_env("BSAN_RT_LLVM", &llvm_runtime));

        env_guards.push(env.sh.push_env("BSAN_PLUGIN", &pass));
        env_guards.push(env.sh.push_env("BSAN_SYMBOLIZER", &symbolizer));
        env_guards.push(env.sh.push_env("CARGO_BSAN", &cargo_bsan));

        if config.fix {
            let root = &env.root_dir;
            let miri_sp = count_rs(&path!(root / "tests" / "miri-tests" / "should-pass"))?;
            let miri_sf = count_rs(&path!(root / "tests" / "miri-tests" / "should-fail"))?;
            if miri_sp > 0 {
                env_guards.push(env.sh.push_env("BSAN_SP", miri_sp.to_string()));
            }
            if miri_sf > 0 {
                env_guards.push(env.sh.push_env("BSAN_SF", miri_sf.to_string()));
            }
        }

        cmd!(env.sh, "{cargo_bsan} bsan setup").run()?;
        let rustflags = cmd!(env.sh, "{cargo_bsan} bsan setup --print-rustflags").output()?;
        let rustflags = String::from_utf8(rustflags.stdout)?;

        env_guards.push(env.sh.push_env("BSAN_RUSTFLAGS", rustflags.trim()));

        if config.allow_unsafe_deps {
            env_guards.push(env.sh.push_env("BSAN_UNSAFE_DEPS", "1"))
        }

        let add_bless = if config.bless { "--bless" } else { "" };
        cmd!(env.sh, "cargo test -p bsan --test ui -- {add_bless}").run()?;
        Ok(())
    })?;
    Ok(())
}

#[derive(Debug, Clone, Copy, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum Component {
    CargoBsan,
    BsanRt,
    CompilerRt,
    BsanPass,
}

#[macro_export]
macro_rules! all_components {
    () => {
        [Component::CargoBsan, Component::BsanRt, Component::CompilerRt, Component::BsanPass]
    };
}

impl Deref for Component {
    type Target = dyn Buildable;

    fn deref(&self) -> &Self::Target {
        match self {
            Component::CargoBsan => &CargoBsan,
            Component::BsanRt => &BsanRt,
            Component::CompilerRt => &CompilerRt,
            Component::BsanPass => &BsanPass,
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
                    Ok(())
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

impl_component!(CargoBsan, "cargo-bsan", true, false);

static RT_FLAGS: &[&str] = &[
    "-Cpanic=abort",
    "-Zpanic_abort_tests",
    "-Cembed-bitcode=yes",
    "-Clto",
    "-Crelocation-model=pic",
];

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
        cfg.define("BSAN_CLANG_FORMAT", env.sysroot_binary("clang-format"));
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
        let arch = host.split("-").next().unwrap_or_else(|| {
            panic!("Invalid target triple: `{}`", env.toolchain_config.meta.host)
        });
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
    fn install(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.in_mode(Mode::Release, |env| {
            let built = self.build(env, args)?.expect("Compiler-rt was not built.");
            env.copy_to_sysroot_libdir(&built)
        })
    }
}

struct BsanRt;

impl Buildable for BsanRt {
    fn artifact(&self, _env: &BsanEnv) -> String {
        "libbsan_rt.a".into()
    }

    fn doc(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.doc("bsan-rt", args)
    }

    fn build(&self, env: &mut BsanEnv, args: &[String]) -> Result<Option<PathBuf>> {
        let llvm_objcopy = env.target_binary("llvm-objcopy");
        let rust_runtime = env.with_flags("RUSTFLAGS", RT_FLAGS, |env| {
            env.build("bsan-rt", args)?;
            Ok(env.assert_artifact(&self.artifact(env)))
        })?;

        cmd!(env.sh, "{llvm_objcopy} -w -G __bsan_*").arg(&rust_runtime).quiet().run()?;

        Ok(Some(rust_runtime))
    }

    fn test(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.with_flags("RUSTFLAGS", RT_FLAGS, |env| env.test("bsan-rt", args))
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

    fn install(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.in_mode(Mode::Release, |env| {
            self.build(env, args)?;
            let runtime = env.assert_artifact(&self.artifact(env));
            env.copy_to_sysroot_libdir(&runtime)
        })
    }
}

struct BsanPass;

impl BsanPass {
    fn cmake(env: &mut BsanEnv) -> Result<Config> {
        let source_dir = path!(env.root_dir / "bsan-pass");
        let output_dir = path!(env.artifact_dir() / "bsan-pass");
        let mut cfg = env.llvm_cmake(&source_dir, &output_dir, &[])?;
        cfg.define("BSAN_CLANG_FORMAT", env.sysroot_binary("clang-format"));
        Ok(cfg)
    }

    fn fmt(env: &mut BsanEnv, check: bool) -> Result<()> {
        let mut cfg = BsanPass::cmake(env)?;
        cfg.define("BSAN_CLANG_FORMAT", env.sysroot_binary("clang-format"));
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
