use std::fs;
use std::ops::Deref;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use chrono::Local;
use clap::ValueEnum;
use cmake::Config;
use path_macro::path;
use xshell::cmd;

use crate::env::{BsanEnv, Mode};
use crate::utils::{install_git_hooks, BenchTool};
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
            Command::Bench { runs, warmups, miri_flags, tools } => {
                Self::bench(env, runs, warmups, tools, miri_flags)
            }
        }
    }

    fn bench(
        env: &mut BsanEnv,
        runs: i32,
        warmups: i32,
        tools: Vec<BenchTool>,
        // Unfortunately cannot move this to be a part of BenchTool because
        // of limitations with Clap's ValueEnum
        miri_flags: Vec<String>,
    ) -> Result<()> {
        println!("Benchmarking...");

        // Ensure hyperfine is installed
        cmd!(env.sh, "cargo install hyperfine --locked")
            .quiet()
            .run()
            .context("Failed to install hyperfine")?;

        let bench_path = path!(env.root_dir / "tests" / "benches");

        if !env.sh.path_exists(&bench_path) {
            return Err(anyhow!("Corrupted work tree! benches submodule missing!"));
        }

        // Pull the latest benches changes
        env.sh.change_dir(&bench_path);
        // TODO: Uncomment this when the benches repo is public, for now it's easier to do it manually
        // cmd!(env.sh, "git pull").quiet().run().context("Failed to pull benches repo!")?;

        let target_dir = path!(&bench_path / "programs" / "src" / "bin");
        // While probably not the best unique global ID, it is *extremely* unlikely that two benches are triggered at the same
        // exact time (famous last words)
        let time = Local::now().format("%Y-%m-%d_%H-%M-%S");
        env.sh
            .create_dir(path!(&bench_path / "results" / format!("results_{}", &time)))
            .context("Failed to create results directory!")?;

        // Most baseline version of Miri with eveything except TB aliasing disabled
        let default_miri_flags: Vec<String> = vec![
            "-Zmiri-tree-borrows",
            "-Zmiri-ignore-leaks",
            "-Zmiri-disable-alignment-check",
            "-Zmiri-disable-data-race-detector",
            "-Zmiri-disable-validation",
            "-Zmiri-disable-weak-memory-emulation",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let flags = if miri_flags.is_empty() { default_miri_flags } else { miri_flags };

        for file_path in env
            .sh
            .read_dir(target_dir)
            .context("Corrupt benches submodule! Failed to read over target programs")?
        {
            let file = file_path.file_name().unwrap();
            let program_name = file.to_str().unwrap().strip_suffix(".rs").unwrap();

            println!(
                r#"
                
                    ==============================
                    Benchmarking: {program_name}

                    Run Spec:
                        Differentially testing against: {tools:#?}
                        Runs: {runs}
                        Warmup per experiment: {warmups}
                    ==============================
                "#
            );

            // Instrument program with BSAN
            Self::inst(env, file_path.to_str().unwrap().to_string(), false, Default::default())
                .with_context(|| {
                    format!("Failed to instrument {program_name} at {file_path:#?}")
                })?;

            let mut commands: Vec<String> = Vec::new();

            if tools.contains(&BenchTool::MIRI) {
                env.sh.set_var("MIRIFLAGS", &flags.join(" "));
                // TODO: Possible variable for changing miri's toolchain
                // let miri_toolchain = ""

                cmd!(env.sh, "cargo miri setup")
                    .quiet()
                    .run()
                    .context("Failed to setup Miri")?;

                commands.push(format!("cargo miri run -p programs --bin {program_name}"));
            }

            if tools.contains(&BenchTool::NATIVE) {
                // Build base program with cargo
                cmd!(env.sh, "cargo build -p programs")
                    .arg("--bin")
                    .arg(program_name)
                    .quiet()
                    .run()
                    .context("Failed to build uninstrumented program with cargo")?;

                commands.push(format!(" ../../target/debug/{program_name}"));
            }

            if tools.contains(&BenchTool::ASAN) {
                env.sh.set_var("RUSTFLAGS", "-Zsanitizer-address");

                // TODO: Disable more flags, pass these in the RunSpec
                env.sh.set_var(
                    "ASAN_OPTIONS",
                    vec!["detect_leaks=false", "detect_deadlocks=false", "halt_on_error=false"]
                        .join(":"),
                );

                cmd!(env.sh, "cargo build -Zbuild-std -p programs")
                    .quiet()
                    .arg("--bin")
                    .arg(format!("asan-{program_name}"))
                    .run()
                    .context("Failed to build ASAN program")?;

                commands.push(format!(" ../../target/debug/asan-{program_name}"));
            }

            // Push BSAN command
            commands.push(format!(" ./{program_name}"));

            // Run hyperfine with no default shell and ignorning non-zero exit codes by default
            // TODO: Add these to the runspec
            cmd!(env.sh, "hyperfine -i -N")
                .arg("--warmup")
                .arg(warmups.to_string())
                .arg("--runs")
                .arg(runs.to_string())
                .arg("--export-json")
                .arg(format!("./results/results_{time}/{program_name}-results.json"))
                // .arg("--cleanup")
                // .arg(format!("rm ./{program_name}"))
                .args(commands)
                .run()
                .context("Failed to run benchmark with hyperfine")?;
        }

        Ok(())
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
        let sysroot_dir = path!(&env.build_dir / "sysroot");
        env.sh.set_var("BSAN_SYSROOT", &sysroot_dir);

        env.in_mode(Mode::Release, |env| {
            let args = &[];
            let mut env_guards = vec![];
            let cargo_bsan = env.build_artifact(CargoBsan, args)?;
            let runtime = env.build_artifact(BsanRt, args)?;
            let pass = env.build_artifact(BsanPass, args)?;
            let symbolizer = env.sysroot_binary("llvm-symbolizer");

            env_guards.push(env.sh.push_env("BSAN_RT", &runtime));
            env_guards.push(env.sh.push_env("BSAN_PLUGIN", &pass));
            env_guards.push(env.sh.push_env("BSAN_SYMBOLIZER", &symbolizer));
            env_guards.push(env.sh.push_env("CARGO_BSAN", &cargo_bsan));

            cmd!(env.sh, "{cargo_bsan} bsan setup").run()?;
            let rustflags = cmd!(env.sh, "{cargo_bsan} bsan setup --print-rustflags").output()?;
            let rustflags = String::from_utf8(rustflags.stdout)?;

            env_guards.push(env.sh.push_env("BSAN_RUSTFLAGS", rustflags.trim()));

            let add_bless = if bless { "--bless" } else { "" };
            cmd!(env.sh, "cargo test -p bsan --test ui -- {add_bless}").run()?;
            Ok(())
        })?;

        crate::all_components!().iter().try_for_each(|c| c.install(env, &[]))?;
        cmd!(env.sh, "python3 tests/test-cargo-bsan/run_test.py").run()?;
        Ok(())
    }

    fn ci(env: &mut BsanEnv, args: &[String]) -> Result<()> {
        let components = crate::all_components!();
        // We want to ensure that all formatting steps are completed for every component
        // before we try running more expensive checks, like unit and integration tests.
        Self::fmt(env, true)?;
        components.iter().try_for_each(|c| c.clippy(env, args))?;
        components.iter().try_for_each(|c| c.test(env, args))?;
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
        env.in_mode(Mode::Release, |env| {
            let plugin = env.build_artifact(BsanPass, &[])?;

            let runtime = if debug {
                env.build_artifact(BsanRt, &["--features".to_string(), "debug".to_string()])?
            } else {
                env.build_artifact(BsanRt, &[])?
            };

            let cargo_bsan = env.build_artifact(CargoBsan, &[])?;
            let sysroot_dir = path!(&env.build_dir / "sysroot");

            let mut env_guards = vec![];
            env_guards.push(env.sh.push_env("BSAN_PLUGIN", &plugin));
            env_guards.push(env.sh.push_env("BSAN_RT", &runtime));
            env_guards.push(env.sh.push_env("BSAN_SYSROOT", &sysroot_dir));

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

            Ok(())
        })
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum Component {
    CargoBsan,
    BsanRt,
    BsanRtCore,
    CompilerRt,
    BsanPass,
}

#[macro_export]
macro_rules! all_components {
    () => {
        [
            Component::CargoBsan,
            Component::BsanRt,
            Component::BsanRtCore,
            Component::CompilerRt,
            Component::BsanPass,
        ]
    };
}

impl Deref for Component {
    type Target = dyn Buildable;

    fn deref(&self) -> &Self::Target {
        match self {
            Component::CargoBsan => &CargoBsan,
            Component::BsanRt => &BsanRt,
            Component::BsanRtCore => &BsanRtCore,
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
        let llvm_wrapper = env.build_artifact(CompilerRt, &[])?;
        let rust_runtime = env.build_artifact(BsanRtCore, args)?;

        let dest_archive = path!(env.artifact_dir() / self.artifact(env));
        cmd!(env.sh, "cp {llvm_wrapper} {dest_archive}").quiet().run()?;

        let tmp_dir = env.sh.create_temp_dir()?;
        env.cd(tmp_dir.path(), |env| {
            cmd!(env.sh, "{llvm_ar} -x {rust_runtime}").quiet().run()?;

            let file_names: Vec<String> = fs::read_dir(tmp_dir.path())
                .unwrap()
                .filter_map(|entry| {
                    let path = entry.ok().unwrap().path();
                    if path.is_file() {
                        path.to_str().map(|s| s.to_owned())
                    } else {
                        None
                    }
                })
                .collect();

            // Finally, add the objects into the static archive of C++ component.
            cmd!(env.sh, "{llvm_ar} -r {dest_archive}").args(file_names).quiet().run()?;
            Ok(())
        })?;

        Ok(Some(path!(env.artifact_dir() / dest_archive)))
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
        let llvm_objcopy = env.target_binary("llvm-objcopy");
        let rust_runtime = env.with_flags("RUSTFLAGS", RT_FLAGS, |env| {
            env.build("bsan-rt", args)?;
            Ok(env.assert_artifact(&self.artifact(env)))
        })?;

        cmd!(env.sh, "{llvm_objcopy} -w -G __bsan_* -G __BSAN_*")
            .arg(&rust_runtime)
            .quiet()
            .run()?;

        Ok(Some(rust_runtime))
    }

    fn test(&self, env: &mut BsanEnv, args: &[String]) -> Result<()> {
        env.with_flags("RUSTFLAGS", &RT_FLAGS, |env| env.test("bsan-rt", args))
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
