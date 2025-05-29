#![feature(rustc_private)]
#![feature(box_patterns)]
extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;
mod retag;

use std::env;

use retag::AddRetagPass;
use rustc_driver::Compilation;
use rustc_interface::interface::Compiler;
use rustc_middle::ty::TyCtxt;

pub const BSAN_BUG_REPORT_URL: &str = "https://github.com/BorrowSanitizer/rust/issues/new";
pub const BSAN_DEFAULT_ARGS: &[&str] = &["--cfg=bsan", "-Zmir-opt-level=0", "-Cpasses=bsan"];

pub struct BSanCtx {}
impl rustc_driver::Callbacks for BSanCtx {
    fn after_analysis(&mut self, compiler: &Compiler, tcx: TyCtxt<'_>) -> Compilation {
        AddRetagPass::run(self, compiler, tcx)
    }
}

/// Execute a compiler with the given CLI arguments and callbacks.
pub fn run_compiler(mut args: Vec<String>, target_crate: bool, ctx: &mut BSanCtx) -> ! {
    if target_crate {
        let mut additional_args =
            BSAN_DEFAULT_ARGS.iter().map(ToString::to_string).collect::<Vec<_>>();

        let plugin = env::var("BSAN_PLUGIN").expect("BSAN_PLUGIN environment variable not set.");
        additional_args.push(format!("-Zllvm-plugins={plugin}"));

        let runtime =
            env::var_os("BSAN_RT_SYSROOT").expect("BSAN_RT_SYSROOT environment variable not set.");
        let rt = runtime.to_string_lossy();
        additional_args.push(format!("-L{rt}"));
        additional_args.push("-lstatic=bsan_rt".to_string());

        args.splice(1..1, additional_args);
    }
    rustc_driver::run_compiler(&args, ctx);
    std::process::exit(0)
}
