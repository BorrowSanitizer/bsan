#![feature(rustc_private)]
<<<<<<< Updated upstream
#![feature(box_patterns)]
extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;
mod retag;
=======

extern crate rustc_abi;
extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_index;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_session;
>>>>>>> Stashed changes

pub mod callbacks;
pub mod cx;
pub mod expand_retag;
use std::env;
<<<<<<< Updated upstream

use retag::AddRetagPass;
use rustc_driver::Compilation;
use rustc_interface::interface::Compiler;
use rustc_middle::ty::TyCtxt;

pub const BSAN_BUG_REPORT_URL: &str = "https://github.com/BorrowSanitizer/rust/issues/new";
pub const BSAN_DEFAULT_ARGS: &[&str] =
    &["--cfg=bsan", "-Zmir-opt-level=0", "-Cpasses=bsan", "-Zmir-emit-retag", "-Zllvm-emit-retag"];

pub struct BSanCtx {}
impl rustc_driver::Callbacks for BSanCtx {
    fn after_analysis(&mut self, compiler: &Compiler, tcx: TyCtxt<'_>) -> Compilation {
        AddRetagPass::run(self, compiler, tcx)
    }
}

=======

pub use expand_retag::RetagFields;

pub use crate::callbacks::BSanCallBacks;

pub const BSAN_BUG_REPORT_URL: &str = "https://github.com/BorrowSanitizer/rust/issues/new";
pub const BSAN_DEFAULT_ARGS: &[&str] =
    &["--cfg=bsan", "-Zmir-opt-level=0", "-Cpasses=bsan", "-Zmir-emit-retag", "-Zllvm-emit-retag"];

>>>>>>> Stashed changes
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
