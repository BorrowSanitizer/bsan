use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_interface::Config;
use rustc_middle::mir::Body;
use rustc_middle::ty::TyCtxt;
use rustc_middle::util::Providers;
use rustc_session::Session;

use crate::expand_retag::{ExpandRetags, RetagFields};

pub struct BSanCallBacks {
    pub retag_fields: RetagFields,
}

fn bsan_override(_session: &Session, providers: &mut Providers) {
    providers.optimized_mir = run_mir_passes;
    providers.extern_queries.optimized_mir = run_mir_passes_extern;
}

fn run_mir_passes_extern<'tcx>(tcx: TyCtxt<'tcx>, def_id: DefId) -> &Body<'tcx> {
    let body = (rustc_interface::DEFAULT_QUERY_PROVIDERS.extern_queries.optimized_mir)(tcx, def_id);
    run_bsan_mir_passes(tcx, body)
}

fn run_mir_passes<'tcx>(tcx: TyCtxt<'tcx>, def_id: LocalDefId) -> &Body<'tcx> {
    let body = (rustc_interface::DEFAULT_QUERY_PROVIDERS.optimized_mir)(tcx, def_id);
    run_bsan_mir_passes(tcx, body)
}

fn run_bsan_mir_passes<'tcx>(tcx: TyCtxt<'tcx>, body: &'tcx Body<'tcx>) -> &'tcx Body<'tcx> {
    let mut transformed_body = body.clone();
    ExpandRetags::run_pass(tcx, &mut transformed_body, RetagFields::All);
    tcx.arena.alloc(transformed_body)
}

impl rustc_driver::Callbacks for BSanCallBacks {
    fn config(&mut self, config: &mut Config) {
        config.override_queries = Some(bsan_override);
    }
}
