use rustc_interface::Config;
use rustc_middle::mir::RetagParams;
use rustc_middle::ty::{Ty, TyCtxt, TypingEnv};
use rustc_middle::util::Providers;
use rustc_session::Session;

pub struct BSanCallBacks {}
impl rustc_driver::Callbacks for BSanCallBacks {
    fn config(&mut self, config: &mut Config) {
        config.override_queries = Some(override_queries);
    }
}

fn override_queries(_sess: &Session, providers: &mut Providers) {
    providers.retag_perm = retag_perm;
}

fn retag_perm<'tcx>(
    _tcx: TyCtxt<'tcx>,
    _key: (TypingEnv<'tcx>, Ty<'tcx>, RetagParams),
) -> Option<u64> {
    Some(0)
}
