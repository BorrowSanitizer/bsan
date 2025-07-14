use rustc_interface::interface;
use rustc_middle::ty::{Ty, TyCtxt};
use rustc_middle::util::Providers;
use rustc_session::Session;
pub struct BSanCallBacks {}
impl rustc_driver::Callbacks for BSanCallBacks {
    fn config(&mut self, config: &mut interface::Config) {
        config.override_queries = Some(query_provider)
    }
}

fn query_provider(sess: &Session, prov: &mut Providers) {
    prov.queries.retag_perm = override_retag_perm;
}

fn override_retag_perm<'tcx>(tcx: TyCtxt<'tcx>, key: (Ty<'tcx>, RetagParams)) -> Option<u64> {
    None
}
