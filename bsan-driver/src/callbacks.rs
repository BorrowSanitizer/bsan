use bsan_shared::{AccessKind, Permission, PermissionInfo, ProtectorKind};
use rustc_interface::Config;
use rustc_middle::mir::{RetagKind, RetagParams};
use rustc_middle::ty::{self, Mutability, Ty, TyCtxt, TypingEnv};
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
    tcx: TyCtxt<'tcx>,
    key: (TypingEnv<'tcx>, Ty<'tcx>, Ty<'tcx>, RetagParams),
) -> Option<u64> {
    let (env, pointer_ty, pointee_ty, params) = key;
    let ty_is_freeze = pointee_ty.is_freeze(tcx, env);
    let ty_is_unpin = pointee_ty.is_unpin(tcx, env);
    let is_protected = params.kind == RetagKind::FnEntry;
    let info = match pointer_ty.kind() {
        ty::Ref(_, _, mutability) => {
            let (perm_kind, access_kind) = match mutability {
                Mutability::Not if ty_is_unpin => (
                    Permission::new_reserved(ty_is_freeze && !params.in_unsafe_cell, is_protected),
                    Some(AccessKind::Read),
                ),
                Mutability::Mut if ty_is_freeze => {
                    if params.in_unsafe_cell {
                        (Permission::new_cell(), None)
                    } else {
                        (Permission::new_frozen(), Some(AccessKind::Read))
                    }
                }
                // Raw pointers never enter this function so they are not handled.
                // However raw pointers are not the only pointers that take the parent
                // tag, this also happens for `!Unpin` `&mut`s and interior mutable
                // `&`s, which are excluded above.
                _ => return None,
            };

            let protector_kind = is_protected.then_some(ProtectorKind::StrongProtector);
            PermissionInfo { perm_kind, protector_kind, access_kind }
        }

        ty::Adt(def, ..) if def.is_box() => {
            let protector_kind = is_protected.then_some(ProtectorKind::WeakProtector);
            let perm_kind =
                Permission::new_reserved(ty_is_freeze && !params.in_unsafe_cell, is_protected);
            PermissionInfo { perm_kind, protector_kind, access_kind: None }
        }
        _ => return None,
    };
    Some(PermissionInfo::into_raw(info))
}
