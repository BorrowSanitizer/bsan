use bsan_shared::{AccessKind, NewPermission, Permission, ProtectorKind};
use rustc_interface::Config;
use rustc_middle::mir::RetagKind;
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
    providers.queries.retag_perm = retag_perm;
}

fn retag_perm<'tcx>(
    tcx: TyCtxt<'tcx>,
    key: (TypingEnv<'tcx>, Ty<'tcx>, Ty<'tcx>, RetagKind),
) -> Option<u64> {
    let (env, target_ty, pointee_ty, kind) = key;
    let ref_mutability =
        if let ty::Ref(_, _, mutability) = target_ty.kind() { Some(*mutability) } else { None };
    let ty_is_unpin = pointee_ty.is_unpin(tcx, env);
    let ty_is_freeze = pointee_ty.is_freeze(tcx, env);
    let is_protected = kind == RetagKind::FnEntry;

    if matches!(ref_mutability, Some(Mutability::Mut) | None if !ty_is_unpin) {
        // Mutable reference / Box to pinning type: retagging is a NOP.
        // FIXME: with `UnsafePinned`, this should do proper per-byte tracking.
        return None;
    }

    let freeze_perm = match ref_mutability {
        // Shared references are frozen.
        Some(Mutability::Not) => Permission::new_frozen(),
        // Mutable references and Boxes are reserved.
        _ => Permission::new_reserved_frz(),
    };

    let nonfreeze_perm = match ref_mutability {
        // Shared references are "transparent".
        Some(Mutability::Not) => Permission::new_cell(),
        // *Protected* mutable references and boxes are reserved without regarding for interior mutability.
        _ if is_protected => Permission::new_reserved_frz(),
        // Unprotected mutable references and boxes start in `ReservedIm`.
        _ => Permission::new_reserved_im(),
    };

    // Everything except for `Cell` gets an initial access.
    let initial_access = |perm: &Permission| !perm.is_cell();

    let perm = NewPermission {
        freeze_perm,
        freeze_access: initial_access(&freeze_perm),
        nonfreeze_perm,
        nonfreeze_access: initial_access(&nonfreeze_perm).then_some(AccessKind::Read),
        ty_is_freeze,
        protector: is_protected.then_some(if ref_mutability.is_some() {
            // Strong protector for references
            ProtectorKind::StrongProtector
        } else {
            // Weak protector for boxes
            ProtectorKind::WeakProtector
        }),
    };

    Some(NewPermission::into_raw(perm))
}
