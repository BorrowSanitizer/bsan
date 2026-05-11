// This module was ported from Miri (commit:072a9fa) and modified by our team.
use crate::errors::UBResult;
use crate::global::{GlobalCtx, ProtectedTags};
use crate::helpers::{AllocRange, Size};
use crate::tree_borrows::perms::AccessKind;
use crate::{AllocId, BorTag, RetagInfo};

pub mod data_structures;
pub mod diagnostics;
mod exhaustive;
mod foreign_access_skipping;
pub mod perms;
pub mod tree;
mod tree_visitor;
mod wildcard;

pub use perms::*;

use self::perms::Permission;
pub use self::tree::Tree;

pub type AllocState = Tree;
type GlobalState = ProtectedTags;

impl Tree {
    /// Create a new allocation, i.e. a new tree
    pub fn new_allocation(id: AllocId, size: Size, state: &GlobalCtx) -> Self {
        todo!()
    }

    /// Check that an access on the entire range is permitted, and update
    /// the tree.
    pub fn before_memory_access(
        &mut self,
        access_kind: AccessKind,
        alloc_id: AllocId,
        prov: Option<BorTag>,
        range: AllocRange,
    ) -> UBResult<()> {
        /*
        let global = machine.borrow_tracker.as_ref().unwrap();
        let span = machine.current_user_relevant_span();
        self.perform_access(
            prov,
            range,
            access_kind,
            diagnostics::AccessCause::Explicit(access_kind),
            global,
            alloc_id,
            span,
        ) */
        Ok(())
    }

    /// Check that this pointer has permission to deallocate this range.
    pub fn before_memory_deallocation(
        &mut self,
        alloc_id: AllocId,
        prov: Option<BorTag>,
        size: Size,
    ) -> UBResult<()> {
        /*
        let global = machine.borrow_tracker.as_ref().unwrap();
        let span = machine.current_user_relevant_span();
        self.dealloc(prov, alloc_range(Size::ZERO, size), global, alloc_id, span)*/
        Ok(())
    }

    /// A tag just lost its protector.
    ///
    /// This emits a special kind of access that is only applied
    /// to accessed locations, as a protection against other
    /// tags not having been made aware of the existence of this
    /// protector.
    pub fn release_protector(
        &mut self,
        global: &GlobalCtx,
        tag: BorTag,
        alloc_id: AllocId, // diagnostics
    ) {
        /*
        let span = machine.current_user_relevant_span();
        self.perform_protector_end_access(tag, global, alloc_id, span)?;

        self.update_exposure_for_protector_release(tag);

        interp_ok(()) */
    }
}

/// Policy for a new borrow.
#[derive(Debug, Clone, Copy)]
pub struct NewPermission {
    /// Permission for the frozen part of the range.
    pub(crate) freeze_perm: Permission,
    /// Whether a read access should be performed on the frozen part on a retag.
    pub(crate) freeze_access: bool,
    /// Permission for the non-frozen part of the range.
    pub(crate) nonfreeze_perm: Permission,
    /// Whether a read access should be performed on the non-frozen
    /// part on a retag.
    pub(crate) nonfreeze_access: bool,
    /// Permission for memory outside the range.
    pub(crate) outside_perm: Permission,
    /// Whether this pointer is part of the arguments of a function call.
    /// `protector` is `Some(_)` for all pointers marked `noalias`.
    pub(crate) protector: Option<ProtectorKind>,
}

impl<'tcx> NewPermission {
    /// Determine NewPermission of the reference/Box from the type of the pointee.
    ///
    /// A `ref_mutability` of `None` indicates a `Box` type.
    pub(crate) fn new(info: RetagInfo<'tcx>) -> Self {
        /*
        let ty_is_unpin = pointee.is_unpin(*cx.tcx, cx.typing_env())
            && pointee.is_unsafe_unpin(*cx.tcx, cx.typing_env());
        let ty_is_freeze = pointee.is_freeze(*cx.tcx, cx.typing_env());
        let is_protected = retag_kind == RetagKind::FnEntry;

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

        Some(NewPermission {
            freeze_perm,
            freeze_access: initial_access(&freeze_perm),
            nonfreeze_perm,
            nonfreeze_access: initial_access(&nonfreeze_perm),
            outside_perm: if ty_is_freeze { freeze_perm } else { nonfreeze_perm },
            protector: is_protected.then_some(if ref_mutability.is_some() {
                // Strong protector for references
                ProtectorKind::StrongProtector
            } else {
                // Weak protector for boxes
                ProtectorKind::WeakProtector
            }),
        })*/
        todo!()
    }
    pub(crate) fn default_perm(self) -> Permission {
        todo!()
    }
    pub(crate) fn is_freeze(&self) -> bool {
        todo!()
    }
}
/*
trait EvalContextPrivExt<'tcx>: crate::MiriInterpCxExt<'tcx> {
    /// Returns the provenance that should be used henceforth.
    fn tb_reborrow(
        &mut self,
        place: &MPlaceTy<'tcx>, // parent tag extracted from here
        ptr_size: Size,
        new_perm: NewPermission,
        new_tag: BorTag,
    ) -> InterpResult<'tcx, Option<Provenance>> {
        let this = self.eval_context_mut();


        let new_prov = Provenance::Concrete { alloc_id, tag: new_tag };

        if let Some(protect) = new_perm.protector {
            // We register the protection in two different places.
            // This makes creating a protector slower, but checking whether a tag
            // is protected faster.
            this.frame_mut()
                .extra
                .borrow_tracker
                .as_mut()
                .unwrap()
                .protected_tags
                .push((alloc_id, new_tag));
            this.machine
                .borrow_tracker
                .as_mut()
                .expect("We should have borrow tracking data")
                .get_mut()
                .protected_tags
                .insert(new_tag, protect);
        }


        let protected = new_perm.protector.is_some();
        let precise_interior_mut = this
            .machine
            .borrow_tracker
            .as_mut()
            .unwrap()
            .get_mut()
            .borrow_tracker_method
            .get_tree_borrows_params()
            .precise_interior_mut;

        // Compute initial "inside" permissions.
        let loc_state = |frozen: bool| -> LocationState {
            let (perm, access) = if frozen {
                (new_perm.freeze_perm, new_perm.freeze_access)
            } else {
                (new_perm.nonfreeze_perm, new_perm.nonfreeze_access)
            };
            let sifa = perm.strongest_idempotent_foreign_access(protected);
            if access {
                LocationState::new_accessed(perm, sifa)
            } else {
                LocationState::new_non_accessed(perm, sifa)
            }
        };
        let inside_perms = if !precise_interior_mut {
            // For `!Freeze` types, just pretend the entire thing is an `UnsafeCell`.
            let ty_is_freeze = place.layout.ty.is_freeze(*this.tcx, this.typing_env());
            let state = loc_state(ty_is_freeze);
            DedupRangeMap::new(ptr_size, state)
        } else {
            // The initial state will be overwritten by the visitor below.
            let mut perms_map: DedupRangeMap<LocationState> = DedupRangeMap::new(
                ptr_size,
                LocationState::new_accessed(
                    Permission::new_disabled(),
                    IdempotentForeignAccess::None,
                ),
            );
            this.visit_freeze_sensitive(place, ptr_size, |range, frozen| {
                let state = loc_state(frozen);
                for (_loc_range, loc) in perms_map.iter_mut(range.start, range.size) {
                    *loc = state;
                }
                Ok(())
            })?;
            perms_map
        };

        let alloc_extra = this.get_alloc_extra(alloc_id)?;
        let mut tree_borrows = alloc_extra.borrow_tracker_tb().borrow_mut();

        for (perm_range, perm) in inside_perms.iter_all() {
            if perm.accessed() {
                // Some reborrows incur a read access to the parent.
                // Adjust range to be relative to allocation start (rather than to `place`).
                let range_in_alloc = AllocRange {
                    start: Size::from_bytes(perm_range.start) + base_offset,
                    size: Size::from_bytes(perm_range.end - perm_range.start),
                };

                tree_borrows.perform_access(
                    parent_prov,
                    range_in_alloc,
                    AccessKind::Read,
                    diagnostics::AccessCause::Reborrow,
                    this.machine.borrow_tracker.as_ref().unwrap(),
                    alloc_id,
                    this.machine.current_user_relevant_span(),
                )?;
            }
        }
        // Record the parent-child pair in the tree.
        tree_borrows.new_child(
            base_offset,
            parent_prov,
            new_tag,
            inside_perms,
            new_perm.outside_perm,
            protected,
            this.machine.current_user_relevant_span(),
        )?;
        drop(tree_borrows);

        Ok(Some(new_prov))
    }
} */
