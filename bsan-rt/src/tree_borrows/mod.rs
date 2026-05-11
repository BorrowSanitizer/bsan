// This module was ported from Miri (commit:072a9fa) and modified by our team.
// RetagMode and implicit writes are not implemented yet.
use crate::errors::UBResult;
use crate::global::{GlobalCtx, ProtectedTags};
use crate::helpers::{AllocRange, Size};
use crate::tree_borrows::perms::AccessKind;
use crate::{AllocId, BorTag, RetagFlags, RetagInfo, Span};

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
    pub fn new_allocation(tag: BorTag, size: Size, span: Span) -> Self {
        Tree::new(tag, size, span)
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
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct NewPermission {
    /// Permission for the frozen part of the range.
    pub freeze_perm: Permission,
    /// Whether a read access should be performed on the frozen part on a retag.
    pub freeze_access: bool,
    /// Permission for the non-frozen part of the range.
    pub nonfreeze_perm: Permission,
    /// What kind of access should be performed on the non-frozen part on a retag.
    pub nonfreeze_access: Option<AccessKind>,
    // Whether the type is frozen.
    pub ty_is_freeze: bool,
    /// Whether this pointer is part of the arguments of a function call.
    /// `protector` is `Some(_)` for all pointers marked `noalias`.
    pub protector: Option<ProtectorKind>,
}

impl NewPermission {
    pub fn new(info: RetagInfo<'_>) -> Self {
        let is_mutable: bool = info.flags.contains(RetagFlags::IS_MUTABLE);
        let is_protected = info.flags.contains(RetagFlags::IS_PROTECTED);
        let ty_is_freeze = info.flags.contains(RetagFlags::IS_FREEZE);
        let is_box = info.flags.contains(RetagFlags::IS_BOX);
        let freeze_perm =
            if is_mutable { Permission::new_reserved_frz() } else { Permission::new_frozen() };

        let nonfreeze_perm = if is_mutable {
            if is_protected {
                Permission::new_reserved_frz()
            } else {
                Permission::new_reserved_im()
            }
        } else {
            Permission::new_cell()
        };

        // Everything except for `Cell` gets an initial access.
        let initial_access = |perm: &Permission| !perm.is_cell();

        NewPermission {
            freeze_perm,
            freeze_access: initial_access(&freeze_perm),
            nonfreeze_perm,
            nonfreeze_access: initial_access(&nonfreeze_perm).then_some(AccessKind::Read),
            ty_is_freeze,
            protector: is_protected.then_some(if is_box {
                // Weak protector for boxes
                ProtectorKind::WeakProtector
            } else {
                // Strong protector for references
                ProtectorKind::StrongProtector
            }),
        }
    }
    pub fn default_perm(&self) -> Permission {
        if self.ty_is_freeze {
            self.freeze_perm
        } else {
            self.nonfreeze_perm
        }
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
