// Components in this library were ported from Miri and then modified by our team.
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use spin::MutexGuard;

use crate::errors::{UBInfo, UBResult};
use crate::helpers::{AllocRange, Size};
use crate::sanitizer_common::Span;
use crate::tree_borrows::data_structures::{AccessType, DedupRangeMap};
use crate::tree_borrows::diagnostics::AccessCause;
use crate::tree_borrows::perms::{AccessKind, Permission};
use crate::tree_borrows::tree::LocationState;
use crate::tree_borrows::{IdempotentForeignAccess, NewPermission};
use crate::{AllocInfoPtr, BorTag, GlobalCtx, LazyTree, Provenance, RetagFlags, RetagInfo};

#[derive(Debug)]
pub struct BorrowTracker {
    bor_tag: BorTag,
    alloc_info: AllocInfoPtr,
    range: AllocRange,
}

/// A guard over the `Tree` for an allocation.
struct TreeGuard<'b>(MutexGuard<'b, Option<LazyTree>>);

impl Deref for TreeGuard<'_> {
    type Target = LazyTree;
    fn deref(&self) -> &LazyTree {
        self.0.as_ref().unwrap()
    }
}

impl DerefMut for TreeGuard<'_> {
    fn deref_mut(&mut self) -> &mut LazyTree {
        self.0.as_mut().unwrap()
    }
}

impl BorrowTracker {
    fn tree(&self) -> TreeGuard<'_> {
        TreeGuard(self.alloc_info.tree.lock())
    }

    fn take_tree(&self) -> LazyTree {
        unsafe { self.alloc_info.tree.lock().take().unwrap_unchecked() }
    }

    unsafe fn for_alloc_inner(prov: Provenance) -> UBResult<Self> {
        // Safety:
        // Our instrumentation pass guarantees that if a pointer's
        // provenance is non-null and not omnivalid, then it will contain
        // valid allocation info pointer.
        debug_assert!(!prov.alloc_info.is_null());
        let alloc_info: AllocInfoPtr = unsafe { NonNull::new_unchecked(prov.alloc_info).into() };
        if alloc_info.tree.lock().is_none() {
            return Err(UBInfo::UseAfterFree);
        }
        let size = alloc_info.size.get();
        let range = AllocRange { start: Size::ZERO, size };
        Ok(Self { bor_tag: prov.bor_tag, alloc_info, range })
    }

    pub fn for_alloc<T, F>(prov: Provenance, f: F) -> UBResult<T>
    where
        F: FnOnce(Self) -> UBResult<T>,
        T: Default,
    {
        if prov.bor_tag == BorTag::omnivalid() || prov.bor_tag.is_wildcard() {
            // Only concrete provenance values have `AllocInfo` that we can
            // access directly. This API is intended to have an affect in this case,
            // so we also skip wildcard provenance.
            Ok(T::default())
        } else if prov.bor_tag == BorTag::invalid() {
            Err(UBInfo::UseAfterFree)
        } else {
            unsafe { BorrowTracker::for_alloc_inner(prov) }.and_then(f)
        }
    }

    /// # Safety
    /// Takes in provenance pointer that is checked via debug_asserts
    pub fn for_access<T, F>(
        global_ctx: &GlobalCtx,
        prov: Provenance,
        start: Size,
        access_size: Option<Size>,
        f: F,
    ) -> UBResult<T>
    where
        F: FnOnce(Self) -> UBResult<T>,
        T: Default,
    {
        if prov.bor_tag == BorTag::omnivalid() {
            Ok(T::default())
        } else if prov.bor_tag == BorTag::invalid() {
            if access_size == Some(Size::ZERO) {
                Ok(T::default())
            } else {
                Err(UBInfo::UseAfterFree)
            }
        } else {
            let alloc_info: AllocInfoPtr = if prov.bor_tag.is_wildcard() {
                let size = access_size.unwrap_or(Size::ZERO);
                let range = AllocRange { start, size };
                if let Some(exposed) = global_ctx.get_exposed_provenance(range) {
                    exposed
                } else {
                    // We cannot resolve this wildcard access to an exposed
                    // allocation. The access may target an allocation that we
                    // do not track at all (e.g. a global, which has omnivalid
                    // provenance and so is never registered as exposed), so we
                    // permit it to avoid false positives.
                    return Ok(T::default());
                }
            } else {
                debug_assert!(!prov.alloc_info.is_null());
                unsafe { NonNull::new_unchecked(prov.alloc_info).into() }
            };

            let alloc_size = alloc_info.size.get();
            let base_addr = unsafe { alloc_info.base_addr() };
            let access_size = access_size.unwrap_or(alloc_size);

            // The allocation has been freed (`None`), or the pointer's tag is no
            // longer live in the tree (e.g. it referred to a now-reallocated
            // allocation): either way, accessing it is a use-after-free. A
            // zero-sized access is always permitted. A wildcard tag is never
            // present in the tree itself; it stands in for any exposed tag, so
            // it is live as long as the allocation is.
            let is_live = matches!(
                alloc_info.tree.lock().as_ref(),
                Some(tree) if prov.bor_tag.is_wildcard() || tree.contains_tag(prov.bor_tag)
            );

            if !is_live {
                return if access_size != Size::ZERO {
                    Err(UBInfo::UseAfterFree)
                } else {
                    Ok(T::default())
                };
            }

            let alloc_id = alloc_info.alloc_id.get();

            // It is crucial for this to be a wrapping sub here, since we want to accurately
            // model the affect of applying an oversized offset on the allocation.
            let offset = Size::from_bytes(start.bytes().wrapping_sub(base_addr.bytes()));
            if start < base_addr || (offset + access_size > alloc_size) {
                return if access_size != Size::ZERO {
                    Err(UBInfo::AccessOutOfBounds { alloc_id, access_size, alloc_size, offset })
                } else {
                    Ok(T::default())
                };
            }

            let range = AllocRange { start: offset, size: access_size };
            f(Self { bor_tag: prov.bor_tag, alloc_info, range })
        }
    }

    pub fn retag(
        &self,
        global_ctx: &GlobalCtx,
        retag_info: RetagInfo<'_>,
        span: Span,
    ) -> UBResult<Provenance> {
        let alloc_id = self.alloc_info.alloc_id.get();
        let parent_tag = self.bor_tag;
        let new_tag = BorTag::default();
        // A wildcard parent is never present in the tree: retagging it adds
        // the new tag as a fresh wildcard root instead.
        if !parent_tag.is_wildcard() && !self.tree().contains_tag(parent_tag) {
            return Err(UBInfo::UseAfterFree);
        }
        let new_perm: NewPermission = NewPermission::new(retag_info);

        let protected = new_perm.protector.is_some();
        if let Some(protector) = new_perm.protector {
            // We register the protection in two different places.
            // This makes creating a protector slower, but checking whether a tag
            // is protected faster.
            // Since we return the fully-resolved provenance (including for
            // wildcard parents), the new tag is reachable for `protector_end`.
            global_ctx.protected_tags_mut().add_protector(new_tag, protector);
        }

        // Compute initial "inside" permissions.
        let loc_state = |frozen: bool| -> LocationState {
            let perm = if frozen { new_perm.freeze_perm } else { new_perm.nonfreeze_perm };
            let sifa = perm.strongest_idempotent_foreign_access(protected);
            if perm.associated_access().is_some() {
                assert!(perm.associated_access().unwrap() == AccessKind::Read);
                LocationState::new_accessed(perm, sifa)
            } else {
                LocationState::new_non_accessed(perm, sifa)
            }
        };

        let mut inside_perms = DedupRangeMap::new(
            retag_info.size,
            LocationState::new_accessed(Permission::new_disabled(), IdempotentForeignAccess::None),
        );

        let mut cursor = Size::ZERO;
        if let Some(im_layout) = retag_info.im_layout {
            for &[offset, size] in im_layout {
                if cursor != offset {
                    for (_loc_range, loc) in inside_perms.iter_mut(cursor, offset - cursor) {
                        *loc = loc_state(true);
                    }
                }
                for (_loc_range, loc) in inside_perms.iter_mut(offset, size) {
                    *loc = loc_state(false);
                }
                cursor = offset + size
            }
            if cursor < retag_info.size {
                let width = retag_info.size - cursor;
                for (_loc_range, loc) in inside_perms.iter_mut(cursor, width) {
                    *loc = loc_state(true);
                }
            }
        } else if retag_info.size > Size::ZERO {
            let perm = loc_state(retag_info.flags.contains(RetagFlags::IS_FREEZE));
            for (_loc_range, loc) in inside_perms.iter_mut(Size::ZERO, retag_info.size) {
                *loc = perm;
            }
        }

        let base_offset = self.range.start;
        for (perm_range, loc_state) in inside_perms.iter_all() {
            if let Some(access_kind) = loc_state.permission().associated_access() {
                // Some reborrows incur a read access to the parent.
                // Adjust range to be relative to allocation start
                let range_in_alloc = AllocRange {
                    start: Size::from_bytes(perm_range.start) + base_offset,
                    size: Size::from_bytes(perm_range.end - perm_range.start),
                };

                // Perform the access (update the Tree Borrows FSM)
                self.tree().perform_access(
                    parent_tag,
                    range_in_alloc,
                    access_kind,
                    AccessCause::Reborrow,
                    &global_ctx.protected_tags(),
                    alloc_id,
                    span,
                )?;
            }
        }

        // base offset should be the offset, from zero, where the retag is taking place within the allocation.
        self.tree().new_child(
            base_offset,
            parent_tag,
            new_tag,
            inside_perms,
            new_perm.outside_perm,
            protected,
            span,
        )?;

        Ok(Provenance { alloc_info: self.alloc_info.0.as_ptr(), bor_tag: new_tag })
    }

    pub fn protector_end(&self, global_ctx: &GlobalCtx, span: Span) -> UBResult<()> {
        self.tree().perform_protector_end_access(
            self.bor_tag,
            &global_ctx.protected_tags(),
            self.alloc_info.alloc_id.get(),
            span,
        )
    }

    pub fn access(
        &self,
        global_ctx: &GlobalCtx,
        access_kind: AccessKind,
        span: Span,
    ) -> UBResult<()> {
        self.tree().perform_access(
            self.bor_tag,
            self.range,
            access_kind,
            AccessCause::Explicit(access_kind),
            &global_ctx.protected_tags(),
            self.alloc_info.alloc_id.get(),
            span,
        )
    }

    pub fn dealloc(self, global_ctx: &GlobalCtx, span: Span) -> UBResult<()> {
        self.take_tree().dealloc(
            self.bor_tag,
            self.range,
            &global_ctx.protected_tags(),
            self.alloc_info.alloc_id.get(),
            span,
        )?;
        let range = unsafe { self.alloc_info.range() };
        global_ctx.remove_exposed_provenance(range);
        Ok(())
    }

    /// Ensure that the allocation is invalidated without triggering UB for a use-after-free.
    /// This is specific to stack deallocation.
    pub fn dealloc_weak(ctx: &GlobalCtx, prov: Provenance, span: Span) -> UBResult<()> {
        if !prov.bor_tag.is_concrete() {
            return Ok(());
        }
        let alloc_info: AllocInfoPtr = unsafe { NonNull::new_unchecked(prov.alloc_info).into() };
        let mut guard = alloc_info.tree.lock();
        let Some(tree) = guard.as_mut() else { return Ok(()) };
        let range = AllocRange { start: Size::ZERO, size: alloc_info.size.get() };
        tree.dealloc(prov.bor_tag, range, &ctx.protected_tags(), alloc_info.alloc_id.get(), span)?;
        *guard = None;
        drop(guard);
        let range = unsafe { alloc_info.range() };
        ctx.remove_exposed_provenance(range);
        Ok(())
    }

    pub fn expose_tag(&self, global_ctx: &GlobalCtx) -> UBResult<()> {
        let tag = self.bor_tag;
        let range = unsafe { self.alloc_info.range() };

        // Ranges in the mapping must be non-empty, and a wildcard access can
        // never resolve to a zero-sized allocation anyway.
        if range.size > Size::ZERO {
            let mut exposed = global_ctx.exposed_provenance_mut();
            if let AccessType::Empty(pos) = exposed.access_type(range) {
                exposed.insert_at_pos(pos, range, self.alloc_info);
            }
        }

        let mut tree = self.tree();
        if tree.contains_tag(tag) {
            let protected = global_ctx.protected_tags().get_protector_kind(tag).is_some();
            tree.expose_tag(tag, protected);
        }
        Ok(())
    }

    pub fn expose(ctx: &GlobalCtx, prov: Provenance) {
        // Only concrete tags have valid `AllocInfo` to expose.
        if prov.bor_tag.is_concrete() {
            let _ =
                unsafe { BorrowTracker::for_alloc_inner(prov) }.and_then(|bt| bt.expose_tag(ctx));
        }
    }

    pub fn debug_take_snapshot(&self, ctx: &GlobalCtx) {
        let tree = self.tree();
        ctx.take_snapshot(self.alloc_info.alloc_id.get(), tree.clone());
    }

    pub fn debug_print_diff(&self, ctx: &GlobalCtx) {
        ctx.with_snapshot(self.alloc_info.alloc_id.get(), |old_tree: &LazyTree| {
            self.tree().print_tree_diff(old_tree, &ctx.protected_tags());
        });
    }

    pub fn debug_print_tree(&self, ctx: &GlobalCtx, show_unnamed: bool) {
        self.tree().print_tree(&ctx.protected_tags(), show_unnamed);
    }

    pub fn debug_tree_size(&self) -> usize {
        self.tree().node_count()
    }
}
