// Components in this library were ported from Miri and then modified by our team.
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use spin::{Mutex, MutexGuard};

use crate::errors::{UBInfo, UBResult};
use crate::helpers::{AllocRange, Size};
use crate::sanitizer_common::Span;
use crate::tree_borrows::data_structures::{AccessType, DedupRangeMap};
use crate::tree_borrows::diagnostics::AccessCause;
use crate::tree_borrows::perms::{AccessKind, Permission};
use crate::tree_borrows::tree::LocationState;
use crate::tree_borrows::{AllocState, AllocStateImpl, IdempotentForeignAccess, NewPermission};
use crate::{AllocId, AllocInfo, BorTag, GlobalCtx, Provenance, RetagFlags, RetagInfo};

#[derive(Debug)]
pub struct BorrowTracker<'b> {
    alloc_id: AllocId,
    prov: Provenance,
    base_addr: Size,
    range: AllocRange,
    tree: &'b Mutex<Option<AllocStateImpl>>,
}

/// A guard over the `Tree` for an allocation.
struct TreeGuard<'b>(MutexGuard<'b, Option<AllocStateImpl>>);

impl Deref for TreeGuard<'_> {
    type Target = AllocStateImpl;
    fn deref(&self) -> &AllocStateImpl {
        self.0.as_ref().unwrap()
    }
}

impl DerefMut for TreeGuard<'_> {
    fn deref_mut(&mut self) -> &mut AllocStateImpl {
        self.0.as_mut().unwrap()
    }
}

impl<'b> BorrowTracker<'b> {
    fn tree(&self) -> TreeGuard<'_> {
        TreeGuard(self.tree.lock())
    }

    fn alloc_info(&self) -> NonNull<AllocInfo> {
        // SAFETY:
        // When we construct an instance of `BorrowTracker`, we validate
        // that its provenance value is nonnull.
        unsafe { NonNull::new_unchecked(self.prov.alloc_info) }
    }

    fn alloc_size(&self) -> Size {
        // SAFETY: see `alloc_info`; the pointer is non-null and valid for the
        // lifetime of this `BorrowTracker`.
        unsafe { (*self.prov.alloc_info).size }
    }

    unsafe fn for_alloc_inner(prov: Provenance) -> UBResult<Self> {
        // Safety:
        // Our instrumentation pass guarantees that if a pointer's
        // provenance is non-null and not omnivalid, then it will contain
        // valid allocation info pointer.
        // TODO: support wildcard provenance
        debug_assert!(!prov.alloc_info.is_null());
        let alloc_id = unsafe { (*prov.alloc_info).alloc_id };
        let base_addr = unsafe { (*prov.alloc_info).base_addr.base_addr };

        let tree = unsafe { &(*prov.alloc_info).tree_lock };
        if tree.lock().is_none() {
            return Err(UBInfo::UseAfterFree);
        }

        let size = unsafe { (*prov.alloc_info).size };
        let range = AllocRange { start: Size::ZERO, size };
        Ok(Self { alloc_id, prov, base_addr, range, tree })
    }

    pub fn for_alloc<T, F>(prov: Provenance, f: F) -> UBResult<T>
    where
        F: FnOnce(Self) -> UBResult<T>,
        T: Default,
    {
        if prov.bor_tag == BorTag::omnivalid() {
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
            // Safety:
            // Our instrumentation pass guarantees that if a pointer's
            // provenance is non-null and not omnivalid, then it will contain
            // valid allocation info pointer.
            // TODO: support wildcard provenance
            debug_assert!(!prov.alloc_info.is_null());

            let alloc_id = unsafe { (*prov.alloc_info).alloc_id };

            let (alloc_size, base_addr) =
                unsafe { ((*prov.alloc_info).size, (*prov.alloc_info).base_addr.base_addr) };

            let access_size = access_size.unwrap_or(alloc_size);

            let tree = unsafe { &(*prov.alloc_info).tree_lock };
            // The allocation has been freed (`None`), or the pointer's tag is no
            // longer live in the tree (e.g. it referred to a now-reallocated
            // allocation): either way, accessing it is a use-after-free. A
            // zero-sized access is always permitted.
            let is_live = matches!(
                tree.lock().as_ref(),
                Some(tree) if tree.contains_tag(prov.bor_tag)
            );
            if !is_live {
                return if access_size != Size::ZERO {
                    Err(UBInfo::UseAfterFree)
                } else {
                    Ok(T::default())
                };
            }

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
            f(Self { alloc_id, prov, base_addr, range, tree })
        }
    }

    pub fn retag(
        &self,
        global_ctx: &GlobalCtx,
        retag_info: RetagInfo<'_>,
        span: Span,
    ) -> UBResult<BorTag> {
        let alloc_id = self.alloc_id;
        let parent_tag = self.prov.bor_tag;
        let new_tag = BorTag::default();
        if !self.tree().contains_tag(self.prov.bor_tag) {
            return Err(UBInfo::UseAfterFree);
        }
        let new_perm: NewPermission = NewPermission::new(retag_info);

        let protected = new_perm.protector.is_some();
        if let Some(protector) = new_perm.protector {
            // We register the protection in two different places.
            // This makes creating a protector slower, but checking whether a tag
            // is protected faster.
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

        Ok(new_tag)
    }

    pub fn protector_end(&self, global_ctx: &GlobalCtx, span: Span) -> UBResult<()> {
        let (bor_tag, alloc_id) = (self.prov.bor_tag, self.alloc_id);
        self.tree().perform_protector_end_access(
            bor_tag,
            &global_ctx.protected_tags(),
            alloc_id,
            span,
        )
    }

    pub fn access(
        &self,
        global_ctx: &GlobalCtx,
        access_kind: AccessKind,
        span: Span,
    ) -> UBResult<()> {
        let (range, bor_tag, alloc_id) = (self.range, self.prov.bor_tag, self.alloc_id);
        self.tree().perform_access(
            bor_tag,
            range,
            access_kind,
            AccessCause::Explicit(access_kind),
            &global_ctx.protected_tags(),
            alloc_id,
            span,
        )
    }

    pub fn dealloc(&self, global_ctx: &GlobalCtx, span: Span) -> UBResult<()> {
        let (range, bor_tag, alloc_id) = (self.range, self.prov.bor_tag, self.alloc_id);

        let mut guard = self.tree.lock();
        if let Some(tree) = guard.as_mut() {
            tree.dealloc(bor_tag, range, &global_ctx.protected_tags(), alloc_id, span)?;
        }

        *guard = None;
        Ok(())
    }

    /// Ensure that the allocation is invalidated without triggering UB for a use-after-free.
    /// This is specific to stack deallocation.
    pub fn dealloc_weak(ctx: &GlobalCtx, prov: Provenance, span: Span) -> UBResult<()> {
        if !prov.bor_tag.is_concrete() {
            return Ok(());
        }
        // SAFETY: a concrete provenance is guaranteed by the instrumentation
        // pass to carry a non-null, valid `alloc_info` pointer.
        debug_assert!(!prov.alloc_info.is_null());
        let info = unsafe { &*prov.alloc_info };
        let mut guard = info.tree_lock.lock();
        let Some(tree) = guard.as_mut() else { return Ok(()) };
        let range = AllocRange { start: Size::ZERO, size: info.size };
        tree.dealloc(prov.bor_tag, range, &ctx.protected_tags(), info.alloc_id, span)?;
        *guard = None;
        Ok(())
    }

    pub fn expose_tag(&self, global_ctx: &GlobalCtx) -> UBResult<()> {
        let tag = self.prov.bor_tag;

        // First, we need to mark that the allocation has been exposed in our global mapping.
        // We do this using a range object map covering the span of the entire address space.
        let range = AllocRange { start: self.base_addr, size: self.alloc_size() };

        let mut exposed = global_ctx.exposed_provenance_mut();
        if let AccessType::Empty(pos) = exposed.access_type(range) {
            exposed.insert_at_pos(pos, range, self.alloc_info());
        }
        drop(exposed);

        // Then, within the tree associated with this allocation, we need to indicate that
        // this particular tag has been exposed.
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
        ctx.take_snapshot(self.alloc_id, tree.clone());
    }

    pub fn debug_print_diff(&self, ctx: &GlobalCtx) {
        ctx.with_snapshot(self.alloc_id, |old_tree: &AllocStateImpl| {
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
