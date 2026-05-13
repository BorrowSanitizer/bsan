// Components in this library were ported from Miri and then modified by our team.
use core::ffi::c_void;

use spin::MutexGuard;

use crate::errors::{UBInfo, UBResult};
use crate::helpers::{AllocRange, Size};
use crate::sanitizer_common::Span;
use crate::tree_borrows::data_structures::DedupRangeMap;
use crate::tree_borrows::diagnostics::AccessCause;
use crate::tree_borrows::perms::AccessKind;
use crate::tree_borrows::tree::LocationState;
use crate::tree_borrows::NewPermission;
use crate::{AllocId, BorTag, GlobalCtx, Provenance, RetagInfo, Tree};

#[derive(Debug)]
pub struct BorrowTracker<'b> {
    alloc_id: AllocId,
    prov: Provenance,
    range: AllocRange,
    tree: MutexGuard<'b, Tree>,
}

impl<'b> BorrowTracker<'b> {
    fn tree_mut(&mut self) -> &mut Tree {
        &mut self.tree
    }

    fn tree(&self) -> &Tree {
        &self.tree
    }

    pub fn for_alloc<T, F>(prov: Provenance, f: F) -> UBResult<Option<T>>
    where
        F: FnOnce(Self) -> UBResult<T>,
    {
        if prov.bor_tag == BorTag::wildcard() {
            Ok(None)
        } else if prov.bor_tag == BorTag::invalid() {
            Err(UBInfo::UseAfterFree)
        } else {
            // Safety:
            // Our instrumentation pass guarantees that if a pointer's
            // provenance is non-null and not wildcard, then it will contain
            // valid allocation info pointer.
            debug_assert!(!prov.alloc_info.is_null());
            let alloc_id = unsafe { (*prov.alloc_info).alloc_id };

            let tree = if let Some(tree_lock) = unsafe { (*prov.alloc_info).tree_lock.as_ref() } {
                tree_lock
            } else {
                return Err(UBInfo::UseAfterFree);
            };

            let size = Size::from_bytes(unsafe { (*prov.alloc_info).size });
            let range = AllocRange { start: Size::ZERO, size };
            let tree = tree.lock();
            f(Self { alloc_id, prov, range, tree }).map(|v| Some(v))
        }
    }

    /// # Safety
    /// Takes in provenance pointer that is checked via debug_asserts
    pub fn for_access<T, F>(
        prov: Provenance,
        start: *mut c_void,
        access_size: Option<usize>,
        f: F,
    ) -> UBResult<Option<T>>
    where
        F: FnOnce(Self) -> UBResult<T>,
    {
        if prov.bor_tag == BorTag::wildcard() {
            Ok(None)
        } else if prov.bor_tag == BorTag::invalid() {
            if access_size == Some(0) {
                Ok(None)
            } else {
                Err(UBInfo::UseAfterFree)
            }
        } else {
            // Safety:
            // Our instrumentation pass guarantees that if a pointer's
            // provenance is non-null and not wildcard, then it will contain
            // valid allocation info pointer.
            debug_assert!(!prov.alloc_info.is_null());

            let alloc_id = unsafe { (*prov.alloc_info).alloc_id };

            let (alloc_size, base_addr) =
                unsafe { ((*prov.alloc_info).size, (*prov.alloc_info).base_addr.addr) };

            let access_size = access_size.unwrap_or(alloc_size);
            let tree = if let Some(tree_lock) = unsafe { (*prov.alloc_info).tree_lock.as_ref() } {
                tree_lock
            } else {
                return if access_size != 0 { Err(UBInfo::UseAfterFree) } else { Ok(None) };
            };

            let tree = tree.lock();
            if !tree.tag_mapping.contains_key(&prov.bor_tag) {
                return if access_size != 0 { Err(UBInfo::UseAfterFree) } else { Ok(None) };
            }

            let offset = start.addr().wrapping_sub(base_addr);
            if start.addr() < base_addr || (offset + access_size > alloc_size) {
                return if access_size != 0 {
                    Err(UBInfo::AccessOutOfBounds { alloc_id, access_size, alloc_size, offset })
                } else {
                    Ok(None)
                };
            }

            let start = Size::from_bytes(offset);
            let size = Size::from_bytes(access_size);
            let range = AllocRange { start, size };

            f(Self { alloc_id, prov, range, tree }).map(|r| Some(r))
        }
    }

    pub fn retag(
        ctx: &GlobalCtx,
        prov: Provenance,
        start: *mut c_void,
        retag_info: RetagInfo<'_>,
        span: Span,
    ) -> UBResult<BorTag> {
        Self::for_access(prov, start, Some(retag_info.size), |mut bt| {
            bt.retag_inner(ctx, retag_info, span)
        })
        .map(|opt| opt.unwrap_or(prov.bor_tag))
    }

    #[inline]
    pub fn retag_inner(
        &mut self,
        global_ctx: &GlobalCtx,
        retag_info: RetagInfo<'_>,
        span: Span,
    ) -> UBResult<BorTag> {
        let alloc_id = self.alloc_id;
        let parent_tag = self.prov.bor_tag;
        let new_tag = BorTag::default();

        if !self.tree().tag_mapping.contains_key(&self.prov.bor_tag) {
            return Err(UBInfo::UseAfterFree);
        }
        let perm: NewPermission = NewPermission::new(retag_info);

        let protected = perm.protector.is_some();
        if let Some(protector) = perm.protector {
            // We register the protection in two different places.
            // This makes creating a protector slower, but checking whether a tag
            // is protected faster.
            global_ctx.protected_tags_mut().add_protector(new_tag, protector);
        }

        // Compute initial "inside" permissions.
        let loc_state = |frozen: bool| -> LocationState {
            let (perm, access) = if frozen {
                (perm.freeze_perm, perm.freeze_access)
            } else {
                (perm.nonfreeze_perm, perm.nonfreeze_access.is_some())
            };
            let sifa = perm.strongest_idempotent_foreign_access(protected);
            if access {
                LocationState::new_accessed(perm, sifa)
            } else {
                LocationState::new_non_accessed(perm, sifa)
            }
        };

        let initial_state = loc_state(perm.ty_is_freeze);
        let mut inside_perms = DedupRangeMap::new(Size::from_bytes(retag_info.size), initial_state);

        if let Some(im_layout) = retag_info.im_layout {
            for [start, size] in im_layout {
                inside_perms.iter_mut(*start, *size).for_each(|(_, loc)| *loc = loc_state(false));
            }
        }

        let base_offset = self.range.start;
        for (perm_range, perm) in inside_perms.iter_all() {
            if perm.accessed() {
                // Some reborrows incur a read access to the parent.
                // Adjust range to be relative to allocation start
                let range_in_alloc = AllocRange {
                    start: Size::from_bytes(perm_range.start) + base_offset,
                    size: Size::from_bytes(perm_range.end - perm_range.start),
                };

                // Perform the access (update the Tree Borrows FSM)
                self.tree_mut().perform_access(
                    parent_tag,
                    range_in_alloc,
                    AccessKind::Read,
                    AccessCause::Reborrow,
                    &global_ctx.protected_tags(),
                    alloc_id,
                    span,
                )?;
            }
        }

        // base offset should be the offset, from zero, where the retag is taking place within the allocation.
        let _ = self.tree_mut().new_child(
            base_offset,
            parent_tag,
            new_tag,
            inside_perms,
            perm.default_perm(),
            protected,
            span,
        );

        Ok(new_tag)
    }

    pub fn protector_end(&mut self, global_ctx: &GlobalCtx, span: Span) -> UBResult<()> {
        let (bor_tag, alloc_id) = (self.prov.bor_tag, self.alloc_id);
        self.tree_mut().perform_protector_end_access(
            bor_tag,
            &global_ctx.protected_tags(),
            alloc_id,
            span,
        )
    }

    pub fn access(
        &mut self,
        global_ctx: &GlobalCtx,
        access_kind: AccessKind,
        span: Span,
    ) -> UBResult<()> {
        let (range, bor_tag, alloc_id) = (self.range, self.prov.bor_tag, self.alloc_id);
        self.tree_mut().perform_access(
            bor_tag,
            range,
            access_kind,
            AccessCause::Explicit(access_kind),
            &global_ctx.protected_tags(),
            alloc_id,
            span,
        )
    }

    pub fn dealloc(&mut self, global_ctx: &GlobalCtx, span: Span) -> UBResult<()> {
        let (range, bor_tag, alloc_id) = (self.range, self.prov.bor_tag, self.alloc_id);
        let tree = self.tree_mut();
        tree.dealloc(bor_tag, range, &global_ctx.protected_tags(), alloc_id, span)?;
        let info = unsafe { &mut *self.prov.alloc_info };
        drop(info.tree_lock.take());
        Ok(())
    }

    pub fn expose_tag(&mut self, global_ctx: &GlobalCtx) -> UBResult<()> {
        let tag = self.prov.bor_tag;
        let protected = global_ctx.protected_tags().get_protector_kind(tag).is_some();
        self.tree_mut().expose_tag(tag, protected);
        Ok(())
    }

    pub fn expose(ctx: &GlobalCtx, prov: Provenance) -> UBResult<()> {
        Self::for_alloc(prov, |mut bt| bt.expose_tag(ctx)).map(|_| ())
    }

    pub fn debug_take_snapshot(&self, ctx: &GlobalCtx) {
        let tree = self.tree();
        ctx.take_snapshot(self.alloc_id, tree.clone());
    }

    pub fn debug_print_diff(&self, ctx: &GlobalCtx) {
        ctx.with_snapshot(self.alloc_id, |old_tree| {
            self.tree().print_tree_diff(old_tree, &ctx.protected_tags());
        });
    }

    pub fn debug_print_tree(&self, ctx: &GlobalCtx, show_unnamed: bool) {
        self.tree().print_tree(&ctx.protected_tags(), show_unnamed);
    }

    pub fn debug_tree_size(&self) -> usize {
        self.tree().tag_mapping.len()
    }
}
