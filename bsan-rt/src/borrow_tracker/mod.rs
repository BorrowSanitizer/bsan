// Components in this library were ported from Miri and then modified by our team.
use core::ffi::c_void;

use bsan_shared::{AccessKind, ProtectorKind, RangeMap, RetagInfo, Size};
use spin::MutexGuard;
use tree::{AllocRange, Tree};

use crate::borrow_tracker::tree::{ChildParams, LocationState};
use crate::diagnostics::AccessCause;
use crate::errors::{BorsanResult, ErrorInfo, UBInfo};
use crate::memory::hooks::BsanAllocHooks;
use crate::span::Span;
use crate::{AllocId, BorTag, GlobalCtx, Provenance};

pub mod tree;
pub mod unimap;

#[derive(Debug)]
pub struct BorrowTracker<'b> {
    prov: Provenance,
    range: AllocRange,
    tree: MutexGuard<'b, Option<Tree<BsanAllocHooks>>>,
}

impl<'b> BorrowTracker<'b> {
    fn tree_mut(&mut self) -> &mut Tree<BsanAllocHooks> {
        self.tree.as_mut().unwrap()
    }

    pub fn for_alloc<T, F>(prov: Provenance, f: F) -> BorsanResult<Option<T>>
    where
        F: FnOnce(Self) -> BorsanResult<T>,
    {
        if prov.alloc_id == AllocId::wildcard() {
            Ok(None)
        } else if prov.alloc_id == AllocId::invalid() {
            Err(ErrorInfo::UndefinedBehavior(UBInfo::UseAfterFree(prov.alloc_id)))
        } else {
            // Safety:
            // Our instrumentation pass guarantees that if a pointer's
            // provenance is non-null and not wildcard, then it will contain
            // valid allocation info pointer.
            debug_assert!(!prov.alloc_info.is_null());
            let root_alloc_id = unsafe { (*prov.alloc_info).alloc_id };
            if prov.alloc_id != root_alloc_id {
                return Err(ErrorInfo::UndefinedBehavior(UBInfo::UseAfterFree(prov.alloc_id)));
            }
            let size = Size::from_bytes(unsafe { (*prov.alloc_info).size });
            let range = AllocRange { start: Size::ZERO, size };
            let tree = unsafe { (*prov.alloc_info).tree_lock.lock() };
            f(Self { prov, range, tree }).map(|v| Some(v))
        }
    }

    /// # Safety
    /// Takes in provenance pointer that is checked via debug_asserts
    pub fn for_access<T, F>(
        prov: Provenance,
        start: *mut c_void,
        access_size: Option<usize>,
        f: F,
    ) -> BorsanResult<Option<T>>
    where
        F: FnOnce(Self) -> BorsanResult<T>,
    {
        if prov.alloc_id == AllocId::wildcard() {
            Ok(None)
        } else if prov.alloc_id == AllocId::invalid() {
            if let Some(size) = access_size
                && size > 0
            {
                Err(ErrorInfo::UndefinedBehavior(UBInfo::UseAfterFree(prov.alloc_id)))
            } else {
                Ok(None)
            }
        } else {
            // Safety:
            // Our instrumentation pass guarantees that if a pointer's
            // provenance is non-null and not wildcard, then it will contain
            // valid allocation info pointer.
            debug_assert!(!prov.alloc_info.is_null());
            let root_alloc_id = unsafe { (*prov.alloc_info).alloc_id };
            let (alloc_size, base_addr) =
                unsafe { ((*prov.alloc_info).size, (*prov.alloc_info).base_addr.base_addr) };
            let access_size = access_size.unwrap_or(alloc_size);
            if prov.alloc_id != root_alloc_id {
                return if access_size != 0 {
                    Err(ErrorInfo::UndefinedBehavior(UBInfo::UseAfterFree(prov.alloc_id)))
                } else {
                    Ok(None)
                };
            }
            let relative_offset = start.addr().wrapping_sub(base_addr.addr());
            if start.addr() < base_addr.addr() || (relative_offset + access_size > alloc_size) {
                return if access_size != 0 {
                    Err(ErrorInfo::UndefinedBehavior(UBInfo::AccessOutOfBounds(
                        prov,
                        access_size,
                        alloc_size,
                    )))
                } else {
                    Ok(None)
                };
            }
            let start = Size::from_bytes(relative_offset);
            let size = Size::from_bytes(access_size);
            let range = AllocRange { start, size };
            let tree = unsafe { (*prov.alloc_info).tree_lock.lock() };
            f(Self { prov, range, tree }).map(|r| Some(r))
        }
    }

    pub fn retag(
        global_ctx: &GlobalCtx,
        prov: Provenance,
        start: *mut c_void,
        access_size: Option<usize>,
        retag_info: RetagInfo<'_>,
        span: Span,
    ) -> BorsanResult<BorTag> {
        let tag = Self::for_access(prov, start, access_size, |mut bt| {
            bt.retag_inner(global_ctx, retag_info, span)
        })?
        .unwrap_or_else(|| prov.bor_tag);
        Ok(tag)
    }
    pub fn retag_inner(
        &mut self,
        global_ctx: &GlobalCtx,
        retag_info: RetagInfo<'_>,
        span: Span,
    ) -> BorsanResult<BorTag> {
        let alloc_id = self.prov.alloc_id;
        let parent_tag = self.prov.bor_tag;
        let new_tag = BorTag::default();

        let protected = retag_info.perm.protector.is_some();
        if let Some(protector) = retag_info.perm.protector {
            // We register the protection in two different places.
            // This makes creating a protector slower, but checking whether a tag
            // is protected faster.
            global_ctx.add_protected_tag(new_tag, protector);
        }

        // Compute initial "inside" permissions.
        let loc_state = |frozen: bool| -> LocationState {
            let (perm, access) = if frozen {
                (retag_info.perm.freeze_perm, retag_info.perm.freeze_access)
            } else {
                (retag_info.perm.nonfreeze_perm, retag_info.perm.nonfreeze_access.is_some())
            };
            let sifa = perm.strongest_idempotent_foreign_access(protected);
            if access {
                LocationState::new_accessed(perm, sifa)
            } else {
                LocationState::new_non_accessed(perm, sifa)
            }
        };

        let initial_state = loc_state(retag_info.perm.ty_is_freeze);
        let mut inside_perms = RangeMap::new_in(
            Size::from_bytes(retag_info.size),
            initial_state,
            global_ctx.allocator(),
        );

        if let Some(im_layout) = retag_info.im_layout {
            for [start, size] in im_layout {
                inside_perms.iter_mut(*start, *size).for_each(|(_, loc)| *loc = loc_state(false));
            }
        }

        let base_offset = self.range.start;
        for (perm_range, perm) in inside_perms.iter_all() {
            if perm.is_accessed() {
                // Some reborrows incur a read access to the parent.
                // Adjust range to be relative to allocation start
                let range_in_alloc = AllocRange {
                    start: Size::from_bytes(perm_range.start) + base_offset,
                    size: Size::from_bytes(perm_range.end - perm_range.start),
                };

                // Perform the access (update the Tree Borrows FSM)
                self.tree_mut().perform_access(
                    parent_tag,
                    Some((range_in_alloc, AccessKind::Read, AccessCause::Reborrow)),
                    global_ctx,
                    alloc_id,
                    span,
                    global_ctx.allocator(),
                )?;
            }
        }

        // base offset should be the offset, from zero, where the retag is taking place within the allocation.
        let child_params = ChildParams {
            base_offset,
            parent_tag,
            new_tag,
            inside_perms,
            default_perm: retag_info.perm.default_perm(),
            protected,
            span,
        };

        self.tree_mut().new_child(child_params);

        Ok(new_tag)
    }

    pub fn protector_end(&mut self, global_ctx: &GlobalCtx, span: Span) -> BorsanResult<()> {
        let (bor_tag, alloc_id) = (self.prov.bor_tag, self.prov.alloc_id);
        self.tree_mut().perform_access(
            bor_tag,
            None,
            global_ctx,
            alloc_id,
            span,
            global_ctx.allocator(),
        )?;
        Ok(())
    }

    pub fn access(
        &mut self,
        global_ctx: &GlobalCtx,
        access_kind: AccessKind,
        span: Span,
    ) -> BorsanResult<()> {
        let (range, bor_tag, alloc_id) = (self.range, self.prov.bor_tag, self.prov.alloc_id);
        self.tree_mut().perform_access(
            bor_tag,
            Some((range, access_kind, AccessCause::Explicit(access_kind))),
            global_ctx,
            alloc_id,
            span,
            global_ctx.allocator(),
        )?;
        Ok(())
    }

    pub fn dealloc(&mut self, global_ctx: &GlobalCtx, span: Span) -> BorsanResult<()> {
        let prov = self.prov;
        let range = self.range;
        let mut tree = self.tree.take().unwrap();
        tree.dealloc(prov.bor_tag, range, global_ctx, prov.alloc_id, span, global_ctx.allocator())?;
        let info = unsafe { &mut *self.prov.alloc_info };
        info.alloc_id = AllocId::invalid();
        Ok(())
    }
}
