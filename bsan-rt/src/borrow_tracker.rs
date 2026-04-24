// Components in this library were ported from Miri and then modified by our team.
use core::ffi::c_void;

use spin::MutexGuard;

use crate::errors::{UBInfo, UBResult};
use crate::helpers::{AllocRange, Size};
use crate::sanitizer_common::Span;
use crate::tree_borrows::{AccessKind, Tree};
use crate::{AllocId, BorTag, GlobalCtx, Provenance, RetagInfo};

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

            let tree = tree.lock();
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
        todo!()
    }

    pub fn protector_end(&mut self, global_ctx: &GlobalCtx, span: Span) -> UBResult<()> {
        todo!()
    }

    pub fn access(
        &mut self,
        global_ctx: &GlobalCtx,
        access_kind: AccessKind,
        span: Span,
    ) -> UBResult<()> {
        todo!()
    }

    pub fn dealloc(&mut self, global_ctx: &GlobalCtx, span: Span) -> UBResult<()> {
        todo!()
    }

    pub fn debug_take_snapshot(&self, ctx: &GlobalCtx) {
        todo!()
    }

    pub fn debug_print_diff(&self, ctx: &GlobalCtx) {
        todo!()
    }

    pub fn debug_print_tree(&self, ctx: &GlobalCtx, show_unnamed: bool) {
        todo!()
    }

    pub fn debug_tree_size(&self) -> usize {
        todo!()
    }
}
