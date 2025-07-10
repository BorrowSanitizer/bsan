// Components in this library were ported from Miri and then modified by our team.
use core::ffi::c_void;
use core::ptr;

use bsan_shared::{AccessKind, Permission, ProtectorKind, RangeMap, RetagInfo, Size};
use spin::MutexGuard;
use tree::{AllocRange, Tree};

use crate::borrow_tracker::tree::{ChildParams, LocationState};
use crate::diagnostics::AccessCause;
use crate::errors::{BsanResult, ErrorInfo, UBInfo};
use crate::hooks::BsanAllocHooks;
use crate::span::Span;
use crate::{throw_ub, AllocId, AllocInfo, GlobalCtx, LocalCtx, Provenance};

pub mod tree;
pub mod unimap;

#[derive(Debug)]
pub struct BorrowTracker {
    prov: Provenance,
    range: AllocRange,
}

impl BorrowTracker {
    fn allocation_size(&self) -> Size {
        Size::from_bytes(unsafe { (*self.prov.alloc_info).size })
    }

    fn lock(&self) -> MutexGuard<'_, Option<Tree<BsanAllocHooks>>> {
        unsafe { (*self.prov.alloc_info).tree_lock.lock() }
    }

    /// # Safety
    /// Takes in provenance pointer that is checked via debug_asserts
    pub fn new(
        prov: Provenance,
        start: *mut c_void,
        access_size: Option<usize>,
    ) -> BsanResult<Option<Self>> {
        if prov.alloc_id == AllocId::invalid() {
            throw_ub!(UBInfo::InvalidProvenance)
        } else if prov.alloc_id == AllocId::wildcard() {
            Ok(None)
        } else {
            // Safety:
            // Our instrumentation pass guarantees that if a pointer's
            // provenance is non-null and not wildcard, then it will contain
            // valid allocation info pointer.
            debug_assert!(!prov.alloc_info.is_null());
            let root_alloc_id = unsafe { (*prov.alloc_info).alloc_id };

            if prov.alloc_id != root_alloc_id {
                throw_ub!(UBInfo::UseAfterFree(prov.alloc_id))
            }

            let (alloc_size, root_base_addr) =
                unsafe { ((*prov.alloc_info).size, (*prov.alloc_info).base_addr.base_addr) };

            let access_size = access_size.unwrap_or(alloc_size);
            let offset = start.addr().wrapping_sub(root_base_addr.addr());
            if start.addr() < root_base_addr.addr() || (offset + access_size > alloc_size) {
                throw_ub!(UBInfo::AccessOutOfBounds(prov.alloc_id, start, access_size))
            }

            let start = Size::from_bytes(offset);
            let size = Size::from_bytes(access_size);
            let range = AllocRange { start, size };

            Ok(Some(Self { prov, range }))
        }
    }

    pub fn retag(
        &self,
        global_ctx: &GlobalCtx,
        local_ctx: &mut LocalCtx,
        retag_info: RetagInfo,
    ) -> BsanResult<()> {
        // Tree is assumed to be initialized
        let mut lock = self.lock();
        let tree = unsafe { lock.as_mut().unwrap_unchecked() };

        #[cfg(debug_assertions)]
        if tree.is_allocation_of(self.prov.bor_tag) {
            crate::throw_internal_err!("This tag already exists in the tree!");
        }

        let parent_tag = self.prov.bor_tag;
        let new_tag = global_ctx.new_borrow_tag();

        if let Some(protect) = retag_info.protector_kind {
            // We register the protection in two different places.
            // This makes creating a protector slower, but checking whether a tag
            // is protected faster.
            local_ctx.add_protected_tag(self.prov.alloc_id, new_tag);
            global_ctx.add_protected_tag(new_tag, protect);
        }

        let mut perms_map = RangeMap::new_in(
            self.allocation_size(),
            LocationState::new_accessed(
                Permission::new_disabled(),
                bsan_shared::IdempotentForeignAccess::None,
            ),
            global_ctx.allocator(),
        );

        let base_offset = self.range.start;
        if let Some(access_kind) = retag_info.access_kind {
            for (perm_range, perm) in perms_map.iter_mut_all() {
                if perm.is_accessed() {
                    // Some reborrows incur a read access to the parent.
                    // Adjust range to be relative to allocation start
                    let range_in_alloc = AllocRange {
                        start: Size::from_bytes(perm_range.start) + self.range.start,
                        size: Size::from_bytes(perm_range.end - perm_range.start),
                    };

                    // Perform the access (update the Tree Borrows FSM)
                    tree.perform_access(
                        self.prov.bor_tag,
                        // TODO: Validate the Range
                        Some((range_in_alloc, access_kind, AccessCause::Explicit(access_kind))),
                        global_ctx,
                        self.prov.alloc_id,
                        // TODO: Replace with actual span
                        Span::new(),
                        // Passing in allocator explicitly to stay consistent with API
                        global_ctx.allocator(),
                    )?;
                }
            }
        }

        let protected = retag_info.protector_kind.is_some();
        let default_perm = retag_info.perm_kind;

        let child_params = ChildParams {
            base_offset,
            parent_tag,
            new_tag,
            perms_map,
            default_perm,
            protected,
            // TODO: Replace with actual span
            span: Span::new(),
        };

        tree.new_child(child_params);
        Ok(())
    }

    pub fn access(&self, global_ctx: &GlobalCtx, access_kind: AccessKind) -> BsanResult<()> {
        // Tree is initialized
        let mut lock = self.lock();
        let tree = unsafe { lock.as_mut().unwrap_unchecked() };
        // Perform the access (update the Tree Borrows FSM)
        tree.perform_access(
            self.prov.bor_tag,
            // TODO: Validate the Range
            Some((self.range, access_kind, AccessCause::Explicit(access_kind))),
            global_ctx,
            self.prov.alloc_id,
            // TODO: Replace with actual span
            Span::new(),
            // Passing in allocator explicitly to stay consistent with API
            global_ctx.allocator(),
        )
    }

    pub fn dealloc(&mut self, global_ctx: &GlobalCtx) -> BsanResult<()> {
        let mut lock = self.lock();
        let tree = unsafe { lock.as_mut().unwrap_unchecked() };

        tree.dealloc(
            self.prov.bor_tag,
            self.range,
            global_ctx,
            self.prov.alloc_id,
            // TODO: Replace with actual span
            Span::new(),
            global_ctx.allocator(),
        )?;

        unsafe { drop(ptr::replace(self.prov.alloc_info, AllocInfo::default())) }
        unsafe { global_ctx.deallocate_lock_location(self.prov.alloc_info) };
        Ok(())
    }
}
