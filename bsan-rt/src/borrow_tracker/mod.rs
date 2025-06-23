use core::alloc::Allocator;
use core::cell::LazyCell;
use core::ffi::c_void;
use core::mem;

use bsan_shared::{
    AccessKind, AccessRelatedness, Permission, ProtectorKind, RangeMap, RetagInfo, Size,
};
use parking_lot::Mutex;
use spin::Once;
use tree::{AllocRange, Tree};

use crate::borrow_tracker::errors::{BsanTreeError, BtOp, BtResult, TreeError};
use crate::borrow_tracker::tree::{ChildParams, LocationState};
use crate::diagnostics::AccessCause;
use crate::span::Span;
use crate::{AllocInfo, BorTag, BsanAllocHooks, GlobalCtx, Provenance};

pub mod errors;
#[cfg_attr(not(test), no_std)]
pub mod tree;
pub mod unimap;

// TODO: Create struct for this wrapper functionality

#[derive(Debug)]
pub struct BorrowTracker<'a> {
    prov: &'a Provenance,
    ctx: &'a GlobalCtx,
    allocator: BsanAllocHooks,
    alloc_info: &'a mut AllocInfo,
    tree: &'a mut Tree<BsanAllocHooks>,
}

impl<'a> BorrowTracker<'a> {
    pub unsafe fn new(
        prov: *const Provenance,
        ctx: &'a GlobalCtx,
        object_address: *const c_void,
    ) -> BtResult<Self> {
        // Get global allocator
        let allocator = ctx.allocator();

        // TODO: Validate provenance and return a "safe" reference
        debug_assert!(unsafe { prov.as_ref().is_some() });

        // Initialize `Tree` if first retag

        // We assert that the tree ptr exists in the alloc metadata (and that the alloc metadata exists)
        debug_assert!(unsafe { !((*prov).alloc_info).is_null() });

        let alloc_info_ptr = AllocInfo::get_raw(prov);

        let mut alloc_info = unsafe { &mut *(alloc_info_ptr as *mut AllocInfo) };

        let prov = unsafe { &*prov };

        if prov.alloc_id != alloc_info.alloc_id {
            return Err(errors::BorrowTrackerError::UseAfterFree(BtOp {
                op: errors::BtOpType::Unknown,
                // TODO: Pass in actual span/backtrace
                span: Some(Span::new()),
                reason: Some(format!(
                    "Allocation IDs don't match. Provenance AllocID: {:?}\nAllocInfo AllocID: {:?}",
                    prov.alloc_id, alloc_info.alloc_id
                )),
            }));
        }

        let base_offset = alloc_info.base_offset(object_address as usize);

        // Check for out of bounds accessess
        let lower_bound = alloc_info.base_addr() as usize;
        let upper_bound = alloc_info.base_addr() as usize + alloc_info.size;
        // TODO: Checkout lib functions to compare pointers instead of using usize
        if (object_address as usize) < lower_bound || (object_address as usize) >= upper_bound {
            // TODO: Add proper error handling and bailing
            // Access out-of-bounds error
            return Err(errors::BorrowTrackerError::OutOfBounds(BtOp {
                op: errors::BtOpType::Unknown,
                // TODO: Pass in actual span/backtrace
                span: Some(Span::new()),
                reason: Some(
                    format!(
                        "Object address is outside of the allocation range.\nObject Address: {:?}\nLower Bound: {:?}\nUpper Bound: {:?}",
                        object_address,
                        lower_bound,
                        upper_bound
                    )
                )
            }));
        }

        let mut tree_lock = alloc_info.tree_lock.lock();

        // Cast the Tree void ptr into `Tree` by locking the Tree
        let tree_ptr = unsafe { &raw mut tree_lock as *mut Tree<BsanAllocHooks> };

        // Dropping the tree lock early as we already have our tree_ptr
        // TODO: Validate that this drop does not lose us access to the tree pointer
        core::mem::drop(tree_lock);

        Ok(Self { prov, ctx, allocator, alloc_info, tree: unsafe { &mut *tree_ptr } })
    }

    pub fn retag(&mut self, retag_info: &RetagInfo) -> BtResult<()> {
        // TODO: Potentially also update prov.alloc_info?
        #[cfg(debug)]
        if self.tree.is_allocation_of(self.prov.bor_tag) {
            use crate::borrow_tracker::errors::BorrowTrackerError;

            return Err(BorrowTrackerError::ErroneousRetag(BtOp {
                op: errors::BtOpType::Retag,
                // TODO: Replace with actual span/retag
                span: Some(Span::new()),
                reason: Some(format!("Tag exists in Tree indicating an erroneus retag")),
            }));
        }

        // TODO: Pass this in
        let mut perms_map = RangeMap::new_in(
            Size::from_bytes(self.alloc_info.size),
            LocationState::new_accessed(
                Permission::new_disabled(),
                bsan_shared::IdempotentForeignAccess::None,
            ),
            self.allocator,
        );

        for (perm_range, perm) in perms_map.iter_mut_all() {
            if perm.is_accessed() {
                // Some reborrows incur a read access to the parent.
                // Adjust range to be relative to allocation start
                let range_in_alloc = AllocRange {
                    start: Size::from_bytes(perm_range.start)
                        + self.alloc_info.base_offset(todo!("object address")),
                    size: Size::from_bytes(perm_range.end - perm_range.start),
                };

                self.access(AccessKind::Read, range_in_alloc).unwrap()
            }
        }

        let child_params: ChildParams = ChildParams {
            base_offset: self.alloc_info.base_offset(todo!("object address")),
            parent_tag: self.prov.bor_tag,
            new_tag: self.ctx.new_bor_tag(),
            initial_perms: perms_map,
            default_perm: todo!("Implement default perm"),
            protected: todo!("Implement protected"),
            span: Span::new(),
        };

        self.tree.new_child(child_params)?;

        Ok(())
    }

    pub fn access(&mut self, access_kind: AccessKind, alloc_range: AllocRange) -> BtResult<()> {
        // Perform the access (update the Tree Borrows FSM)
        // Uses a dummy span
        self.tree.perform_access(
            self.prov.bor_tag,
            // TODO: Validate the Range
            Some((alloc_range, access_kind, AccessCause::Explicit(access_kind))),
            &self.ctx,
            self.prov.alloc_id,
            Span::new(),
            // Passing in allocator explicitly to stay consistent with API
            self.allocator,
        )?;

        Ok(())
    }

    pub fn dealloc(&mut self) -> BtResult<()> {
        let lock_addr_id = self.prov.alloc_id.get();
        let metadata_id = self.alloc_info.alloc_id.get();

        // println!("Alloc Info: {:?}", self.prov.alloc_info);

        if lock_addr_id != metadata_id {
            return Err(errors::BorrowTrackerError::UseAfterFree(BtOp {
                op: errors::BtOpType::Dealloc,
                span: Some(Span::new()),
                reason: Some(
                    format!(
                        "Allocation ID in pointer metadata does not match the one in the lock address.\nLock address ID: {:?}\nPointer metadata ID: {:?}",
                        lock_addr_id,
                        metadata_id
                    )),
            }));
        }

        // TODO: Handle the result properly
        // and lock the tree
        self.tree.dealloc(
            self.prov.bor_tag,
            AllocRange {
                start: Size::from_bytes(self.alloc_info.base_addr() as usize),
                size: Size::from_bytes(self.alloc_info.size),
            },
            self.ctx,
            self.prov.alloc_id,
            Span::new(),
            self.allocator,
        )?;

        self.alloc_info.dealloc(self.ctx);

        Ok(())
    }
}
