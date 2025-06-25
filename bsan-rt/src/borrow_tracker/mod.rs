use core::alloc::Allocator;
use core::cell::LazyCell;
use core::ffi::c_void;
use core::mem;

use bsan_shared::{
    AccessKind, AccessRelatedness, Permission, ProtectorKind, RangeMap, RetagInfo, Size,
};
use parking_lot::{Mutex, MutexGuard};
use spin::Once;
use tree::{AllocRange, Tree};

use crate::borrow_tracker::errors::{BsanTreeError, BtOp, BtResult, TreeError};
use crate::borrow_tracker::tree::{ChildParams, LocationState};
use crate::diagnostics::AccessCause;
use crate::hooks::BsanAllocHooks;
use crate::span::Span;
use crate::{AllocId, AllocInfo, BorTag, FreeListAddrUnion, GlobalCtx, Provenance};

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
    // We treat AllocInfo as mutable as it is vulnerable to data races.
    // Data races are not undefined behavior on our end, but may be undefined
    // if the compiler optimizes an immutable borrow
    alloc_info: *mut AllocInfo,
    tree_lock: &'a Mutex<Once<Tree<BsanAllocHooks>>>,
}

impl<'a> BorrowTracker<'a> {
    // # SAFETY
    // Takes in provenance pointer that is checked via debug_asserts
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

        let prov = unsafe { &*prov };

        if prov.alloc_id != unsafe { (*alloc_info_ptr).alloc_id } {
            return Err(errors::BorrowTrackerError::UseAfterFree(BtOp {
                op: errors::BtOpType::Unknown,
                // TODO: Pass in actual span/backtrace
                span: Some(Span::new()),
                reason: Some(format!(
                    "Allocation IDs don't match. Provenance AllocID: {:?}\nAllocInfo AllocID: {:?}",
                    prov.alloc_id,
                    unsafe { (*alloc_info_ptr).alloc_id }
                )),
            }));
        }

        let base_offset = unsafe { (*alloc_info_ptr).base_offset(object_address as usize) };

        // Check for out of bounds accessess
        let lower_bound = unsafe { (*alloc_info_ptr).base_addr() as usize };
        let upper_bound =
            unsafe { (*alloc_info_ptr).base_addr() as usize + (*alloc_info_ptr).size };
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

        // Cast the Tree void ptr into `Tree` by locking the Tree

        Ok(Self {
            prov,
            ctx,
            allocator,
            tree_lock: unsafe { &(*alloc_info_ptr).tree_lock },
            alloc_info: alloc_info_ptr,
        })
    }

    pub fn retag(&self, retag_info: &RetagInfo) -> BtResult<()> {
        // Tree is initialized
        let lock = self.tree_lock.lock();
        let tree = lock.get().unwrap();

        #[cfg(debug)]
        if tree.is_allocation_of(self.prov.bor_tag) {
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
            Size::from_bytes(unsafe { (*self.alloc_info).size }),
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
                let range_in_alloc = unsafe {
                    AllocRange {
                        start: Size::from_bytes(perm_range.start)
                            + (*self.alloc_info).base_offset(todo!("object address")),
                        size: Size::from_bytes(perm_range.end - perm_range.start),
                    }
                };

                self.access(AccessKind::Read, range_in_alloc).unwrap()
            }
        }

        let child_params: ChildParams = ChildParams {
            base_offset: unsafe { (*self.alloc_info).base_offset(todo!("object address")) },
            parent_tag: self.prov.bor_tag,
            new_tag: self.ctx.new_bor_tag(),
            initial_perms: perms_map,
            default_perm: todo!("Implement default perm"),
            protected: todo!("Implement protected"),
            span: Span::new(),
        };

        tree.new_child(child_params)?;

        Ok(())
    }

    pub fn access(&self, access_kind: AccessKind, alloc_range: AllocRange) -> BtResult<()> {
        // Tree is initialized
        let mut lock = self.tree_lock.lock();
        let mut tree = lock.get_mut().unwrap();
        // Perform the access (update the Tree Borrows FSM)
        // Uses a dummy span
        tree.perform_access(
            self.prov.bor_tag,
            // TODO: Validate the Range
            Some((alloc_range, access_kind, AccessCause::Explicit(access_kind))),
            self.ctx,
            self.prov.alloc_id,
            Span::new(),
            // Passing in allocator explicitly to stay consistent with API
            self.allocator,
        )?;

        Ok(())
    }

    pub fn dealloc(&mut self) -> BtResult<()> {
        // Tree is initialized
        let mut lock = self.tree_lock.lock();
        let mut tree = lock.get_mut().unwrap();

        let lock_addr_id = self.prov.alloc_id.get();
        let metadata_id = unsafe { (*self.alloc_info).alloc_id.get() };

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
        tree.dealloc(
            self.prov.bor_tag,
            unsafe {
                AllocRange {
                    start: Size::from_bytes((*self.alloc_info).base_addr() as usize),
                    size: Size::from_bytes((*self.alloc_info).size),
                }
            },
            self.ctx,
            self.prov.alloc_id,
            Span::new(),
            self.allocator,
        )?;

        unsafe {
            (*self.alloc_info).alloc_id = AllocId::invalid();
            (*self.alloc_info).base_addr = FreeListAddrUnion { base_addr: core::ptr::null() };
            (*self.alloc_info).size = 0;
            (*self.alloc_info).align = 1;
        }
        // Tree is freed by `__bsan_dealloc`
        // Set the tree pointer to NULL
        let tree_lock = &self.tree_lock;
        let _lock = tree_lock.lock();

        // SAFETY: Exclusive access to *mut raw pointer is ensured by the above
        // tree lock
        unsafe { *self.tree_lock.data_ptr() = Once::new() }
        // // Drop lock early so we can pass in mutable reference
        // core::mem::drop(_lock);
        // Deallocate `AllocInfo`
        unsafe { self.ctx.deallocate_lock_location(self.alloc_info) };
        Ok(())
    }
}
