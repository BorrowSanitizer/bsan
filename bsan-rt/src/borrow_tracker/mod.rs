use core::alloc::Allocator;
use core::cell::LazyCell;
use core::ffi::c_void;

use bsan_shared::{
    AccessKind, AccessRelatedness, Permission, ProtectorKind, RangeMap, RetagInfo, Size,
};
use parking_lot::Mutex;
use spin::Once;
use tree::{AllocRange, Tree};

use crate::borrow_tracker::tree::{ChildParams, LocationState};
use crate::diagnostics::AccessCause;
use crate::span::Span;
use crate::{AllocInfo, BorTag, BsanAllocHooks, GlobalCtx, Provenance};

#[cfg_attr(not(test), no_std)]
pub mod tree;
pub mod unimap;

// TODO: Create trait for this wrapper functionality

// Potential validation middleware should be part of wrapper API?

pub fn bt_init_tree(
    // This is an output pointer
    tree: Once<Tree<BsanAllocHooks>>,
    bor_tag: BorTag,
    size: Size,
    allocator: BsanAllocHooks,
) -> Result<(), ()> {
    // Create the tree
    let tree_allocator = || Tree::new_in(bor_tag, size, Span::new(), allocator);
    // Initialize the tree
    tree.call_once(tree_allocator);

    // Now `Tree` reference should be valid
    Ok(())
}

// TODO: Replace with custom `Result` type
/// # Safety
///
/// This function should be called as middleware to verify the provenance and optionally
/// initialize the tree on retags
/// Checks if the pointer's address is within bounds of the allocation
#[allow(clippy::result_unit_err)]
#[allow(private_interfaces)]
pub unsafe fn bt_validate_tree(
    prov: *const Provenance,
    ctx: &GlobalCtx,
    object_address: usize,
) -> Result<(*const Tree<BsanAllocHooks>), ()> {
    // Get global allocator
    let allocator = ctx.allocator();

    // TODO: Validate provenance and return a "safe" reference
    debug_assert!(unsafe { prov.as_ref().is_some() });

    // Initialize `Tree` if first retag

    // We assert that the tree ptr exists in the alloc metadata (and that the alloc metadata exists)
    debug_assert!(unsafe { !((*prov).alloc_info).is_null() });

    let alloc_info_ptr = AllocInfo::get_raw(prov);

    let alloc_info = unsafe { &*alloc_info_ptr };

    let prov = unsafe { &*prov };

    if prov.alloc_id != alloc_info.alloc_id {
        // TODO: Add proper error handling and bailing
        // Use after free error as alloc_ids do not match
        return Err(());
    }

    let base_offset = alloc_info.base_offset(object_address);

    // Check for out of bounds accessess
    // TODO: Checkout lib functions to compare pointers instead of using usize
    if (object_address as usize) < alloc_info.base_addr() as usize
        || (object_address as usize) >= alloc_info.base_addr() as usize + alloc_info.size
    {
        // TODO: Add proper error handling and bailing
        // Access out-of-bounds error
        return Err(());
    }

    let mut tree_lock = alloc_info.tree_lock.lock();

    // Cast the Tree void ptr into `Tree` by locking the Tree
    let tree_ptr = unsafe { &raw mut tree_lock as *mut Tree<BsanAllocHooks> };

    // This should be valid
    // Returning pointers as we do not want any lifetime restrictions with this method
    Ok((tree_ptr))
}

#[allow(clippy::result_unit_err)]
#[allow(private_interfaces)]
pub fn bt_retag(
    tree: &mut Tree<BsanAllocHooks>,
    prov: &mut Provenance,
    ctx: &GlobalCtx,
    retag_info: &RetagInfo,
    // TODO: Potentially pass this in as a part of `RetagInfo`
    alloc_info: &AllocInfo,
) -> Result<(), ()> {
    // TODO: Potentially also update prov.alloc_info?
    #[cfg(debug)]
    if tree.is_allocation_of(prov.bor_tag) {
        unreachable!("BT: Tag exists in Tree indicating an erroneous retag");
        return Err(());
    }

    let allocator = ctx.allocator();

    // TODO: Pass this in

    let mut perms_map = RangeMap::new_in(
        Size::from_bytes(alloc_info.size),
        LocationState::new_accessed(
            Permission::new_disabled(),
            bsan_shared::IdempotentForeignAccess::None,
        ),
        allocator,
    );

    for (perm_range, perm) in perms_map.iter_mut_all() {
        if perm.is_accessed() {
            // Some reborrows incura  read access to the parent.
            // Adjust range to be relative to allocation start
            let range_in_alloc = AllocRange {
                start: Size::from_bytes(perm_range.start)
                    + alloc_info.base_offset(todo!("object address")),
                size: Size::from_bytes(perm_range.end - perm_range.start),
            };

            bt_access(tree, prov, ctx, AccessKind::Read, range_in_alloc.start, range_in_alloc.size)
                .unwrap()
        }
    }

    let child_params: ChildParams = ChildParams {
        base_offset: alloc_info.base_offset(todo!("object address")),
        parent_tag: prov.bor_tag,
        new_tag: ctx.new_bor_tag(),
        initial_perms: perms_map,
        default_perm: todo!("Implement default perm"),
        protected: todo!("Implement protected"),
        span: Span::new(),
    };

    tree.new_child(child_params);

    Ok(())
}

#[allow(clippy::result_unit_err)]
pub fn bt_access(
    tree: &mut Tree<BsanAllocHooks>,
    prov: &Provenance,
    global_ctx: &GlobalCtx,
    access_kind: AccessKind,
    base_addr: Size,
    size: Size,
) -> Result<(), ()> {
    // Perform the access (update the Tree Borrows FSM)
    // Uses a dummy span
    // TODO: Implement error propagation
    tree.perform_access(
        prov.bor_tag,
        // TODO: Validate the Range
        Some((
            AllocRange { start: base_addr, size },
            access_kind,
            AccessCause::Explicit(access_kind),
        )),
        global_ctx,
        prov.alloc_id,
        Span::new(),
        // Passing in allocator explicitly to stay consistent with API
        global_ctx.hooks().alloc,
    )
    .unwrap();

    Ok(())
}
