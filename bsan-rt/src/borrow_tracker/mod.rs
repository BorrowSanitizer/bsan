use core::alloc::Allocator;

use bsan_shared::{AccessKind, AccessRelatedness, Permission, ProtectorKind, RetagInfo, Size};
use tree::{AllocRange, Tree};

use crate::diagnostics::AccessCause;
use crate::span::Span;
use crate::{AllocInfo, BorTag, BsanAllocHooks, GlobalCtx, Provenance};

#[cfg_attr(not(test), no_std)]
pub mod tree;
pub mod unimap;

// The allocator for BorrowTracker
pub type BtAlloc = BsanAllocHooks;
// TODO: Create trait for this wrapper functionality

// Potential validation middleware should be part of wrapper API?

// TODO: Replace with custom `Result` type
///
pub unsafe fn bt_validate_tree(
    prov: *const Provenance,
    global_ctx: &GlobalCtx,
    // `Some` intializes the tree
    retag_info: Option<&RetagInfo>,
) -> Result<(&'static mut Tree<BtAlloc>, &'static Provenance), ()> {
    // Get global allocator
    let allocator = global_ctx.hooks().alloc;

    // TODO: Validate provenance and return a "safe" reference

    assert!(unsafe { prov.as_ref().is_some() });

    // Initialize `Tree` if first retag

    // We assert that the tree ptr exists in the alloc metadata (and that the alloc metadata exists)
    assert!(unsafe { !((*prov).alloc_info).is_null() });

    // Casts the raw void ptr into an AllocInfo raw ptr and reborrows as a `AllocInfo` reference
    let alloc_info = unsafe { &*(((*prov).alloc_info) as *mut AllocInfo) };

    // Asserting that the tree pointer exists
    assert!(unsafe { alloc_info.tree.as_ref().is_some() });

    let prov_ref = unsafe { &*prov };

    // Cast the Tree void ptr into `Tree`
    let tree_ptr = unsafe { &raw mut *alloc_info.tree as *mut Tree<BtAlloc> };

    if retag_info.is_some() {
        // Check if the `Tree` (root node) exists, otherwise create it
        if (tree_ptr.is_null()) {
            // Create the tree

            // ATTENTION: Using the allocator provided by `global_ctx`, with a dummy Span for now
            unsafe {
                let tree: Tree<BtAlloc> = Tree::new_in(
                    (*prov).bor_tag,
                    Size::from_bytes(retag_info.unwrap().size),
                    Span::new(),
                    allocator,
                );

                *tree_ptr = tree;
            };
            // Now `Tree` reference should be valid
        }
    }
    // This should be valid
    let mut tree: &mut Tree<BtAlloc> = unsafe { &mut *tree_ptr };

    Ok((tree, prov_ref))
}

pub fn bt_tree_retag(
    tree: &mut Tree<BtAlloc>,
    prov: &Provenance,
    global_ctx: &GlobalCtx,
    retag_info: &RetagInfo,
) -> Result<(), ()> {
    // TODO: Lock the tree

    // Check if tree contains the tag (this should be unreachable?)
    if (tree.is_allocation_of(prov.bor_tag)) {
        unreachable!("BT: Tag exists in Tree indicating a double retag");
        return Err(());
    }

    let access_kind = AccessKind::Read;

    // Perform the access (update the Tree Borrows FSM)
    // Uses a dummy span
    // TODO: Implement error propagation
    tree.perform_access(
        prov.bor_tag,
        // TODO: Validate the Range
        Some((
            AllocRange { start: Size::from_bytes(0), size: Size::from_bytes(retag_info.size) },
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

pub fn bt_read(
    tree: &mut Tree<BtAlloc>,
    prov: &Provenance,
    global_ctx: &GlobalCtx,
    base_addr: Size,
    size: Size,
) -> Result<(), ()> {
    // TODO: Lock the tree

    let access_kind = AccessKind::Read;

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

pub fn bt_write(
    tree: &mut Tree<BtAlloc>,
    prov: &Provenance,
    global_ctx: &GlobalCtx,
    base_addr: Size,
    size: Size,
) -> Result<(), ()> {
    // TODO: Lock the tree

    let access_kind = AccessKind::Write;

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
