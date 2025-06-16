use core::alloc::Allocator;

use bsan_shared::{AccessKind, AccessRelatedness, Permission, ProtectorKind, RetagInfo, Size};
use tree::{AllocRange, Tree};

use crate::diagnostics::AccessCause;
use crate::hooks::BsanAllocHooks;
use crate::span::Span;
use crate::{AllocInfo, BorTag, GlobalCtx, Provenance};

#[cfg_attr(not(test), no_std)]
pub mod tree;
pub mod unimap;

// TODO: Create trait for this wrapper functionality

// Potential validation middleware should be part of wrapper API?

pub unsafe fn bt_init_tree(
    // This is an output pointer
    tree_ptr: *mut Tree<BsanAllocHooks>,
    bor_tag: BorTag,
    size: Size,
    allocator: BsanAllocHooks,
) -> Result<(), ()> {
    // Check if the `Tree` (root node) exists, otherwise create it
    if (tree_ptr.is_null()) {
        // Create the tree

        // ATTENTION: Using the allocator provided by `global_ctx`, with a dummy Span for now
        unsafe {
            let tree: Tree<BsanAllocHooks> = Tree::new_in(bor_tag, size, Span::new(), allocator);

            *tree_ptr = tree;
        };
        // Now `Tree` reference should be valid
    }

    Ok(())
}

// TODO: Replace with custom `Result` type
/// # Safety
///
/// This function should be called as middleware to verify the provenance and optionally
/// initialize the tree on retags
#[allow(clippy::result_unit_err)]
#[allow(private_interfaces)]
pub unsafe fn bt_validate_prov(
    prov: *const Provenance,
    ctx: &GlobalCtx,
) -> Result<*const AllocInfo, ()> {
    // Get global allocator
    let allocator = ctx.allocator();

    // TODO: Validate provenance and return a "safe" reference
    debug_assert!(unsafe { prov.as_ref().is_some() });

    // Initialize `Tree` if first retag

    // We assert that the tree ptr exists in the alloc metadata (and that the alloc metadata exists)
    debug_assert!(unsafe { !((*prov).alloc_info).is_null() });

    // Casts the raw void ptr into an AllocInfo raw ptr and reborrows as a `AllocInfo` reference
    let alloc_info_ptr = unsafe { (((*prov).alloc_info) as *const AllocInfo) };

    // This should be valid
    // Returning pointers as we do not want any lifetime restrictions with this method
    Ok(alloc_info_ptr)
}

#[allow(clippy::result_unit_err)]
pub fn bt_retag(
    tree: &mut Tree<BsanAllocHooks>,
    prov: &mut Provenance,
    global_ctx: &GlobalCtx,
    retag_info: &RetagInfo,
) -> Result<(), ()> {
    // TODO: Potentially also update prov.alloc_info?

    if tree.is_allocation_of(prov.bor_tag) {
        unreachable!("BT: Tag exists in Tree indicating an erroneous retag");
        return Err(());
    }

    bt_access(
        tree,
        prov,
        global_ctx,
        AccessKind::Read,
        Size::from_bytes(0),
        Size::from_bytes(retag_info.size),
    );

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
