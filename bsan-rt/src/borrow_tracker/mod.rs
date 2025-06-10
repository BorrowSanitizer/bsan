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

// #[derive(Debug, Clone, Copy, Eq, PartialEq)]
// pub enum BtAccessType {
//     READ,
//     WRITE,
//     DEALLOC,
// }

// impl BtAccessType {
//     fn access_kind(&self) -> AccessKind {
//         match self {
//             BtAccessType::READ => AccessKind::Read,
//             BtAccessType::WRITE => AccessKind::Write,
//             BtAccessType::DEALLOC => AccessKind::Write,
//         }
//     }
// }

// TODO: Create trait for this wrapper functionality

// Potential validation middleware should be part of wrapper API?

// TODO: Replace with custom `Result` type
/// # Safety
///
/// This function should be called as middleware to verify the provenance and optionally
/// initialize the tree on retags
#[allow(clippy::result_unit_err)]
pub unsafe fn bt_validate_tree(
    prov: *const Provenance,
    global_ctx: &GlobalCtx,
    // `Some` intializes the tree
    retag_info: Option<&RetagInfo>,
) -> Result<*mut Tree<BsanAllocHooks>, ()> {
    // Get global allocator
    let allocator = global_ctx.hooks().alloc;

    // TODO: Validate provenance and return a "safe" reference

    debug_assert!(unsafe { prov.as_ref().is_some() });

    // Initialize `Tree` if first retag

    // We assert that the tree ptr exists in the alloc metadata (and that the alloc metadata exists)
    debug_assert!(unsafe { !((*prov).alloc_info).is_null() });

    // Casts the raw void ptr into an AllocInfo raw ptr and reborrows as a `AllocInfo` reference
    let alloc_info = unsafe { &*(((*prov).alloc_info) as *mut AllocInfo) };

    // Asserting that the tree pointer exists
    debug_assert!(unsafe { alloc_info.tree.as_ref().is_some() });

    // Cast the Tree void ptr into `Tree`
    let tree_ptr = unsafe { &raw mut *alloc_info.tree as *mut Tree<BsanAllocHooks> };

    if let Some(retag_info) = retag_info {
        // Check if the `Tree` (root node) exists, otherwise create it
        if (tree_ptr.is_null()) {
            // Create the tree

            // ATTENTION: Using the allocator provided by `global_ctx`, with a dummy Span for now
            unsafe {
                let tree: Tree<BsanAllocHooks> = Tree::new_in(
                    (*prov).bor_tag,
                    Size::from_bytes(retag_info.size),
                    Span::new(),
                    allocator,
                );

                *tree_ptr = tree;
            };
            // Now `Tree` reference should be valid
        }
    }
    // This should be valid

    Ok(tree_ptr)
}

#[allow(clippy::result_unit_err)]
pub fn bt_retag(
    tree: &mut Tree<BsanAllocHooks>,
    prov: &mut Provenance,
    global_ctx: &GlobalCtx,
    retag_info: &RetagInfo,
) -> Result<(), ()> {
    // Update the provenance borrow tag
    prov.bor_tag = global_ctx.new_bor_tag();

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
