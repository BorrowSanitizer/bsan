// Components in this library were ported from Miri and then modified by our team.
use core::cell::Cell;
use core::mem::offset_of;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use spin::{Mutex, MutexGuard};

use crate::errors::{UBInfo, UBResult};
use crate::helpers::{AllocRange, Size};
use crate::sanitizer_common::Span;
use crate::tree_borrows::data_structures::{AccessType, DedupRangeMap};
use crate::tree_borrows::diagnostics::AccessCause;
use crate::tree_borrows::perms::{AccessKind, Permission};
use crate::tree_borrows::tree::{BorrowState, LocationState, Node};
use crate::tree_borrows::{AllocState, AllocStateImpl, IdempotentForeignAccess, NewPermission};
use crate::{AllocId, BorTag, GlobalCtx, Provenance, RetagFlags, RetagInfo};

/// Heap-allocated root: inline [`Node`] plus shared borrow state.
///
/// Stack slots (`on_stack`) stay off the free list until `destroy_stack_slot`.
#[repr(C)]
pub(crate) struct RootNode {
    pub(crate) node: Node,
    pub(crate) alloc_id: Cell<AllocId>,
    pub(crate) base_addr: Cell<Size>,
    pub(crate) size: Cell<Size>,
    pub(crate) state: Mutex<BorrowState>,
    pub(crate) free_list_next: Option<NonNull<RootNode>>,
    /// Only frame teardown may return this slot to the free list.
    pub(crate) on_stack: bool,
}

impl RootNode {
    pub(crate) fn invalid() -> Self {
        Self {
            node: Node::new_root(BorTag::invalid(), Span::dummy()),
            alloc_id: Cell::new(AllocId::invalid()),
            base_addr: Cell::new(Size::ZERO),
            size: Cell::new(Size::ZERO),
            state: Mutex::new(BorrowState::None),
            free_list_next: None,
            on_stack: false,
        }
    }

    /// Reserved stack slot (`BorrowState::None`) owned by the frame until destroy.
    pub(crate) fn invalid_stack() -> Self {
        let mut root = Self::invalid();
        root.on_stack = true;
        root
    }

    pub(crate) fn new(base_addr: Size, size: Size, bor_tag: BorTag, span: Span) -> Self {
        Self {
            node: Node::new_root(bor_tag, span),
            alloc_id: Cell::new(AllocId::default()),
            base_addr: Cell::new(base_addr),
            size: Cell::new(size),
            state: Mutex::new(BorrowState::new(bor_tag, size, span)),
            free_list_next: None,
            on_stack: false,
        }
    }

    /// Points `node.state` at this slot's mutex. Must be called after the `RootNode` is placed
    /// at a stable address (heap alloc / in-place write).
    pub(crate) unsafe fn wire_state(this: NonNull<RootNode>) {
        unsafe {
            let state_ptr = NonNull::from(&(*this.as_ptr()).state);
            (*this.as_ptr()).node.state = state_ptr;
        }
    }

    /// Recovers the enclosing [`RootNode`] from any node that shares its `state` mutex.
    pub(crate) unsafe fn from_node(node: NonNull<Node>) -> NonNull<RootNode> {
        let state_ptr = unsafe { node.as_ref().state.as_ptr() };
        let root = (state_ptr as usize).wrapping_sub(offset_of!(RootNode, state)) as *mut RootNode;
        unsafe { NonNull::new_unchecked(root) }
    }

    pub(crate) fn node_ptr(this: NonNull<RootNode>) -> NonNull<Node> {
        unsafe { NonNull::from(&(*this.as_ptr()).node) }
    }

    #[cfg(feature = "debug")]
    pub(crate) fn summarize(&self) -> crate::NodeSummary {
        crate::NodeSummary::Valid {
            alloc_id: self.alloc_id.get(),
            base_addr: self.base_addr.get(),
            size: self.size.get(),
        }
    }
}

/// Pointer to a tree [`Node`] (root or child) for a live allocation.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct NodePtr(NonNull<Node>);

impl NodePtr {
    /// # Safety
    /// The node must belong to a valid, non-freed allocation.
    pub(crate) unsafe fn range(&self) -> AllocRange {
        let root = unsafe { RootNode::from_node(self.0).as_ref() };
        AllocRange { start: root.base_addr.get(), size: root.size.get() }
    }

    /// # Safety
    /// The node must belong to a valid, non-freed allocation.
    pub(crate) unsafe fn base_addr(&self) -> Size {
        unsafe { RootNode::from_node(self.0).as_ref().base_addr.get() }
    }

    pub(crate) fn alloc_id(&self) -> AllocId {
        unsafe { RootNode::from_node(self.0).as_ref().alloc_id.get() }
    }

    pub(crate) fn size(&self) -> Size {
        unsafe { RootNode::from_node(self.0).as_ref().size.get() }
    }

    pub(crate) fn root_node_ptr(&self) -> NonNull<Node> {
        let root = unsafe { RootNode::from_node(self.0) };
        RootNode::node_ptr(root)
    }

    fn tree<'b>(self) -> UBResult<TreeGuard<'b>> {
        self.tree_opt().ok_or(UBInfo::UseAfterFree)
    }

    fn tree_opt<'b>(self) -> Option<TreeGuard<'b>> {
        let state = unsafe { self.0.as_ref().state.as_ref() }.lock();
        if state.is_live() {
            Some(unsafe { TreeGuard::new(state) })
        } else {
            None
        }
    }

    /// Removes dead tags from the allocation's borrow state.
    /// Returns `true` when the tree is empty and the `RootNode` may be ejected.
    ///
    /// Stack roots never report empty: the frame owns the slot until
    /// `destroy_stack_slot`, so GC must not eject them even if all tags were pruned.
    pub(crate) fn prune_dead_tags(self, dead_tags: &mut [BorTag]) -> bool {
        let on_stack = unsafe { RootNode::from_node(self.0).as_ref().on_stack };
        match self.tree_opt() {
            Some(mut tree) => {
                let empty = tree.remove_dead_tags(dead_tags);
                empty && !on_stack
            }
            None => {
                dead_tags.fill(BorTag::omnivalid());
                false
            }
        }
    }
}

impl From<NonNull<Node>> for NodePtr {
    fn from(value: NonNull<Node>) -> Self {
        Self(value)
    }
}

// A guard over the borrow state for an allocation.
#[derive(Debug)]
struct TreeGuard<'b>(MutexGuard<'b, BorrowState>);

impl<'b> TreeGuard<'b> {
    /// # Safety
    /// The inner state must be live (`Uninit` or `Init`).
    #[must_use]
    #[inline]
    unsafe fn new(value: MutexGuard<'b, BorrowState>) -> Self {
        debug_assert!(value.is_live());
        Self(value)
    }

    #[inline]
    fn take(&mut self) -> BorrowState {
        core::mem::replace(&mut *self.0, BorrowState::None)
    }
}

impl Deref for TreeGuard<'_> {
    type Target = BorrowState;
    fn deref(&self) -> &BorrowState {
        &self.0
    }
}

impl DerefMut for TreeGuard<'_> {
    fn deref_mut(&mut self) -> &mut BorrowState {
        &mut self.0
    }
}

#[derive(Debug)]
pub(crate) struct BorrowTracker<'a> {
    bor_tag: BorTag,
    node: NodePtr,
    range: AllocRange,
    tree: TreeGuard<'a>,
}

impl<'b> BorrowTracker<'b> {
    pub(crate) fn for_alloc_weak<T, F>(prov: Provenance, f: F) -> T
    where
        F: FnOnce(Self) -> T,
        T: Default,
    {
        if !prov.is_concrete() {
            return T::default();
        }
        let node: NodePtr = unsafe { NonNull::new_unchecked(prov.node()).into() };
        if let Some(tree) = node.tree_opt() {
            let size = node.size();
            let range = AllocRange { start: Size::ZERO, size };
            f(Self { tree, bor_tag: prov.tag(), node, range })
        } else {
            T::default()
        }
    }

    /// # Safety
    /// The caller must provide concrete provenance whose allocation metadata is
    /// valid and live, and `start..start + access_size` must be in-bounds.
    pub(crate) unsafe fn for_access_unchecked<T, F>(
        _: &GlobalCtx,
        prov: Provenance,
        start: Size,
        access_size: Option<Size>,
        f: F,
    ) -> UBResult<T>
    where
        F: FnOnce(Self) -> UBResult<T>,
        T: Default,
    {
        let node: NodePtr = unsafe { NonNull::new_unchecked(prov.node()).into() };
        let alloc_size = node.size();
        let base_addr = unsafe { node.base_addr() };
        let offset = Size::from_bytes(start.bytes().wrapping_sub(base_addr.bytes()));
        let tree = node.tree()?;

        let range = AllocRange { start: offset, size: access_size.unwrap_or(alloc_size) };
        f(Self { tree, bor_tag: prov.tag(), node, range })
    }

    pub(crate) fn for_access<T, F>(
        global_ctx: &GlobalCtx,
        prov: Provenance,
        start: Size,
        access_size: Option<Size>,
        f: F,
    ) -> UBResult<T>
    where
        F: FnOnce(Self) -> UBResult<T>,
        T: Default,
    {
        // Omnivalid or unaligned shadow garbage (not a sentinel / Node*).
        if !prov.is_invalid() && !prov.is_wildcard() && !prov.is_concrete() {
            Ok(T::default())
        } else if prov.is_invalid() {
            if access_size == Some(Size::ZERO) {
                Ok(T::default())
            } else {
                Err(UBInfo::UseAfterFree)
            }
        } else {
            // Keep the provenance tag (wildcard stays wildcard even after
            // resolving an exposed Node*); do not use the resolved node's tag.
            let bor_tag = prov.tag();
            let node: NodePtr = if prov.is_wildcard() {
                let size = access_size.unwrap_or(Size::ZERO);
                let range = AllocRange { start, size };
                if let Some(exposed) = global_ctx.get_exposed_provenance(range) {
                    exposed
                } else {
                    // We cannot resolve this wildcard access to an exposed
                    // allocation. The access may target an allocation that we
                    // do not track at all (e.g. a global, which has omnivalid
                    // provenance and so is never registered as exposed), so we
                    // permit it to avoid false positives.
                    return Ok(T::default());
                }
            } else {
                debug_assert!(prov.is_concrete());
                unsafe { NonNull::new_unchecked(prov.node()).into() }
            };

            let alloc_id = node.alloc_id();
            let alloc_size = node.size();
            let base_addr = unsafe { node.base_addr() };
            let access_size = access_size.unwrap_or(alloc_size);
            let is_sized_access = access_size != Size::ZERO;

            // If there is no tree for this allocation, then this is a UAF,
            // unless this is a zero-sized access.
            let Some(tree) = node.tree_opt() else {
                return if is_sized_access { Err(UBInfo::UseAfterFree) } else { Ok(T::default()) };
            };

            // If the tree does not contain the borrow tag that we are using to
            // validate the access, then this is also a UAF, unless this is a
            // zero-sized access, or we have a wildcard tag.
            if !tree.contains_tag(bor_tag) && bor_tag.is_concrete() {
                return if is_sized_access { Err(UBInfo::UseAfterFree) } else { Ok(T::default()) };
            }

            // At this point, we know that we are accessing a valid allocation, but we cannot
            // tell if our access is in-bounds. It is crucial for this to be a wrapping sub here,
            // since we want to accurately model the effect of applying an oversized offset on
            // the allocation.
            let offset = Size::from_bytes(start.bytes().wrapping_sub(base_addr.bytes()));
            if start < base_addr || (offset + access_size > alloc_size) {
                return if access_size != Size::ZERO {
                    Err(UBInfo::AccessOutOfBounds { alloc_id, access_size, alloc_size, offset })
                } else {
                    Ok(T::default())
                };
            }

            let range = AllocRange { start: offset, size: access_size };
            f(Self { tree, bor_tag, node, range })
        }
    }

    pub(crate) fn retag(
        &mut self,
        global_ctx: &GlobalCtx,
        retag_info: RetagInfo<'_>,
        span: Span,
    ) -> UBResult<Provenance> {
        let alloc_id = self.node.alloc_id();
        let parent_tag = self.bor_tag;
        let new_tag = BorTag::default();
        // A wildcard parent is never present in the tree: retagging it adds
        // the new tag as a fresh wildcard root instead.
        if !parent_tag.is_wildcard() && !self.tree.contains_tag(parent_tag) {
            return Err(UBInfo::UseAfterFree);
        }
        let new_perm: NewPermission = NewPermission::new(retag_info);

        let protected = new_perm.protector.is_some();
        if let Some(protector) = new_perm.protector {
            // We register the protection in two different places.
            // This makes creating a protector slower, but checking whether a tag
            // is protected faster.
            // Since we return the fully-resolved provenance (including for
            // wildcard parents), the new tag is reachable for `protector_end`.
            global_ctx.protected_tags_mut().add_protector(new_tag, protector);
        }

        // Compute initial "inside" permissions.
        let loc_state = |frozen: bool| -> LocationState {
            let perm = if frozen { new_perm.freeze_perm } else { new_perm.nonfreeze_perm };
            let sifa = perm.strongest_idempotent_foreign_access(protected);
            if perm.associated_access().is_some() {
                assert!(perm.associated_access().unwrap() == AccessKind::Read);
                LocationState::new_accessed(perm, sifa)
            } else {
                LocationState::new_non_accessed(perm, sifa)
            }
        };

        let mut inside_perms = DedupRangeMap::new(
            retag_info.size,
            LocationState::new_accessed(Permission::new_disabled(), IdempotentForeignAccess::None),
        );

        let mut cursor = Size::ZERO;
        if let Some(im_layout) = retag_info.im_layout {
            for &[offset, size] in im_layout {
                if cursor != offset {
                    for (_loc_range, loc) in inside_perms.iter_mut(cursor, offset - cursor) {
                        *loc = loc_state(true);
                    }
                }
                for (_loc_range, loc) in inside_perms.iter_mut(offset, size) {
                    *loc = loc_state(false);
                }
                cursor = offset + size
            }
            if cursor < retag_info.size {
                let width = retag_info.size - cursor;
                for (_loc_range, loc) in inside_perms.iter_mut(cursor, width) {
                    *loc = loc_state(true);
                }
            }
        } else if retag_info.size > Size::ZERO {
            let perm = loc_state(retag_info.flags.contains(RetagFlags::IS_FREEZE));
            for (_loc_range, loc) in inside_perms.iter_mut(Size::ZERO, retag_info.size) {
                *loc = perm;
            }
        }

        let base_offset = self.range.start;
        for (perm_range, loc_state) in inside_perms.iter_all() {
            if let Some(access_kind) = loc_state.permission().associated_access() {
                // Some reborrows incur a read access to the parent.
                // Adjust range to be relative to allocation start
                let range_in_alloc = AllocRange {
                    start: Size::from_bytes(perm_range.start) + base_offset,
                    size: Size::from_bytes(perm_range.end - perm_range.start),
                };

                // Perform the access (update the Tree Borrows FSM)
                self.tree.perform_access(
                    parent_tag,
                    range_in_alloc,
                    access_kind,
                    AccessCause::Reborrow,
                    &global_ctx.protected_tags(),
                    alloc_id,
                    span,
                )?;
            }
        }

        // base offset should be the offset, from zero, where the retag is taking place within the allocation.
        let child = self.tree.new_child(
            base_offset,
            parent_tag,
            new_tag,
            inside_perms,
            new_perm.outside_perm,
            protected,
            span,
            self.node.root_node_ptr(),
        )?;

        Ok(Provenance::from_node(child.as_ptr()))
    }

    pub(crate) fn protector_end(&mut self, global_ctx: &GlobalCtx, span: Span) -> UBResult<()> {
        self.tree.perform_protector_end_access(
            self.bor_tag,
            &global_ctx.protected_tags(),
            self.node.alloc_id(),
            span,
        )
    }

    pub(crate) fn access(
        &mut self,
        global_ctx: &GlobalCtx,
        access_kind: AccessKind,
        span: Span,
    ) -> UBResult<()> {
        self.tree.perform_access(
            self.bor_tag,
            self.range,
            access_kind,
            AccessCause::Explicit(access_kind),
            &global_ctx.protected_tags(),
            self.node.alloc_id(),
            span,
        )
    }

    pub(crate) fn dealloc(mut self, global_ctx: &GlobalCtx, span: Span) -> UBResult<()> {
        let mut taken = self.tree.take();
        taken.dealloc(
            self.bor_tag,
            self.range,
            &global_ctx.protected_tags(),
            self.node.alloc_id(),
            span,
        )?;
        let range = unsafe { self.node.range() };
        global_ctx.remove_exposed_provenance(range, true);
        Ok(())
    }

    pub(crate) fn expose_tag(&mut self, global_ctx: &GlobalCtx) -> UBResult<()> {
        let tag = self.bor_tag;
        let range = unsafe { self.node.range() };

        // Ranges in the mapping must be non-empty, and a wildcard access can
        // never resolve to a zero-sized allocation anyway.
        if range.size > Size::ZERO {
            let mut exposed = global_ctx.exposed_provenance_mut();
            if let AccessType::Empty(pos) = exposed.access_type(range) {
                exposed.insert_at_pos(pos, range, self.node);
            }
        }

        self.tree.ensure_init(self.node.root_node_ptr());
        if self.tree.contains_tag(tag) {
            let protected = global_ctx.protected_tags().get_protector_kind(tag).is_some();
            self.tree.expose_tag(tag, protected);
        }
        Ok(())
    }

    pub(crate) fn debug_take_snapshot(&self, ctx: &GlobalCtx) {
        ctx.take_snapshot(self.node.alloc_id(), self.tree.clone());
    }

    pub(crate) fn debug_print_diff(&self, ctx: &GlobalCtx) {
        ctx.with_snapshot(self.node.alloc_id(), |old_tree: &AllocStateImpl| {
            self.tree.print_tree_diff(old_tree, &ctx.protected_tags());
        });
    }

    pub(crate) fn debug_print_tree(&self, ctx: &GlobalCtx, show_unnamed: bool) {
        self.tree.print_tree(&ctx.protected_tags(), show_unnamed);
    }

    pub(crate) fn debug_tree_size(&self) -> usize {
        self.tree.node_count()
    }
}
