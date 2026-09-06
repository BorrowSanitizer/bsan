// Ported from Miri (commit:072a9fa) with edits: removed `ProvenanceExtra` & `VisitProvenance`
// - added `EagerTree` and `LazyTree`
// - adapted GC functions for shadow memory reference counter
//! In this file we handle the "Tree" part of Tree Borrows, i.e. all tree
//! traversal functions, optimizations to trim branches, and keeping track of
//! the relative position of the access to each node being updated. This of course
//! also includes the definition of the tree structure.
//!
//! Functions here manipulate permissions but are oblivious to them: as
//! the internals of `Permission` are private, the update process is a black
//! box. All we need to know here are
//! - the fact that updates depend only on the old state, the status of protectors,
//!   and the relative position of the access;
//! - idempotency properties asserted in `perms.rs` (for optimizations)

// use alloc::boxed::Box;
use core::ops::Range;
use core::{cmp, fmt, mem};

use smallvec::SmallVec;

use super::data_structures::{DedupRangeMap, UniIndex, UniKeyMap, UniValMap};
use super::diagnostics::{
    no_valid_exposed_references_error, AccessCause, DiagnosticInfo, ErrorNode, NodeDebugInfo,
    TbError, TransitionError,
};
use super::foreign_access_skipping::IdempotentForeignAccess;
use super::perms::{AccessKind, PermTransition, Permission};
use super::refcount::RefCount;
use super::tree_visitor::{ChildrenVisitMode, ContinueTraversal, NodeAppArgs, TreeVisitor};
use super::wildcard::{ExposedCache, WildcardAccessLevel};
use crate::errors::UBResult;
use crate::helpers::{AllocRange, Size};
use crate::sanitizer_common::Span;
use crate::tree_borrows::ProtectorKind;
use crate::*;

// Features in ./bsan-rt/Cargo.toml

#[cfg(all(feature = "lazy", feature = "eager"))] // Ensure one selection
compile_error!("Only one of the following features can be selected: 'lazy', 'eager'");

#[cfg(feature = "lazy")]
pub type AllocStateImpl = LazyTree;

#[cfg(feature = "eager")]
pub type AllocStateImpl = EagerTree;

mod tests;

/// Data for a reference at single *location*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct LocationState {
    /// A location is "accessed" when it is child-accessed for the first time (and the initial
    /// retag initializes the location for the range covered by the type), and it then stays
    /// accessed forever.
    /// For accessed locations, "permission" is the current permission. However, for
    /// non-accessed locations, we still need to track the "future initial permission": this will
    /// start out to be `default_initial_perm`, but foreign accesses need to be taken into account.
    /// Crucially however, while transitions to `Disabled` would usually be UB if this location is
    /// protected, that is *not* the case for non-accessed locations. Instead we just have a latent
    /// "future initial permission" of `Disabled`, causing UB only if an access is ever actually
    /// performed.
    /// Note that the tree root is also always accessed, as if the allocation was a write access.
    accessed: bool,
    /// This pointer's current permission / future initial permission.
    permission: Permission,
    /// See `foreign_access_skipping.rs`.
    /// Stores an idempotent foreign access for this location and its children.
    /// For correctness, this must not be too strong, and the recorded idempotent foreign access
    /// of all children must be at least as strong as this. For performance, it should be as strong as possible.
    idempotent_foreign_access: IdempotentForeignAccess,
}

/// The state of the full tree for a particular location: for all nodes, the local permissions
/// of that node, and the tracking for wildcard accesses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocationTree {
    /// Maps a tag to a perm, with possible lazy initialization.
    ///
    /// NOTE: not all tags registered in `Tree::nodes` are necessarily in all
    /// ranges of `perms`, because `perms` is in part lazily initialized.
    /// Just because `nodes.get(key)` is `Some(_)` does not mean you can safely
    /// `unwrap` any `perm.get(key)`.
    ///
    /// We do uphold the fact that `keys(perms)` is a subset of `keys(nodes)`
    pub perms: UniValMap<LocationState>,
    /// Caches information about the relatedness of nodes for a wildcard access.
    pub exposed_cache: ExposedCache,
}
/// Tree structure with both parents and children since we want to be
/// able to traverse the tree efficiently in both directions.
#[derive(Clone, Debug)]
pub struct EagerTree {
    /// Mapping from tags to keys. The key obtained can then be used in
    /// any of the `UniValMap` relative to this allocation, i.e.
    /// `nodes`, `LocationTree::perms` and `LocationTree::exposed_cache`
    /// of the same `Tree`.
    /// The parent-child relationship in `Node` is encoded in terms of these same
    /// keys, so traversing the entire tree needs exactly one access to
    /// `tag_mapping`.
    pub(crate) tag_mapping: UniKeyMap<BorTag>,
    /// All nodes of this tree.
    pub(super) nodes: UniValMap<Node>,
    /// Associates with each location its state and wildcard access tracking.
    pub(super) locations: DedupRangeMap<LocationTree>,
    /// Contains both the root of the main tree as well as the roots of the wildcard subtrees.
    ///
    /// If we reborrow a reference which has wildcard provenance, then we do not know where in
    /// the tree to attach them. Instead we create a new additional tree for this allocation
    /// with this new reference as a root. We call this additional tree a wildcard subtree.
    ///
    /// The actual structure should be a single tree but with wildcard provenance we approximate
    /// this with this ordered set of trees. Each wildcard subtree is the direct child of *some* exposed
    /// tag (that is smaller than the root), but we do not know which. This also means that it can only be the
    /// child of a tree that comes before it in the vec ensuring we don't have any cycles in our
    /// approximated tree.
    ///
    /// Sorted according to `BorTag` from low to high. This also means the main root is `root[0]`.
    ///
    /// Has array size 2 because that still ensures the minimum size for SmallVec.
    pub(super) roots: SmallVec<[UniIndex; 2]>,
}

/// A tree that is lazily initialized: starts as `Uninit` (storing only the root tag, size, and
/// span needed to construct the real `Tree` on demand), and transitions to `Init` the first
/// time a child is added via `new_child`. All operations on a single-node tree short-circuit
/// without ever allocating the underlying `Tree`.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum LazyTree {
    Uninit { root_tag: BorTag, size: Size, span: Span, refcount: RefCount },
    Init(EagerTree),
}

impl LazyTree {
    pub fn new(root_tag: BorTag, size: Size, span: Span) -> Self {
        LazyTree::Uninit { root_tag, size, span, refcount: RefCount::new() }
    }

    /// Forces the tree into the `Init` state, constructing the underlying `Tree` if needed.
    fn ensure_init(&mut self) {
        if let LazyTree::Uninit { root_tag, size, span, refcount } = self {
            let mut tree = EagerTree::new(*root_tag, *size, *span);
            let root_idx = tree.tag_mapping.get(root_tag).unwrap();
            tree.nodes.get_mut(root_idx).unwrap().refcount = refcount.clone();
            *self = LazyTree::Init(tree);
        }
    }
}

/// A node in the borrow tree. Each node is uniquely identified by a tag via
/// the `nodes` map of `Tree`.
#[derive(Clone, Debug)]
pub struct Node {
    /// The tag of this node.
    pub tag: BorTag,
    /// All tags except the root have a parent tag.
    pub parent: Option<UniIndex>,
    /// If the pointer was reborrowed, it has children.
    // FIXME: bench to compare this to FxHashSet and to other SmallVec sizes
    pub children: SmallVec<[UniIndex; 4]>,
    /// Either `Reserved`,  `Frozen`, or `Disabled`, it is the permission this tag will
    /// lazily be initialized to on the first access.
    /// It is only ever `Disabled` for a tree root, since the root is initialized to `Unique` by
    /// its own separate mechanism.
    default_initial_perm: Permission,
    /// The default initial (strongest) idempotent foreign access.
    /// This participates in the invariant for `LocationState::idempotent_foreign_access`
    /// in cases where there is no location state yet. See `foreign_access_skipping.rs`,
    /// and `LocationState::idempotent_foreign_access` for more information
    default_initial_idempotent_foreign_access: IdempotentForeignAccess,
    /// Whether a wildcard access could happen through this node.
    pub is_exposed: bool,
    /// If the node is currently protected.
    pub protector_kind: Option<ProtectorKind>,
    /// Number of live references to this node. Always accessed under the
    /// allocation's tree `Mutex`.
    pub refcount: RefCount,
    /// Indicates that the node is unreachable in memory.
    pub dead: Cell<bool>,
    /// Some extra information useful only for debugging purposes.
    pub debug_info: NodeDebugInfo,
}

impl Node {
    pub fn default_location_state(&self) -> LocationState {
        LocationState::new_non_accessed(
            self.default_initial_perm,
            self.default_initial_idempotent_foreign_access,
        )
    }

    /// How this node should be referred to by an error message.
    fn error_node(&self) -> ErrorNode<'_> {
        ErrorNode { info: &self.debug_info, protector: self.protector_kind }
    }
}

/// Relative position of the access
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessRelatedness {
    /// The access happened either through the node itself or one of
    /// its transitive children.
    LocalAccess,
    /// The access happened through this nodes ancestor or through
    /// a sibling/cousin/uncle/etc.
    ForeignAccess,
}

impl AccessRelatedness {
    /// Check that access is either Ancestor or Distant, i.e. not
    /// a transitive child (initial pointer included).
    pub fn is_foreign(self) -> bool {
        matches!(self, AccessRelatedness::ForeignAccess)
    }
}

impl LocationState {
    /// Constructs a new initial state. It has neither been accessed, nor been subjected
    /// to any foreign access yet.
    /// The permission is not allowed to be `Unique`.
    /// `sifa` is the (strongest) idempotent foreign access, see `foreign_access_skipping.rs`
    pub fn new_non_accessed(permission: Permission, sifa: IdempotentForeignAccess) -> Self {
        assert!(permission.is_initial() || permission.is_disabled());
        Self { permission, accessed: false, idempotent_foreign_access: sifa }
    }

    /// Constructs a new initial state. It has not yet been subjected
    /// to any foreign access. However, it is already marked as having been accessed.
    /// `sifa` is the (strongest) idempotent foreign access, see `foreign_access_skipping.rs`
    pub fn new_accessed(permission: Permission, sifa: IdempotentForeignAccess) -> Self {
        Self { permission, accessed: true, idempotent_foreign_access: sifa }
    }

    /// Check if the location has been accessed, i.e. if it has
    /// ever been accessed through a child pointer.
    pub fn accessed(&self) -> bool {
        self.accessed
    }

    pub fn permission(&self) -> Permission {
        self.permission
    }

    /// Performs an access on this index and updates node,
    /// perm and wildcard_state to reflect the transition.
    fn perform_transition(
        &mut self,
        global_ctx: &GlobalCtx,
        idx: UniIndex,
        nodes: &mut UniValMap<Node>,
        exposed_cache: &mut ExposedCache,
        access_kind: AccessKind,
        relatedness: AccessRelatedness,
        protected: bool,
        diagnostics: &DiagnosticInfo,
    ) -> Result<(), TransitionError> {
        // Call this function now (i.e. only if we know `relatedness`), which
        // ensures it is only called when `skip_if_known_noop` returns
        // `Recurse`, due to the contract of `traverse_this_parents_children_other`.
        self.record_new_access(access_kind, relatedness);
        let old_access_level = self.permission.strongest_allowed_local_access(protected);
        let transition = self.perform_access(access_kind, relatedness, protected)?;
        if !transition.is_noop() {
            let node = nodes.get_mut(idx).unwrap();

            if global_ctx.flags.node_debug_info {
                // Record the event as part of the history.
                node.debug_info
                    .history
                    .push(diagnostics.create_event(transition, relatedness.is_foreign()));
            }

            // We need to update the wildcard state, if the permission
            // of an exposed pointer changes.
            if node.is_exposed {
                let access_level = self.permission.strongest_allowed_local_access(protected);
                exposed_cache.update_exposure(nodes, idx, old_access_level, access_level);
            }
        }
        Ok(())
    }

    /// Apply the effect of an access to one location, including
    /// - applying `Permission::perform_access` to the inner `Permission`,
    /// - emitting protector UB if the location is accessed,
    /// - updating the accessed status (child accesses produce accessed locations).
    fn perform_access(
        &mut self,
        access_kind: AccessKind,
        rel_pos: AccessRelatedness,
        protected: bool,
    ) -> Result<PermTransition, TransitionError> {
        let old_perm = self.permission;
        let transition = Permission::perform_access(access_kind, rel_pos, old_perm, protected)
            .ok_or(TransitionError::ChildAccessForbidden(old_perm))?;
        self.accessed |= !rel_pos.is_foreign();
        self.permission = transition.applied(old_perm).unwrap();
        // Why do only accessed locations cause protector errors?
        // Consider two mutable references `x`, `y` into disjoint parts of
        // the same allocation. A priori, these may actually both be used to
        // access the entire allocation, as long as only reads occur. However,
        // a write to `y` needs to somehow record that `x` can no longer be used
        // on that location at all. For these non-accessed locations (i.e., locations
        // that haven't been accessed with `x` yet), we track the "future initial state":
        // it defaults to whatever the initial state of the tag is,
        // but the access to `y` moves that "future initial state" of `x` to `Disabled`.
        // However, usually a `Reserved -> Disabled` transition would be UB due to the protector!
        // So clearly protectors shouldn't fire for such "future initial state" transitions.
        //
        // See the test `two_mut_protected_same_alloc` in `tests/pass/tree_borrows/tree-borrows.rs`
        // for an example of safe code that would be UB if we forgot to check `self.accessed`.
        if protected && self.accessed && transition.produces_disabled() {
            return Err(TransitionError::ProtectedDisabled(old_perm));
        }
        Ok(transition)
    }

    /// Like `perform_access`, but ignores the concrete error cause and also uses state-passing
    /// rather than a mutable reference. As such, it returns `Some(x)` if the transition succeeded,
    /// or `None` if there was an error.
    #[cfg(test)]
    fn perform_access_no_fluff(
        mut self,
        access_kind: AccessKind,
        rel_pos: AccessRelatedness,
        protected: bool,
    ) -> Option<Self> {
        match self.perform_access(access_kind, rel_pos, protected) {
            Ok(_) => Some(self),
            Err(_) => None,
        }
    }

    /// Tree traversal optimizations. See `foreign_access_skipping.rs`.
    /// This checks if such a foreign access can be skipped.
    fn skip_if_known_noop(
        &self,
        access_kind: AccessKind,
        rel_pos: AccessRelatedness,
    ) -> ContinueTraversal {
        if rel_pos.is_foreign() {
            let happening_now = IdempotentForeignAccess::from_foreign(access_kind);
            let mut new_access_noop =
                self.idempotent_foreign_access.can_skip_foreign_access(happening_now);
            if self.permission.is_disabled() {
                // A foreign access to a `Disabled` tag will have almost no observable effect.
                // It's a theorem that `Disabled` node have no protected accessed children,
                // and so this foreign access will never trigger any protector.
                // (Intuition: You're either protected accessed, and thus can't become Disabled
                // or you're already Disabled protected, but not accessed, and then can't
                // become accessed since that requires a child access, which Disabled blocks.)
                // Further, the children will never be able to read or write again, since they
                // have a `Disabled` parent. So this only affects diagnostics, such that the
                // blocking write will still be identified directly, just at a different tag.
                new_access_noop = true;
            }
            if self.permission.is_frozen() && access_kind == AccessKind::Read {
                // A foreign read to a `Frozen` tag will have almost no observable effect.
                // It's a theorem that `Frozen` nodes have no `Unique` children, so all children
                // already survive foreign reads. Foreign reads in general have almost no
                // effect, the only further thing they could do is make protected `Reserved`
                // nodes become conflicted, i.e. make them reject child writes for the further
                // duration of their protector. But such a child write is already rejected
                // because this node is frozen. So this only affects diagnostics, but the
                // blocking read will still be identified directly, just at a different tag.
                new_access_noop = true;
            }
            if new_access_noop {
                // Abort traversal if the new access is indeed guaranteed
                // to be noop.
                // No need to update `self.idempotent_foreign_access`,
                // the type of the current streak among nonempty read-only
                // or nonempty with at least one write has not changed.
                ContinueTraversal::SkipSelfAndChildren
            } else {
                // Otherwise propagate this time, and also record the
                // access that just occurred so that we can skip the propagation
                // next time.
                ContinueTraversal::Recurse
            }
        } else {
            // A child access occurred, this breaks the streak of foreign
            // accesses in a row and the sequence since the previous child access
            // is now empty.
            ContinueTraversal::Recurse
        }
    }

    /// Records a new access, so that future access can potentially be skipped
    /// by `skip_if_known_noop`. This must be called on child accesses, and otherwise
    /// should be called on foreign accesses for increased performance. It should not be called
    /// when `skip_if_known_noop` indicated skipping, since it then is a no-op.
    /// See `foreign_access_skipping.rs`
    fn record_new_access(&mut self, access_kind: AccessKind, rel_pos: AccessRelatedness) {
        debug_assert!(matches!(
            self.skip_if_known_noop(access_kind, rel_pos),
            ContinueTraversal::Recurse
        ));
        self.idempotent_foreign_access
            .record_new(IdempotentForeignAccess::from_acc_and_rel(access_kind, rel_pos));
    }
}

impl fmt::Display for LocationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.permission)?;
        if !self.accessed {
            write!(f, "?")?;
        }
        Ok(())
    }
}

impl EagerTree {
    /// Create a new tree, with only a root pointer.
    pub fn new(root_tag: BorTag, size: Size, span: Span) -> Self {
        // The root has `Disabled` as the default permission,
        // so that any access out of bounds is invalid.
        let root_default_perm = Permission::new_disabled();
        let mut tag_mapping = UniKeyMap::default();
        let root_idx = tag_mapping.insert(root_tag);
        let nodes = {
            let mut nodes = UniValMap::<Node>::default();
            let mut debug_info = NodeDebugInfo::new(root_tag, root_default_perm, span);
            // name the root so that all allocations contain one named pointer
            debug_info.add_name("root of the allocation");
            nodes.insert(
                root_idx,
                Node {
                    tag: root_tag,
                    parent: None,
                    children: SmallVec::default(),
                    default_initial_perm: root_default_perm,
                    // The root may never be skipped, all accesses will be local.
                    default_initial_idempotent_foreign_access: IdempotentForeignAccess::None,
                    is_exposed: false,
                    dead: Cell::new(false),
                    protector_kind: None,
                    refcount: RefCount::new(),
                    debug_info,
                },
            );
            nodes
        };
        let locations = {
            let mut perms = UniValMap::default();
            // We manually set it to `Unique` on all in-bounds positions.
            // We also ensure that it is accessed, so that no `Unique` but
            // not yet accessed nodes exist. Essentially, we pretend there
            // was a write that initialized these to `Unique`.
            perms.insert(
                root_idx,
                LocationState::new_accessed(
                    Permission::new_unique(),
                    IdempotentForeignAccess::None,
                ),
            );
            let exposed_cache = ExposedCache::default();
            DedupRangeMap::new(size, LocationTree { perms, exposed_cache })
        };
        Self { roots: SmallVec::from_slice(&[root_idx]), nodes, locations, tag_mapping }
    }

    /// Restores the SIFA "children are stronger"/"parents are weaker" invariant after a retag:
    /// reduce the SIFA of `current` and its parents to be no stronger than `strongest_allowed`.
    /// See `foreign_access_skipping.rs` and [`Tree::new_child`].
    fn update_idempotent_foreign_access_after_retag(
        &mut self,
        mut current: UniIndex,
        strongest_allowed: IdempotentForeignAccess,
    ) {
        if strongest_allowed == IdempotentForeignAccess::Write {
            // Nothing is stronger than `Write`.
            return;
        }
        // We walk the tree upwards, until the invariant is restored
        loop {
            let current_node = self.nodes.get_mut(current).unwrap();
            // Call `ensure_no_stronger_than` on all SIFAs for this node: the per-location SIFA, as well
            // as the default SIFA for not-yet-initialized locations.
            // Record whether we did any change; if not, the invariant is restored and we can stop the traversal.
            let mut any_change = false;
            for (_range, loc) in self.locations.iter_mut_all() {
                // Check if this node has a state for this location (or range of locations).
                if let Some(perm) = loc.perms.get_mut(current) {
                    // Update the per-location SIFA, recording if it changed.
                    any_change |=
                        perm.idempotent_foreign_access.ensure_no_stronger_than(strongest_allowed);
                }
            }
            // Now update `default_initial_idempotent_foreign_access`, which stores the default SIFA for not-yet-initialized locations.
            any_change |= current_node
                .default_initial_idempotent_foreign_access
                .ensure_no_stronger_than(strongest_allowed);

            if any_change {
                let Some(next) = self.nodes.get(current).unwrap().parent else {
                    // We have arrived at the root.
                    break;
                };
                current = next;
                continue;
            } else {
                break;
            }
        }
    }

    /// Checks whether a dead node can be replaced by its only child.
    /// If so, returns the index of said only child. If not, returns none.
    /// The caller iterates the dead tags directly, so `idx` is already known to be dead
    /// and there is no membership check — only the shape and permission conditions remain.
    fn can_be_replaced_by_single_child(&self, idx: UniIndex) -> bool {
        let node = self.nodes.get(idx).unwrap();
        // A root is never replaced by its children
        if node.parent.is_none() {
            return false;
        }
        // Must match single child case
        let [child_idx] = node.children[..] else { return false };

        // Check that for that one child, `can_be_replaced_by_child` holds for the permission
        // on all locations.
        let child = self.nodes.get(child_idx).unwrap();
        return self.locations.iter_all().all(|(_range, loc)| {
            let parent_perm =
                loc.perms.get(idx).map(|x| x.permission).unwrap_or(node.default_initial_perm);
            let child_perm = loc
                .perms
                .get(child_idx)
                .map(|x| x.permission)
                .unwrap_or(child.default_initial_perm);
            parent_perm.can_be_replaced_by_child(child_perm)
        });
    }

    /// Like [`Self::can_be_replaced_by_single_child`], but for a node with more than one
    /// child. This requires the stronger [`Permission::can_be_replaced_by_children`] check, and
    /// it must hold for every child at every location
    fn can_be_replaced_by_children(&self, global_ctx: &GlobalCtx, idx: UniIndex) -> bool {
        let node = self.nodes.get(idx).unwrap();
        // A root nor `ReservedIM` parent is never replaced
        let Some(parent_idx) = node.parent else { return false };
        if node.default_initial_perm.is_reserved_im() {
            return false;
        }

        // Check that the final compaction result would be within bounds
        let parent_width = self.nodes.get(parent_idx).unwrap().children.len();

        if parent_width + node.children.len() - 1 > global_ctx.flags.max_compacted_children {
            return false;
        }

        let children: SmallVec<[(UniIndex, Permission); 4]> = node
            .children
            .iter()
            .map(|&child_idx| (child_idx, self.nodes.get(child_idx).unwrap().default_initial_perm))
            .collect();
        self.locations.iter_all().all(|(_range, loc)| {
            let parent_perm =
                loc.perms.get(idx).map(|x| x.permission).unwrap_or(node.default_initial_perm);
            children.iter().all(|&(child_idx, child_default)| {
                let child_perm =
                    loc.perms.get(child_idx).map(|x| x.permission).unwrap_or(child_default);
                parent_perm.can_be_replaced_by_children(child_perm)
            })
        })
    }

    /// Properly removes a node.
    /// The node to be removed should not otherwise be usable. It also
    /// should have no children, but this is not checked, so that nodes
    /// whose children were rotated somewhere else can be deleted without
    /// having to first modify them to clear that array.
    fn remove_useless_node(&mut self, this: UniIndex) {
        // Due to the API of UniMap we must make sure to call
        // `UniValMap::remove` for the key of this node on *all* maps that used it
        // (which are `self.nodes` and every range of `self.rperms`)
        // before we can safely apply `UniKeyMap::remove` to truly remove
        // this tag from the `tag_mapping`.
        let node = self.nodes.remove(this).unwrap();
        for (_range, loc) in self.locations.iter_mut_all() {
            loc.perms.remove(this);
            loc.exposed_cache.remove(this);
        }
        self.tag_mapping.remove(&node.tag);
    }

    /// Removes from the tree the nodes for the given *dead* tags, wherever
    /// possible. See [`AllocState::remove_dead_tags`].
    ///
    /// This cleanup must be bottom-up; a dead node can only be deleted as a leaf once its
    /// dead descendants are gone, so we must process a node before its parent. Since
    /// borrow tags are distributed with a monotonic global counter, `dead_tags` is guaranteed
    /// to be sorted in ascending order. Since a child must be allocated after its parent,
    /// we maintain the following invariant: `child.tag > parent.tag`. Iterating through
    /// `dead_tags` in reverse gives a valid reverse-topological (bottom-up) traversal.
    ///
    /// Each entry in `dead_tags` is zeroed out (set to [`BorTag::omnivalid`]) once its tag
    /// no longer needs to be tracked: either the node was removed, or it is guaranteed to
    /// re-enter a zero-count table before it can next become prunable. Entries left nonzero
    /// are dead nodes that could not be pruned yet
    ///
    /// When `compact` is false, dead interior nodes are left in place (their entries stay
    /// nonzero) instead of being coalesced into their parent. Dead *leaves* are still
    /// removed unconditionally, so the pending set continues to drain and a tree that dies
    /// entirely still empties out. This lets small trees skip the per-location permission
    /// checks that compaction requires.
    ///
    /// Roots only ever leave the tree as leaves; a dead root with children is never
    /// replaced by them. Since a child's tag is always greater than its parent's,
    /// promoting a child into `self.roots` could break the ascending-tag order of
    /// `roots`, which [`LocationTree::perform_access`] and the wildcard consistency
    /// checks rely on. This retains at most one dead root per tree, and only until its
    /// subtree dies (or is compacted away), at which point it is removed as a leaf.
    fn remove_useless_children(
        &mut self,
        global_ctx: &GlobalCtx,
        dead_tags: &[BorTag],
        compact: bool,
    ) {
        // Iterating through dead_tags in reverse (descending tag order)
        for entry in dead_tags.iter().rev() {
            let tag = *entry;
            // A missing entry means the node was already removed; zero out the entry
            let Some(idx) = self.tag_mapping.get(&tag) else {
                continue;
            };

            let mut opt_parent_idx = {
                let node = self.nodes.get(idx).unwrap();
                if !(node.refcount.get() == 0 && !node.is_exposed) {
                    continue;
                }
                node.dead.set(true);
                node.parent
            };
            let mut attempt = self.try_remove_dead_node(global_ctx, idx, compact);
            while attempt
                && let Some(parent_idx) = opt_parent_idx
                && let Some(parent_node) = self.nodes.get(parent_idx)
                && parent_node.refcount.get() == 0
                && !parent_node.is_exposed
                && parent_node.dead.get()
            {
                opt_parent_idx = parent_node.parent;
                attempt = self.try_remove_dead_node(global_ctx, parent_idx, compact);
            }
        }
    }

    fn try_remove_dead_node(
        &mut self,
        global_ctx: &GlobalCtx,
        idx: UniIndex,
        compact: bool,
    ) -> bool {
        let node = self.nodes.get(idx).unwrap();

        // `parent` is an Option<UniIndex>: if it is None, then `node` is a root
        let parent = node.parent;

        // Branches are mutually exclusive on child count: `can_be_replaced_by_single_child`
        // only yields `Some` for exactly one child, and `can_be_replaced_by_children` only
        // holds for more than one, so we can dispatch on the number of children.
        match node.children.len() {
            // Node is a leaf
            0 => {
                // Drop the leaf from its parent's child list, then delete it everywhere else
                // If it is a root, remove it from `self.roots`
                match parent {
                    Some(parent_idx) => {
                        let children = &mut self.nodes.get_mut(parent_idx).unwrap().children;
                        let pos = children.iter().position(|&c| c == idx).unwrap();
                        children.swap_remove(pos);
                    }
                    None => {
                        let pos = self.roots.iter().position(|&r| r == idx).unwrap();
                        self.roots.remove(pos);
                    }
                }
                self.remove_useless_node(idx);
                true
            }
            // Node has exactly one child (and, per the guard above, a parent)
            1 if compact && self.can_be_replaced_by_single_child(idx) => {
                // Replace the node with its only child.
                let child_idx = node.children[0];
                let parent_idx = parent.unwrap();
                let siblings = &mut self.nodes.get_mut(parent_idx).unwrap().children;
                let pos = siblings.iter().position(|&c| c == idx).unwrap();
                siblings[pos] = child_idx;
                self.nodes.get_mut(child_idx).unwrap().parent = parent;
                self.remove_useless_node(idx);
                true
            }
            // Node has more than one child. If every child can soundly replace it, compact it
            // by reparenting all of its children onto its parent.
            _ if compact && self.can_be_replaced_by_children(global_ctx, idx) => {
                let parent_idx = parent.unwrap();
                // Move `idx`'s children out so we can reparent them
                let children = mem::take(&mut self.nodes.get_mut(idx).unwrap().children);
                // Point every grandchild at the grandparent.
                for i in 0..children.len() {
                    self.nodes.get_mut(children[i]).unwrap().parent = Some(parent_idx);
                }
                // Replace `idx` in the grandparent's child list with all of its children.
                let siblings = &mut self.nodes.get_mut(parent_idx).unwrap().children;
                let pos = siblings.iter().position(|&c| c == idx).unwrap();
                siblings.swap_remove(pos);
                for i in 0..children.len() {
                    siblings.push(children[i]);
                }
                self.remove_useless_node(idx);
                true
            }
            // A dead interior node on a tree too small to be worth compacting. Leave its
            // entry nonzero so the caller keeps it pending; it is removed as a leaf once
            // its subtree dies.
            _ => false,
        }
    }
}

impl LocationTree {
    /// Returns the smallest exposed tag, if any, that is a transitive child of `root`.
    fn get_min_exposed_child(root: UniIndex, nodes: &UniValMap<Node>) -> Option<BorTag> {
        // We cannot use the wildcard datastructure to improve this lookup. This is because
        // the datastructure only tracks enabled nodes and we need to also consider disabled ones.
        let mut stack = vec![root];
        let mut min_tag = None;
        while let Some(idx) = stack.pop() {
            let node = nodes.get(idx).unwrap();
            if min_tag.is_some_and(|min| min < node.tag) {
                // The minimum we found before is bigger than this tag, and therefore
                // also bigger than all its children, so we can skip this subtree.
                continue;
            }
            stack.extend_from_slice(node.children.as_slice());
            if node.is_exposed {
                min_tag = match min_tag {
                    Some(prev) if prev < node.tag => Some(prev),
                    _ => Some(node.tag),
                };
            }
        }
        min_tag
    }

    /// Performs an access on this location.
    /// * `access_source`: The index, if any, where the access came from.
    /// * `visit_children`: Whether to skip updating the children of `access_source`.
    /// * `min_exposed_child`: The tag of the smallest exposed (transitive) child of the accessed node.
    ///   This is only used with `visit_children == SkipChildrenOfAccessed`, where we need to skip children
    ///   of the accessed node.
    fn perform_access(
        &mut self,
        global_ctx: &GlobalCtx,
        roots: impl Iterator<Item = UniIndex>,
        nodes: &mut UniValMap<Node>,
        access_source: Option<UniIndex>,
        access_kind: AccessKind,
        visit_children: ChildrenVisitMode,
        diagnostics: &DiagnosticInfo,
        min_exposed_child: Option<BorTag>,
    ) -> UBResult<()> {
        let accessed_root = if let Some(idx) = access_source {
            Some(self.perform_normal_access(
                global_ctx,
                idx,
                nodes,
                access_kind,
                visit_children,
                diagnostics,
            )?)
        } else {
            // `SkipChildrenOfAccessed` only gets set on protector release, which only
            // occurs on a known node.
            assert!(matches!(visit_children, ChildrenVisitMode::VisitChildrenOfAccessed));
            None
        };

        let accessed_root_tag = accessed_root.map(|idx| nodes.get(idx).unwrap().tag);
        for (i, root) in roots.enumerate() {
            let tag = nodes.get(root).unwrap().tag;
            // On a protector release access we have to skip the children of the accessed tag.
            // However, if the tag has exposed children then some of the wildcard subtrees could
            // also be children of the accessed node and would also need to be skipped. We can
            // narrow down which wildcard trees might be children by comparing their root tag to the
            // minimum exposed child of the accessed node. As the parent tag is always smaller
            // than the child tag this means we only need to skip subtrees with a root tag larger
            // than `min_exposed_child`. Once we find such a root, we can leave the loop because roots
            // are sorted by tag.
            if matches!(visit_children, ChildrenVisitMode::SkipChildrenOfAccessed)
                && let Some(min_exposed_child) = min_exposed_child
                && tag > min_exposed_child
            {
                break;
            }
            // We don't perform a wildcard access on the tree we already performed a
            // normal access on.
            if Some(root) == accessed_root {
                continue;
            }
            // The choice of `max_local_tag` requires some thought.
            // This can only be a local access for nodes that are a parent of the accessed node
            // and are therefore smaller, so the accessed node itself is a valid choice for `max_local_tag`.
            // However, using `accessed_root` is better since that will be smaller. It is still a valid choice
            // because for nodes *in other trees*, if they are a parent of the accessed node then they
            // are a parent of `accessed_root`.
            //
            // As a consequence of this, since the root of the main tree is the smallest tag in the entire
            // allocation, if the access occurred in the main tree then other subtrees will only see foreign accesses.
            self.perform_wildcard_access(
                global_ctx,
                root,
                access_source,
                /*max_local_tag*/ accessed_root_tag,
                nodes,
                access_kind,
                diagnostics,
                /*is_wildcard_tree*/ i != 0,
            )?;
        }
        Ok(())
    }

    /// Performs a normal access on the tree containing `access_source`.
    ///
    /// Returns the root index of this tree.
    /// * `access_source`: The index of the tag being accessed.
    /// * `visit_children`: Whether to skip the children of `access_source`
    ///   during the access. Used for protector end access.
    fn perform_normal_access(
        &mut self,
        global_ctx: &GlobalCtx,
        access_source: UniIndex,
        nodes: &mut UniValMap<Node>,
        access_kind: AccessKind,
        visit_children: ChildrenVisitMode,
        diagnostics: &DiagnosticInfo,
    ) -> UBResult<UniIndex> {
        // Performs the per-node work:
        // - insert the permission if it does not exist
        // - perform the access
        // - record the transition
        // to which some optimizations are added:
        // - skip the traversal of the children in some cases
        // - do not record noop transitions
        //
        // `loc_range` is only for diagnostics (it is the range of
        // the `RangeMap` on which we are currently working).
        let node_skipper = |args: &NodeAppArgs<'_, LocationTree>| -> ContinueTraversal {
            let node = args.nodes.get(args.idx).unwrap();
            let perm = args.data.perms.get(args.idx);

            let old_state = perm.copied().unwrap_or_else(|| node.default_location_state());
            old_state.skip_if_known_noop(access_kind, args.rel_pos)
        };
        let mut visit_count: usize = 0;
        let node_app = |args: NodeAppArgs<'_, LocationTree>| {
            visit_count += 1;
            let node = args.nodes.get_mut(args.idx).unwrap();
            let mut perm = args.data.perms.entry(args.idx);

            let state = perm.or_insert(node.default_location_state());

            let protected = node.protector_kind.is_some();
            state
                .perform_transition(
                    global_ctx,
                    args.idx,
                    args.nodes,
                    &mut args.data.exposed_cache,
                    access_kind,
                    args.rel_pos,
                    protected,
                    diagnostics,
                )
                .map_err(|error_kind| {
                    let accessed = args.nodes.get(access_source).unwrap();
                    let conflicting = args.nodes.get(args.idx).unwrap();
                    TbError {
                        error_kind,
                        access_info: diagnostics,
                        conflicting_node: conflicting.error_node(),
                        accessed_node: Some(accessed.error_node()),
                    }
                    .build()
                })
        };

        let visitor = TreeVisitor { nodes, data: self };
        let result = match visit_children {
            ChildrenVisitMode::VisitChildrenOfAccessed => visitor
                .traverse_this_parents_children_other(access_source, node_skipper, node_app)
                .map_err(|e| e.into()),
            ChildrenVisitMode::SkipChildrenOfAccessed => visitor
                .traverse_nonchildren(access_source, node_skipper, node_app)
                .map_err(|e| e.into()),
        };
        unsafe {
            crate::sanitizer_common::__bsan_visits_since_gc
                .fetch_add(visit_count, core::sync::atomic::Ordering::Relaxed);
        }
        result
    }

    /// Performs a wildcard access on the tree with root `root`. Takes the `access_relatedness`
    /// for each node from the `WildcardState` datastructure.
    /// * `root`: Root of the tree being accessed.
    /// * `access_source`: the index of the accessed tag, if any.
    ///   This is only used for printing the correct tag on errors.
    /// * `max_local_tag`: The access can only be local for nodes whose tag is
    ///   at most `max_local_tag`.
    fn perform_wildcard_access(
        &mut self,
        global_ctx: &GlobalCtx,
        root: UniIndex,
        access_source: Option<UniIndex>,
        max_local_tag: Option<BorTag>,
        nodes: &mut UniValMap<Node>,
        access_kind: AccessKind,
        diagnostics: &DiagnosticInfo,
        is_wildcard_tree: bool,
    ) -> UBResult<()> {
        let get_relatedness = |idx: UniIndex, node: &Node, loc: &LocationTree| {
            // If the tag is larger than `max_local_tag` then the access can only be foreign.
            let only_foreign = max_local_tag.is_some_and(|max_local_tag| max_local_tag < node.tag);
            loc.exposed_cache.access_relatedness(
                root,
                idx,
                access_kind,
                is_wildcard_tree,
                only_foreign,
            )
        };

        // Whether there is an exposed node in this tree that allows this access.
        let mut has_valid_exposed = false;
        let mut visit_count: usize = 0;

        // This does a traversal across the tree updating children before their parents. The
        // difference to `perform_normal_access` is that we take the access relatedness from
        // the wildcard tracking state of the node instead of from the visitor itself.
        //
        // Unlike for a normal access, the iteration order is important for improving the
        // accuracy of wildcard accesses if `max_local_tag` is `Some`: processing the effects of this
        // access further down the tree can cause exposed nodes to lose permissions, thus updating
        // the wildcard data structure, which will be taken into account when processing the parent
        // nodes. Also see the test `cross_tree_update_older_invalid_exposed2.rs`
        // (Doing accesses in the opposite order cannot help with precision but the reasons are complicated;
        // see <https://github.com/rust-lang/miri/pull/4707#discussion_r2581661123>.)
        //
        // Note, however, that this is an approximation: there can be situations where a node is
        // marked as having an exposed foreign node, but actually that foreign node cannot be
        // the source of the access due to `max_local_tag`. The wildcard tracking cannot know
        // about `max_local_tag` so we will incorrectly assume that this might be a foreign access.
        TreeVisitor { data: self, nodes }.traverse_children_this(
            root,
            |args| -> ContinueTraversal {
                let node = args.nodes.get(args.idx).unwrap();
                let perm = args.data.perms.get(args.idx);

                let old_state = perm.copied().unwrap_or_else(|| node.default_location_state());
                // If we know where, relative to this node, the wildcard access occurs,
                // then check if we can skip the entire subtree.
                if let Some(relatedness) = get_relatedness(args.idx, node, args.data)
                    && let Some(relatedness) = relatedness.to_relatedness()
                {
                    // We can use the usual SIFA machinery to skip nodes.
                    old_state.skip_if_known_noop(access_kind, relatedness)
                } else {
                    ContinueTraversal::Recurse
                }
            },
            |args| {
                visit_count += 1;
                let node = args.nodes.get_mut(args.idx).unwrap();

                let protected = node.protector_kind.is_some();

                let Some(wildcard_relatedness) = get_relatedness(args.idx, node, args.data) else {
                    // There doesn't exist a valid exposed reference for this access to
                    // happen through.
                    // This can only happen if `root` is the main root: We set
                    // `max_foreign_access==Write` on all wildcard roots, so at least a foreign access
                    // is always possible on all nodes in a wildcard subtree.
                    return Err(no_valid_exposed_references_error(diagnostics));
                };

                let mut entry = args.data.perms.entry(args.idx);
                let perm = entry.or_insert(node.default_location_state());

                // We only count exposed nodes through which an access could happen.
                if node.is_exposed
                    && perm.permission.strongest_allowed_local_access(protected).allows(access_kind)
                    && max_local_tag.is_none_or(|max_local_tag| max_local_tag >= node.tag)
                {
                    has_valid_exposed = true;
                }

                let Some(relatedness) = wildcard_relatedness.to_relatedness() else {
                    // If the access type is Either, then we do not apply any transition
                    // to this node, but we still update each of its children.
                    // This is an imprecision! In the future, maybe we can still do some sort
                    // of best-effort update here.
                    return Ok(());
                };

                // We know the exact relatedness, so we can actually do precise checks.
                perm.perform_transition(
                    global_ctx,
                    args.idx,
                    args.nodes,
                    &mut args.data.exposed_cache,
                    access_kind,
                    relatedness,
                    protected,
                    diagnostics,
                )
                .map_err(|trans| {
                    let conflicting = args.nodes.get(args.idx).unwrap();
                    TbError {
                        error_kind: trans,
                        access_info: diagnostics,
                        conflicting_node: conflicting.error_node(),
                        accessed_node: access_source
                            .map(|idx| args.nodes.get(idx).unwrap().error_node()),
                    }
                    .build()
                })
            },
        )?;
        unsafe {
            crate::sanitizer_common::__bsan_visits_since_gc
                .fetch_add(visit_count, core::sync::atomic::Ordering::Relaxed);
        }
        // If there is no exposed node in this tree that allows this access, then the access *must*
        // be foreign to the entire subtree. Foreign accesses are only possible on wildcard subtrees
        // as there are no ancestors to the main root. So if we do not find a valid exposed node in
        // the main tree then this access is UB.
        if !has_valid_exposed && !is_wildcard_tree {
            return Err(no_valid_exposed_references_error(diagnostics).into());
        }
        Ok(())
    }
}
/// The public interface shared by all tree implementations.
/// Consumers outside this module interact with the tree exclusively
/// through this trait; the underlying implementations are
/// module-private.
pub trait AllocState: Clone {
    fn get_protector_kind(&self, tag: BorTag) -> Option<ProtectorKind>;
    fn contains_tag(&self, tag: BorTag) -> bool;
    fn node_count(&self) -> usize;
    fn increment(&self, tag: BorTag) -> bool;
    fn decrement(&self, tag: BorTag) -> bool;
    fn new_child(
        &mut self,
        base_offset: Size,
        parent_tag: BorTag,
        new_tag: BorTag,
        inside_perms: DedupRangeMap<LocationState>,
        outside_perm: Permission,
        protector: Option<ProtectorKind>,
        span: Span,
    ) -> UBResult<()>;
    fn perform_access(
        &mut self,
        global_ctx: &GlobalCtx,
        tag: BorTag,
        access_range: AllocRange,
        access_kind: AccessKind,
        access_cause: AccessCause,
        alloc_id: AllocId,
        span: Span,
    ) -> UBResult<()>;
    fn dealloc(
        &mut self,
        global_ctx: &GlobalCtx,
        tag: BorTag,
        access_range: AllocRange,
        alloc_id: AllocId,
        span: Span,
    ) -> UBResult<()>;
    fn perform_protector_end_access(
        &mut self,
        global_ctx: &GlobalCtx,
        tag: BorTag,
        alloc_id: AllocId,
        span: Span,
    ) -> UBResult<()>;
    fn expose_tag(&mut self, tag: BorTag, protected: bool);

    fn remove_dead_tags(&mut self, global_ctx: &GlobalCtx, dead_tags: &[BorTag]) -> bool;
}

impl AllocState for LazyTree {
    fn contains_tag(&self, tag: BorTag) -> bool {
        match self {
            LazyTree::Uninit { root_tag, .. } => *root_tag == tag,
            LazyTree::Init(tree) => tree.tag_mapping.contains_key(&tag),
        }
    }
    fn node_count(&self) -> usize {
        match self {
            LazyTree::Uninit { .. } => 1,
            LazyTree::Init(tree) => tree.tag_mapping.len(),
        }
    }
    fn new_child(
        &mut self,
        base_offset: Size,
        parent_tag: BorTag,
        new_tag: BorTag,
        inside_perms: DedupRangeMap<LocationState>,
        outside_perm: Permission,
        protector: Option<ProtectorKind>,
        span: Span,
    ) -> UBResult<()> {
        self.ensure_init();
        let LazyTree::Init(tree) = self else { unreachable!() };
        tree.new_child(
            base_offset,
            parent_tag,
            new_tag,
            inside_perms,
            outside_perm,
            protector,
            span,
        )
    }
    fn perform_access(
        &mut self,
        global_ctx: &GlobalCtx,

        tag: BorTag,
        access_range: AllocRange,
        access_kind: AccessKind,
        access_cause: AccessCause,
        alloc_id: AllocId,
        span: Span,
    ) -> UBResult<()> {
        match self {
            LazyTree::Uninit { .. } => Ok(()),
            LazyTree::Init(tree) => tree.perform_access(
                global_ctx,
                tag,
                access_range,
                access_kind,
                access_cause,
                alloc_id,
                span,
            ),
        }
    }
    fn dealloc(
        &mut self,
        global_ctx: &GlobalCtx,
        tag: BorTag,
        access_range: AllocRange,
        alloc_id: AllocId,
        span: Span,
    ) -> UBResult<()> {
        match self {
            LazyTree::Uninit { .. } => Ok(()),
            LazyTree::Init(tree) => tree.dealloc(global_ctx, tag, access_range, alloc_id, span),
        }
    }
    fn perform_protector_end_access(
        &mut self,
        global_ctx: &GlobalCtx,

        tag: BorTag,
        alloc_id: AllocId,
        span: Span,
    ) -> UBResult<()> {
        match self {
            LazyTree::Uninit { .. } => Ok(()),
            LazyTree::Init(tree) => {
                tree.perform_protector_end_access(global_ctx, tag, alloc_id, span)
            }
        }
    }
    fn expose_tag(&mut self, tag: BorTag, protected: bool) {
        self.ensure_init();
        if let LazyTree::Init(tree) = self {
            tree.expose_tag(tag, protected);
        }
    }
    fn remove_dead_tags(&mut self, global_ctx: &GlobalCtx, dead_tags: &[BorTag]) -> bool {
        match self {
            LazyTree::Init(tree) => {
                // Only *compaction* of dead interior nodes is skipped on small trees
                let compact = tree.tag_mapping.len() > global_ctx.flags.tree_gc_min_nodes;
                tree.remove_useless_children(global_ctx, dead_tags, compact);
                tree.locations.merge_adjacent_thorough();
                tree.roots.is_empty()
            }
            LazyTree::Uninit { root_tag, refcount, .. } => {
                // A tree in the Uninit state only has a single node (the root). If
                // this node is in the dead list with a zero reference count, then the
                // tree is dead and the associated AllocInfo metadata can be freed.
                let root_is_dead = refcount.get() == 0 && dead_tags.contains(root_tag);
                root_is_dead
            }
        }
    }
    fn increment(&self, tag: BorTag) -> bool {
        match self {
            LazyTree::Uninit { root_tag, refcount, .. } => {
                if *root_tag == tag {
                    refcount.increment_nonatomic()
                } else {
                    false
                }
            }
            LazyTree::Init(tree) => tree.increment(tag),
        }
    }
    fn decrement(&self, tag: BorTag) -> bool {
        match self {
            LazyTree::Uninit { root_tag, refcount, .. } => {
                if *root_tag == tag {
                    refcount.decrement_nonatomic()
                } else {
                    false
                }
            }
            LazyTree::Init(tree) => tree.decrement(tag),
        }
    }

    fn get_protector_kind(&self, tag: BorTag) -> Option<ProtectorKind> {
        match self {
            LazyTree::Uninit { .. } => None,
            LazyTree::Init(tree) => tree.get_protector_kind(tag),
        }
    }
}

impl AllocState for EagerTree {
    fn contains_tag(&self, tag: BorTag) -> bool {
        self.tag_mapping.contains_key(&tag)
    }
    fn node_count(&self) -> usize {
        self.tag_mapping.len()
    }
    fn new_child(
        &mut self,
        base_offset: Size,
        parent_tag: BorTag,
        new_tag: BorTag,
        inside_perms: DedupRangeMap<LocationState>,
        outside_perm: Permission,
        protector: Option<ProtectorKind>,
        span: Span,
    ) -> UBResult<()> {
        let protected = protector.is_some();
        let idx = self.tag_mapping.insert(new_tag);
        let parent_idx = if parent_tag.is_wildcard() {
            None
        } else {
            Some(self.tag_mapping.get(&parent_tag).unwrap())
        };
        assert!(outside_perm.is_initial());

        let default_strongest_idempotent =
            outside_perm.strongest_idempotent_foreign_access(protected);
        self.nodes.insert(
            idx,
            Node {
                tag: new_tag,
                parent: parent_idx,
                children: SmallVec::default(),
                default_initial_perm: outside_perm,
                default_initial_idempotent_foreign_access: default_strongest_idempotent,
                is_exposed: false,
                dead: Cell::new(false),
                protector_kind: protector,
                refcount: RefCount::new(),
                debug_info: NodeDebugInfo::new(new_tag, outside_perm, span),
            },
        );
        if let Some(parent_idx) = parent_idx {
            let parent_node = self.nodes.get_mut(parent_idx).unwrap();
            parent_node.children.push(idx);
        } else {
            self.roots.push(idx);
        }

        let mut min_sifa = default_strongest_idempotent;
        for (Range { start, end }, &perm) in
            inside_perms.iter(Size::from_bytes(0), inside_perms.size())
        {
            assert!(perm.permission.is_initial());
            assert_eq!(
                perm.idempotent_foreign_access,
                perm.permission.strongest_idempotent_foreign_access(protected)
            );

            min_sifa = cmp::min(min_sifa, perm.idempotent_foreign_access);
            for (_range, loc) in self
                .locations
                .iter_mut(Size::from_bytes(start) + base_offset, Size::from_bytes(end - start))
            {
                loc.perms.insert(idx, perm);
            }
        }

        if let Some(parent_idx) = parent_idx {
            self.update_idempotent_foreign_access_after_retag(parent_idx, min_sifa);
        }

        Ok(())
    }
    fn perform_access(
        &mut self,
        global_ctx: &GlobalCtx,
        tag: BorTag,
        access_range: AllocRange,
        access_kind: AccessKind,
        access_cause: AccessCause,
        alloc_id: AllocId,
        span: Span,
    ) -> UBResult<()> {
        #[cfg(feature = "expensive-consistency-checks")]
        if self.roots.len() > 1 || matches!(prov, ProvenanceExtra::Wildcard) {
            self.verify_wildcard_consistency(global);
        }

        let source_idx =
            if tag.is_wildcard() { None } else { Some(self.tag_mapping.get(&tag).unwrap()) };

        for (loc_range, loc) in self.locations.iter_mut(access_range.start, access_range.size) {
            let diagnostics = DiagnosticInfo {
                access_cause,
                access_range: Some(access_range),
                alloc_id,
                span,
                transition_range: loc_range,
            };
            loc.perform_access(
                global_ctx,
                self.roots.iter().copied(),
                &mut self.nodes,
                source_idx,
                access_kind,
                ChildrenVisitMode::VisitChildrenOfAccessed,
                &diagnostics,
                /* min_exposed_child */ None,
            )?;
        }
        Ok(())
    }
    fn dealloc(
        &mut self,
        global_ctx: &GlobalCtx,
        tag: BorTag,
        access_range: AllocRange,
        alloc_id: AllocId,
        span: Span,
    ) -> UBResult<()> {
        self.perform_access(
            global_ctx,
            tag,
            access_range,
            AccessKind::Write,
            AccessCause::Dealloc,
            alloc_id,
            span,
        )?;

        let start_idx =
            if tag.is_wildcard() { None } else { Some(self.tag_mapping.get(&tag).unwrap()) };

        for (loc_range, loc) in self.locations.iter_mut(access_range.start, access_range.size) {
            let diagnostics = DiagnosticInfo {
                alloc_id,
                span,
                transition_range: loc_range,
                access_range: Some(access_range),
                access_cause: AccessCause::Dealloc,
            };
            let mut check_tree = |idx| {
                TreeVisitor { nodes: &mut self.nodes, data: loc }
                    .traverse_this_parents_children_other(
                        idx,
                        |_| ContinueTraversal::Recurse,
                        |args: NodeAppArgs<'_, _>| {
                            let node = args.nodes.get(args.idx).unwrap();

                            let perm = args
                                .data
                                .perms
                                .get(args.idx)
                                .copied()
                                .unwrap_or_else(|| node.default_location_state());
                            if node.protector_kind == Some(ProtectorKind::StrongProtector)
                                && !perm.permission.is_cell()
                                && perm.accessed
                            {
                                Err(TbError {
                                    error_kind: TransitionError::ProtectedDealloc,
                                    access_info: &diagnostics,
                                    conflicting_node: node.error_node(),
                                    accessed_node: start_idx
                                        .map(|idx| args.nodes.get(idx).unwrap().error_node()),
                                }
                                .build())
                            } else {
                                Ok(())
                            }
                        },
                    )
            };
            let accessed_root = start_idx.map(&mut check_tree).transpose()?;
            for &root in self.roots.iter().rev() {
                if Some(root) == accessed_root {
                    continue;
                }
                check_tree(root)?;
            }
        }
        Ok(())
    }
    fn perform_protector_end_access(
        &mut self,
        global_ctx: &GlobalCtx,
        tag: BorTag,
        alloc_id: AllocId,
        span: Span,
    ) -> UBResult<()> {
        #[cfg(feature = "expensive-consistency-checks")]
        if self.roots.len() > 1 {
            self.verify_wildcard_consistency(global);
        }

        let source_idx = self.tag_mapping.get(&tag).unwrap();

        let min_exposed_child = if self.roots.len() > 1 {
            LocationTree::get_min_exposed_child(source_idx, &self.nodes)
        } else {
            None
        };

        for (loc_range, loc) in self.locations.iter_mut_all() {
            if let Some(p) = loc.perms.get(source_idx)
                && let Some(access_kind) = p.permission.protector_end_access()
                && p.accessed
            {
                let diagnostics = DiagnosticInfo {
                    access_cause: AccessCause::FnExit(access_kind),
                    access_range: None,
                    alloc_id,
                    span,
                    transition_range: loc_range,
                };
                loc.perform_access(
                    global_ctx,
                    self.roots.iter().copied(),
                    &mut self.nodes,
                    Some(source_idx),
                    access_kind,
                    ChildrenVisitMode::SkipChildrenOfAccessed,
                    &diagnostics,
                    min_exposed_child,
                )?;
            }
        }

        // If the tag is exposed, then the wildcard tracking state needs to
        // reflect that it is no longer protected: accesses that were UB while
        // the protector was active may be permitted again.
        self.update_exposure_for_protector_release(tag);

        // Remove the protector from the node.
        let node = self.nodes.get_mut(source_idx).unwrap();
        node.protector_kind = None;

        Ok(())
    }

    fn expose_tag(&mut self, tag: BorTag, protected: bool) {
        let id = self.tag_mapping.get(&tag).unwrap();
        let node = self.nodes.get_mut(id).unwrap();
        if !node.is_exposed {
            node.is_exposed = true;
            let node = self.nodes.get(id).unwrap();

            for (_, loc) in self.locations.iter_mut_all() {
                let perm = loc
                    .perms
                    .get(id)
                    .map(|p| p.permission())
                    .unwrap_or_else(|| node.default_location_state().permission());

                let access_level = perm.strongest_allowed_local_access(protected);
                loc.exposed_cache.update_exposure(
                    &self.nodes,
                    id,
                    WildcardAccessLevel::None,
                    access_level,
                );
            }
        }
    }

    fn remove_dead_tags(&mut self, global_ctx: &GlobalCtx, dead_tags: &[BorTag]) -> bool {
        // Only *compaction* of dead interior nodes is skipped on small trees
        let compact = self.tag_mapping.len() > global_ctx.flags.tree_gc_min_nodes;
        self.remove_useless_children(global_ctx, dead_tags, compact);
        self.locations.merge_adjacent_thorough();
        self.roots.is_empty()
    }
    fn increment(&self, tag: BorTag) -> bool {
        self.tag_mapping
            .get(&tag)
            .and_then(|idx| self.nodes.get(idx))
            .map(|node| node.refcount.increment_nonatomic())
            .unwrap_or(false)
    }
    fn decrement(&self, tag: BorTag) -> bool {
        self.tag_mapping
            .get(&tag)
            .and_then(|idx| self.nodes.get(idx))
            .map(|node| node.refcount.decrement_nonatomic())
            .unwrap_or(false)
    }

    fn get_protector_kind(&self, tag: BorTag) -> Option<ProtectorKind> {
        self.tag_mapping
            .get(&tag)
            .and_then(|idx| self.nodes.get(idx))
            .and_then(|node| node.protector_kind)
    }
}
