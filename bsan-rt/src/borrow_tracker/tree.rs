// Half implemented Tree for use in diagnostics

use alloc::vec::Vec;
use core::fmt;

use bsan_shared::*;

use super::unimap::*;
use super::*;
use crate::diagnostics::{NodeDebugInfo, TransitionError};
use crate::{BorTag, BsanAllocHooks};

/// Whether to continue exploring the children recursively or not.
enum ContinueTraversal {
    Recurse,
    SkipSelfAndChildren,
}

/// Data for a single *location*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocationState {
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

impl LocationState {
    /// Constructs a new initial state. It has neither been accessed, nor been subjected
    /// to any foreign access yet.
    /// The permission is not allowed to be `Active`.
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
    pub fn is_accessed(&self) -> bool {
        self.accessed
    }

    /// Check if the state can exist as the initial permission of a pointer.
    ///
    /// Do not confuse with `is_accessed`, the two are almost orthogonal
    /// as apart from `Active` which is not initial and must be accessed,
    /// any other permission can have an arbitrary combination of being
    /// initial/accessed.
    /// FIXME: when the corresponding `assert` in `tree_borrows/mod.rs` finally
    /// passes and can be uncommented, remove this `#[allow(dead_code)]`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_initial(&self) -> bool {
        self.permission.is_initial()
    }

    pub fn permission(&self) -> Permission {
        self.permission
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
                // It's a theorem that `Frozen` nodes have no active children, so all children
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
    /// shoud be called on foreign accesses for increased performance. It should not be called
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

/// Tree structure with both parents and children since we want to be
/// able to traverse the tree efficiently in both directions.
#[derive(Clone, Debug)]
pub struct Tree {
    /// Mapping from tags to keys. The key obtained can then be used in
    /// any of the `UniValMap` relative to this allocation, i.e. both the
    /// `nodes` and `rperms` of the same `Tree`.
    /// The parent-child relationship in `Node` is encoded in terms of these same
    /// keys, so traversing the entire tree needs exactly one access to
    /// `tag_mapping`.
    // TODO: Validate whether this is the correct use of
    pub tag_mapping: UniKeyMap<BorTag, BsanAllocHooks>,
    /// All nodes of this tree.
    pub nodes: UniValMap<Node>,
    /// Maps a tag and a location to a perm, with possible lazy
    /// initialization.
    ///
    /// NOTE: not all tags registered in `nodes` are necessarily in all
    /// ranges of `rperms`, because `rperms` is in part lazily initialized.
    /// Just because `nodes.get(key)` is `Some(_)` does not mean you can safely
    /// `unwrap` any `perm.get(key)`.
    ///
    /// We do uphold the fact that `keys(perms)` is a subset of `keys(nodes)`
    pub rperms: RangeMap<UniValMap<LocationState>>,
    /// The index of the root node.
    pub root: UniIndex,
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
    // miri: FIXME: bench to compare this to FxHashSet and to other SmallVec sizes
    // Miri's implementation uses SmallVec as an optimization, can later be discussed for
    // bsan if needed as an optimization.
    pub children: Vec<[UniIndex; 4]>,
    /// Either `Reserved`,  `Frozen`, or `Disabled`, it is the permission this tag will
    /// lazily be initialized to on the first access.
    /// It is only ever `Disabled` for a tree root, since the root is initialized to `Active` by
    /// its own separate mechanism.
    default_initial_perm: Permission,
    /// The default initial (strongest) idempotent foreign access.
    /// This participates in the invariant for `LocationState::idempotent_foreign_access`
    /// in cases where there is no location state yet. See `foreign_access_skipping.rs`,
    /// and `LocationState::idempotent_foreign_access` for more information
    default_initial_idempotent_foreign_access: IdempotentForeignAccess,
    /// Some extra information useful only for debugging purposes
    pub debug_info: NodeDebugInfo,
}
