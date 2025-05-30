use core::cmp::Ordering;
use core::cmp::Ordering::*;

use super::foreign_access_skipping::*;
use super::helpers::{AccessKind, AccessRelatedness};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RetagInfo {
    pub size: usize,
    pub perm_kind: Permission,
    pub protector_kind: ProtectorKind,
}

impl RetagInfo {
    #[inline]
    pub fn new(size: usize, perm_kind: Permission, protector_kind: ProtectorKind) -> Self {
        Self { size, perm_kind, protector_kind }
    }

    pub unsafe fn from_raw(size: usize, perm_kind: u8, protector_kind: u8) -> Self {
        let perm_kind = unsafe { Permission::from_raw(perm_kind) };
        let protector_kind = unsafe { ProtectorKind::from_raw(protector_kind) };
        Self::new(size, perm_kind, protector_kind)
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectorKind {
    NoProtector,
    /// Protected against aliasing violations from other pointers.
    ///
    /// Items protected like this cause UB when they are invalidated, *but* the pointer itself may
    /// still be used to issue a deallocation.
    ///
    /// This is required for LLVM IR pointers that are `noalias` but *not* `dereferenceable`.
    WeakProtector,

    /// Protected against any kind of invalidation.
    ///
    /// Items protected like this cause UB when they are invalidated or the memory is deallocated.
    /// This is strictly stronger protection than `WeakProtector`.
    ///
    /// This is required for LLVM IR pointers that are `dereferenceable` (and also allows `noalias`).
    StrongProtector,
}

impl ProtectorKind {
    unsafe fn from_raw(protector_kind: u8) -> Self {
        unsafe { core::mem::transmute::<u8, ProtectorKind>(protector_kind) }
    }
}

/// The activation states of a pointer.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PermissionPriv {
    /// represents: a local mutable reference that has not yet been written to;
    /// allows: child reads, foreign reads;
    /// affected by: child writes (becomes Active),
    /// rejects: foreign writes (Disabled).
    ///
    /// `ReservedFrz` is mostly for types that are `Freeze` (no interior mutability).
    /// If the type has interior mutability, see `ReservedIM` instead.
    /// (Note: since the discovery of `tests/fail/tree_borrows/reservedim_spurious_write.rs`,
    /// we also use `ReservedFreeze` for mutable references that were retagged with a protector
    /// independently of interior mutability)
    ///
    /// special case: beuse self::PermissionPriv::*;haves differently when protected, which is where `conflicted`
    /// is relevant
    /// - `conflicted` is set on foreign reads,
    /// - `conflicted` must not be set on child writes (there is UB otherwise).
    ///
    /// This is so that the behavior of `Reserved` adheres to the rules of `noalias`:
    /// - foreign-read then child-write is UB due to `conflicted`,
    /// - child-write then foreign-read is UB since child-write will activate and then
    ///   foreign-read disables a protected `Active`, which is UB.
    ReservedFrz,

    #[allow(dead_code)]
    ReservedFrzConf,
    /// Alternative version of `ReservedFrz` made for types with interior mutability.
    /// allows: child reads, foreign reads, foreign writes (extra);
    /// affected by: child writes (becomes Active);
    /// rejects: nothing.
    ReservedIM,
    /// represents: a unique pointer;
    /// allows: child reads, child writes;
    /// rejects: foreign reads (Frozen), foreign writes (Disabled).
    Active,
    /// represents: a shared pointer;
    /// allows: all read accesses;
    /// rejects child writes (UB), foreign writes (Disabled).
    Frozen,
    /// represents: a dead pointer;
    /// allows: all foreign accesses;
    /// rejects: all child accesses (UB).
    Disabled,
}
use self::PermissionPriv::*;

impl PartialOrd for PermissionPriv {
    /// PermissionPriv is ordered by the reflexive transitive closure of
    /// `Reserved(conflicted=false) < Reserved(conflicted=true) < Active < Frozen < Disabled`.
    /// `Reserved` that have incompatible `ty_is_freeze` are incomparable to each other.
    /// This ordering matches the reachability by transitions, as asserted by the exhaustive test
    /// `permissionpriv_partialord_is_reachability`.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(match (self, other) {
            (a, b) if a == b => Equal,
            (Disabled, _) => Greater,
            (_, Disabled) => Less,
            (Frozen, _) => Greater,
            (_, Frozen) => Less,
            (Active, _) => Greater,
            (_, Active) => Less,
            (ReservedIM, ReservedIM) => Equal,
            (ReservedFrz, ReservedFrz) => Equal,
            (ReservedFrzConf, ReservedFrzConf) => Equal,
            (ReservedFrz, ReservedFrzConf) => Less,
            // Versions of `Reserved` with different interior mutability are incomparable with each
            // other.
            (ReservedFrzConf, ReservedFrz) => Greater,
            (ReservedIM, ReservedFrz) | (ReservedFrz, ReservedIM) => return None,
            (ReservedIM, ReservedFrzConf) | (ReservedFrzConf, ReservedIM) => return None,
        })
    }
}

impl PermissionPriv {
    /// Check if `self` can be the initial state of a pointer.
    fn is_initial(&self) -> bool {
        matches!(self, ReservedFrz | Frozen | ReservedIM)
    }

    /// Reject `ReservedIM` that cannot exist in the presence of a protector.
    fn compatible_with_protector(&self) -> bool {
        !matches!(self, ReservedIM)
    }

    /// See `foreign_access_skipping.rs`. Computes the SIFA of a permission.
    fn strongest_idempotent_foreign_access(&self, prot: bool) -> IdempotentForeignAccess {
        match self {
            // A protected non-conflicted Reserved will become conflicted under a foreign read,
            // and is hence not idempotent under it.
            // Otherwise, foreign reads do not affect Reserved
            ReservedFrz => {
                if prot {
                    return IdempotentForeignAccess::None;
                }

                IdempotentForeignAccess::Read
            }
            // Famously, ReservedIM survives foreign writes. It is never protected.
            ReservedIM if prot => unreachable!("Protected ReservedIM should not exist!"),
            ReservedIM => IdempotentForeignAccess::Write,
            // Active changes on any foreign access (becomes Frozen/Disabled).
            Active => IdempotentForeignAccess::None,
            // Frozen survives foreign reads, but not writes.
            Frozen => IdempotentForeignAccess::Read,
            // Disabled survives foreign reads and writes. It survives them
            // even if protected, because a protected `Disabled` is not initialized
            // and does therefore not trigger UB.
            Disabled => IdempotentForeignAccess::Write,

            _ => IdempotentForeignAccess::None,
        }
    }
}
/// This module controls how each permission individually reacts to an access.
/// Although these functions take `protected` as an argument, this is NOT because
/// we check protector violations here, but because some permissions behave differently
/// when protected.
mod transition {
    use super::*;
    /// A child node was read-accessed: UB on Disabled, noop on the rest.
    fn child_read(state: PermissionPriv, _protected: bool) -> Option<PermissionPriv> {
        Some(match state {
            Disabled => return None,
            // The inner data `ty_is_freeze` of `Reserved` is always irrelevant for Read
            // accesses, since the data is not being mutated. Hence the `{ .. }`.
            readable @ (ReservedFrz | ReservedFrzConf | ReservedIM | Active | Frozen) => readable,
        })
    }

    /// A non-child node was read-accessed: keep `Reserved` but mark it as `conflicted` if it
    /// is protected; invalidate `Active`.
    fn foreign_read(state: PermissionPriv, protected: bool) -> Option<PermissionPriv> {
        Some(match state {
            // Non-writeable states just ignore foreign reads.
            non_writeable @ (Frozen | Disabled) => non_writeable,
            // Writeable states are more tricky, and depend on whether things are protected.
            // The inner data `ty_is_freeze` of `Reserved` is always irrelevant for Read
            // accesses, since the data is not being mutated. Hence the `{ .. }`

            // Someone else read. To make sure we won't write before function exit,
            // we set the "conflicted" flag, which will disallow writes while we are protected.
            ReservedFrz if protected => ReservedFrzConf,
            // Before activation and without protectors, foreign reads are fine.
            // That's the entire point of 2-phase borrows.
            res @ (ReservedFrz | ReservedIM) => {
                // Even though we haven't checked `ReservedIM if protected` separately,
                // it is a state that cannot occur because under a protector we only
                // create `ReservedFrz` never `ReservedIM`.
                assert!(!protected);
                res
            }
            Active => {
                if protected {
                    // We wrote, someone else reads -- that's bad.
                    // (Since Active is always initialized, this move-to-protected will mean insta-UB.)
                    Disabled
                } else {
                    // We don't want to disable here to allow read-read reordering: it is crucial
                    // that the foreign read does not invalidate future reads through this tag.
                    Frozen
                }
            }
            // TODO: Verify behavior
            _ => return None,
        })
    }

    /// A child node was write-accessed: `Reserved` must become `Active` to obtain
    /// write permissions, `Frozen` and `Disabled` cannot obtain such permissions and produce UB.
    fn child_write(state: PermissionPriv, protected: bool) -> Option<PermissionPriv> {
        Some(match state {
            // If the `conflicted` flag is set, then there was a foreign read during
            // the function call that is still ongoing (still `protected`),
            // this is UB (`noalias` violation).
            ReservedFrzConf if protected => return None,
            // A write always activates the 2-phase borrow, even with interior
            // mutability
            ReservedFrz | ReservedIM | Active => Active,
            Frozen | Disabled => return None,
            // TODO: Verify validity of this behavior
            _ => return None,
        })
    }

    /// A non-child node was write-accessed: this makes everything `Disabled` except for
    /// non-protected interior mutable `Reserved` which stay the same.
    fn foreign_write(state: PermissionPriv, protected: bool) -> Option<PermissionPriv> {
        // There is no explicit dependency on `protected`, but recall that interior mutable
        // types receive a `ReservedFrz` instead of `ReservedIM` when retagged under a protector,
        // so the result of this function does indirectly depend on (past) protector status.
        Some(match state {
            res @ ReservedIM => {
                // We can never create a `ReservedIM` under a protector, only `ReservedFrz`.
                assert!(!protected);
                res
            }
            _ => Disabled,
        })
    }

    /// Dispatch handler depending on the kind of access and its position.
    pub(super) fn perform_access(
        kind: AccessKind,
        rel_pos: AccessRelatedness,
        child: PermissionPriv,
        protected: bool,
    ) -> Option<PermissionPriv> {
        match (kind, rel_pos.is_foreign()) {
            (AccessKind::Write, true) => foreign_write(child, protected),
            (AccessKind::Read, true) => foreign_read(child, protected),
            (AccessKind::Write, false) => child_write(child, protected),
            (AccessKind::Read, false) => child_read(child, protected),
        }
    }
}

/// Transition from one permission to the next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermTransition {
    from: PermissionPriv,
    to: PermissionPriv,
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]

pub struct Permission {
    inner: PermissionPriv,
}
impl Permission {
    #[inline]
    pub unsafe fn from_raw(perm_priv: u8) -> Self {
        let inner: PermissionPriv =
            unsafe { core::mem::transmute::<u8, PermissionPriv>(perm_priv) };
        Self { inner }
    }

    /// Check if `self` can be the initial state of a pointer.
    pub fn is_initial(&self) -> bool {
        self.inner.is_initial()
    }
    /// Check if `self` is the terminal state of a pointer (is `Disabled`).
    pub fn is_disabled(&self) -> bool {
        self.inner == Disabled
    }
    /// Check if `self` is the post-child-write state of a pointer (is `Active`).
    pub fn is_active(&self) -> bool {
        self.inner == Active
    }

    /// Default initial permission of the root of a new tree at inbounds positions.
    /// Must *only* be used for the root, this is not in general an "initial" permission!
    pub fn new_active() -> Self {
        Self { inner: Active }
    }

    /// Default initial permission of a reborrowed mutable reference that is either
    /// protected or not interior mutable.
    fn new_reserved_frz() -> Self {
        Self { inner: ReservedFrz }
    }

    /// Default initial permission of an unprotected interior mutable reference.
    fn new_reserved_im() -> Self {
        Self { inner: ReservedIM }
    }

    /// Wrapper around `new_reserved_frz` and `new_reserved_im` that decides
    /// which to call based on the interior mutability and the retag kind (whether there
    /// is a protector is relevant because being protected takes priority over being
    /// interior mutable)
    pub fn new_reserved(ty_is_freeze: bool, protected: bool) -> Self {
        if ty_is_freeze || protected {
            Self::new_reserved_frz()
        } else {
            Self::new_reserved_im()
        }
    }

    /// Default initial permission of a reborrowed shared reference.
    pub fn new_frozen() -> Self {
        Self { inner: Frozen }
    }

    /// Default initial permission of  the root of a new tree at out-of-bounds positions.
    /// Must *only* be used for the root, this is not in general an "initial" permission!
    pub fn new_disabled() -> Self {
        Self { inner: Disabled }
    }

    /// Reject `ReservedIM` that cannot exist in the presence of a protector.
    pub fn compatible_with_protector(&self) -> bool {
        self.inner.compatible_with_protector()
    }
}

impl Into<u8> for Permission {
    fn into(self) -> u8 {
        self.inner as u8
    }
}
