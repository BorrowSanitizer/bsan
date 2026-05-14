// This module was ported from Miri (commit:072a9fa) and modified by our team.
// RetagMode and implicit writes are not implemented yet.
#![allow(clippy::too_many_arguments)]
use crate::global::ProtectedTags;
use crate::tree_borrows::perms::AccessKind;
use crate::{RetagFlags, RetagInfo};

pub mod data_structures;
pub mod diagnostics;
mod exhaustive;
mod foreign_access_skipping;
pub mod perms;
pub mod tree;
mod tree_visitor;
mod wildcard;

pub use foreign_access_skipping::IdempotentForeignAccess;
pub use perms::*;

use self::perms::Permission;
pub use self::tree::Tree;

type GlobalState = ProtectedTags;

/// Policy for a new borrow.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct NewPermission {
    /// Permission for the frozen part of the range.
    pub freeze_perm: Permission,
    /// Permission for the non-frozen part of the range.
    pub nonfreeze_perm: Permission,
    /// Permission for memory outside the range.
    pub outside_perm: Permission,
    /// Whether this pointer is part of the arguments of a function call.
    /// `protector` is `Some(_)` for all pointers marked `noalias`.
    pub protector: Option<ProtectorKind>,
}

impl NewPermission {
    pub fn new(info: RetagInfo<'_>) -> Self {
        let is_mutable: bool = info.flags.contains(RetagFlags::IS_MUTABLE);
        let is_protected = info.flags.contains(RetagFlags::IS_PROTECTED);
        let ty_is_freeze = info.flags.contains(RetagFlags::IS_FREEZE);
        let is_box = info.flags.contains(RetagFlags::IS_BOX);

        enum Part {
            InsideFrozen,
            InsideUnsafeCell,
            Outside,
        }
        use Part::*;

        let perm = |part: Part| {
            // Whether we should consider this byte to be frozen.
            // Outside bytes are frozen only if the entire type is frozen.
            let frozen = match part {
                InsideFrozen => true,
                InsideUnsafeCell => false,
                Outside => ty_is_freeze,
            };
            if is_mutable {
                // Boxes
                if is_box {
                    if is_protected || frozen {
                        // We also use this for protected `Box<UnsafeCell>` as otherwise adding
                        // `noalias` would not be sound.
                        Permission::new_reserved_frz()
                    } else {
                        Permission::new_reserved_im()
                    }
                // Mutable references
                } else {
                    if is_protected || frozen {
                        // We also use this for protected `&mut UnsafeCell` as otherwise adding
                        // `noalias` would not be sound.
                        Permission::new_reserved_frz()
                    } else {
                        Permission::new_reserved_im()
                    }
                }
            // Shared references
            } else {
                if frozen {
                    Permission::new_frozen()
                } else {
                    Permission::new_cell()
                }
            }
        };

        NewPermission {
            freeze_perm: perm(InsideFrozen),
            nonfreeze_perm: perm(InsideUnsafeCell),
            outside_perm: perm(Outside),
            protector: is_protected.then_some(if is_box {
                // Weak protector for boxes
                ProtectorKind::WeakProtector
            } else {
                // Strong protector for references
                ProtectorKind::StrongProtector
            }),
        }
    }
}
