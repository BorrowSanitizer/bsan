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

pub use perms::*;

use self::perms::Permission;
pub use self::tree::Tree;

type GlobalState = ProtectedTags;

/// Policy for a new borrow.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct NewPermission {
    /// Permission for the frozen part of the range.
    pub freeze_perm: Permission,
    /// Whether a read access should be performed on the frozen part on a retag.
    pub freeze_access: bool,
    /// Permission for the non-frozen part of the range.
    pub nonfreeze_perm: Permission,
    /// What kind of access should be performed on the non-frozen part on a retag.
    pub nonfreeze_access: Option<AccessKind>,
    // Whether the type is frozen.
    pub ty_is_freeze: bool,
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
        let freeze_perm =
            if is_mutable { Permission::new_reserved_frz() } else { Permission::new_frozen() };

        let nonfreeze_perm = if is_mutable {
            if is_protected {
                Permission::new_reserved_frz()
            } else {
                Permission::new_reserved_im()
            }
        } else {
            Permission::new_cell()
        };

        // Everything except for `Cell` gets an initial access.
        let initial_access = |perm: &Permission| !perm.is_cell();

        NewPermission {
            freeze_perm,
            freeze_access: initial_access(&freeze_perm),
            nonfreeze_perm,
            nonfreeze_access: initial_access(&nonfreeze_perm).then_some(AccessKind::Read),
            ty_is_freeze,
            protector: is_protected.then_some(if is_box {
                // Weak protector for boxes
                ProtectorKind::WeakProtector
            } else {
                // Strong protector for references
                ProtectorKind::StrongProtector
            }),
        }
    }
    pub fn default_perm(&self) -> Permission {
        if self.ty_is_freeze {
            self.freeze_perm
        } else {
            self.nonfreeze_perm
        }
    }
}
