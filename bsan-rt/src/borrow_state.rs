//! Allocation-level borrow metadata attached to [`crate::AllocInfo`].
//!
//! Today this is the old `LazyTree` path under a clearer name: one
//! [`BorrowState`] per allocation, stored under `AllocInfo`'s mutex.
//! Provenance remains two-word (`BorTag` + `AllocInfo*`).
//!
//! - [`BorrowState::Uninit`]: lazy; root tag / size / span / refcount only.
//! - [`BorrowState::Tree`]: owns the full [`crate::tree_borrows::tree::EagerTree`].
//!
//! [#279](https://github.com/BorrowSanitizer/bsan/issues/279) (one-word provenance)
//! will turn Heap-allocated metadata into `Uninit | Tree | Node`, make provenance a
//! single pointer (tag unused), and hand out per-retag `Node` objects. That work
//! should land in a follow-up PR on top of this rename.

pub use crate::tree_borrows::tree::BorrowState;
