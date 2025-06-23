#![no_std]

use alloc::boxed::Box;
use alloc::string::String;

use bsan_shared::Permission;
use thiserror_no_std::Error;

use crate::diagnostics::{AccessCause, NodeDebugInfo};
use crate::span::Span;
use crate::AllocId;

pub type BtResult<T> = Result<T, BorrowTrackerError>;
pub type TreeResult<T> = Result<T, TreeError>;
pub type TreeTransitionResult<T> = Result<T, TransitionError>;

#[derive(Debug, Clone, Copy)]
pub enum TransitionError {
    /// This access is not allowed because some parent tag has insufficient permissions.
    /// For example, if a tag is `Frozen` and encounters a child write this will
    /// produce a `ChildAccessForbidden(Frozen)`.
    /// This kind of error can only occur on child accesses.
    ChildAccessForbidden(Permission),
    /// A protector was triggered due to an invalid transition that loses
    /// too much permissions.
    /// For example, if a protected tag goes from `Active` to `Disabled` due
    /// to a foreign write this will produce a `ProtectedDisabled(Active)`.
    /// This kind of error can only occur on foreign accesses.
    ProtectedDisabled(Permission),
    /// Cannot deallocate because some tag in the allocation is strongly protected.
    /// This kind of error can only occur on deallocations.
    ProtectedDealloc,
}

#[derive(Debug)]
pub enum BtOpType {
    Alloc,
    Read,
    Write,
    Retag,
    Dealloc,
    Unknown,
}

#[derive(Debug)]
pub struct BtOp {
    pub op: BtOpType,
    pub span: Option<Span>,
    pub reason: Option<String>,
}

#[derive(Error, Debug)]
pub enum BorrowTrackerError {
    #[error("Erroneous retag caused by: {:?} during {:?} at {:?}", .0.reason, .0.op, .0.span)]
    ErroneousRetag(BtOp),
    #[error("Detected use after free during {:?} at {:?}", .0.op, .0.span)]
    UseAfterFree(BtOp),
    #[error("Detected out-of-bounds access during {:?} at {:?}", .0.op, .0.span)]
    OutOfBounds(BtOp),
    #[error("Unknown Error: Likely caused by an internal failure during {:?} at {:?}", .0.op, .0.span)]
    HardError(BtOp),
    #[error("Tree Borrows Error")]
    TreeError(#[from] TreeError),
}

// Derived from Miri's TbError
#[derive(Debug, Clone, Default)]
pub struct BsanTreeError {
    /// What failure occurred.
    pub error_kind: Option<TransitionError>,
    /// The allocation in which the error is happening.
    pub alloc_id: Option<AllocId>,
    /// The offset (into the allocation) at which the conflict occurred.
    pub error_offset: Option<u64>,
    /// The tag on which the error was triggered.
    /// On protector violations, this is the tag that was protected.
    /// On accesses rejected due to insufficient permissions, this is the
    /// tag that lacked those permissions.
    pub conflicting_info: Option<NodeDebugInfo>,
    // What kind of access caused this error (read, write, reborrow, deallocation)
    pub access_cause: Option<AccessCause>,
    /// Which tag the access that caused this error was made through, i.e.
    /// which tag was used to read/write/deallocate.
    pub accessed_info: Option<NodeDebugInfo>,
}

#[derive(Error, Debug, Clone)]
pub enum SoftError {
    #[error("Tree Error: {0:?}")]
    Bsan(#[from] Box<BsanTreeError>),
    #[error("Internal Transition Error: {0:?}")]
    Transition(#[from] TransitionError),
}

#[derive(Error, Debug, Clone)]
pub enum TreeError {
    #[error("Tree Borrows Violation: {0:?}")]
    SoftTreeError(SoftError),
    #[error("Tree Borrows Error: Likely caused by an internal failure of Tree Borrows")]
    HardTreeError,
    #[error("Unknown Error: Likely caused by an internal failure")]
    UnknownError,
}
