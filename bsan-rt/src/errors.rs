// Components in this file were ported from Miri, and then modified by our team.
use alloc::boxed::Box;
use alloc::string::String;

use bsan_shared::Permission;
use thiserror_no_std::Error;

use crate::diagnostics::{AccessCause, NodeDebugInfo};
use crate::memory::{self, AllocError};
use crate::span::Span;
use crate::{AllocId, Provenance};

pub type BorsanResult<T> = Result<T, ErrorInfo>;
pub type TreeTransitionResult<T> = core::result::Result<T, TransitionError>;

#[derive(Debug)]
pub enum InternalError {
    Alloc(memory::AllocError),
}

impl From<AllocError> for ErrorInfo {
    fn from(err: AllocError) -> ErrorInfo {
        ErrorInfo::Internal(InternalError::Alloc(err))
    }
}

#[derive(Debug, Error)]
pub enum ErrorInfo {
    #[error("internal")]
    Internal(InternalError),
    #[error("undefined behavior")]
    UndefinedBehavior(UBInfo),
}

#[derive(Error, Debug)]
pub enum UBInfo {
    #[error("invalid provenance")]
    InvalidProvenance,
    #[error("access out-of-bounds")]
    AccessOutOfBounds(Provenance, usize, usize),
    #[error("use-after-free.")]
    UseAfterFree(AllocId),
    #[error("freeing global allocation")]
    GlobalFree(AllocId),
    #[error("freeing stack allocation")]
    StackFree(AllocId),
    #[error("aliasing violation")]
    AliasingViolation(Box<TreeError>),
}

pub type UBResult<T> = Result<T, UBInfo>;

impl From<UBInfo> for ErrorInfo {
    fn from(err: UBInfo) -> ErrorInfo {
        ErrorInfo::UndefinedBehavior(err)
    }
}

#[macro_export]
macro_rules! throw_ub {
    ($($tt:tt)*) => {
        do yeet $crate::errors::ErrorInfo::UndefinedBehavior($($tt)*)
    };
}

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

#[allow(unused)]
#[derive(Debug)]
pub struct BtOperation {
    pub op: OperationType,
    pub span: Option<Span>,
    pub reason: Option<String>,
}

#[allow(unused)]
#[derive(Debug)]
pub enum OperationType {
    Alloc,
    Read,
    Write,
    Retag,
    Dealloc,
    Unknown,
}

// Derived from Miri's TbError
#[derive(Debug, Clone)]
pub struct TreeError {
    /// What failure occurred.
    pub error_kind: TransitionError,
    /// The allocation in which the error is happening.
    pub alloc_id: AllocId,
    /// The offset (into the allocation) at which the conflict occurred.
    pub error_offset: u64,
    /// The tag on which the error was triggered.
    /// On protector violations, this is the tag that was protected.
    /// On accesses rejected due to insufficient permissions, this is the
    /// tag that lacked those permissions.
    pub conflicting_info: NodeDebugInfo,
    // What kind of access caused this error (read, write, reborrow, deallocation)
    pub access_cause: AccessCause,
    /// Which tag the access that caused this error was made through, i.e.
    /// which tag was used to read/write/deallocate.
    pub accessed_info: NodeDebugInfo,
}
