// Components in this file were ported from Miri, and then modified by our team.
use alloc::boxed::Box;
use alloc::string::String;
use core::fmt::{Debug, Display};

use bsan_shared::Permission;

use crate::diagnostics::{AccessCause, NodeDebugInfo};
use crate::memory::{self, AllocError};
use crate::span::Span;
use crate::{AllocId, Provenance};

pub type BorsanResult<T> = Result<T, ErrorInfo>;
pub type TreeTransitionResult<T> = core::result::Result<T, TransitionError>;

#[derive(Debug)]
pub enum InternalError {
    Alloc(memory::AllocError),
    Unexpected(String),
}

impl From<AllocError> for ErrorInfo {
    fn from(err: AllocError) -> ErrorInfo {
        ErrorInfo::Internal(InternalError::Alloc(err))
    }
}

pub enum ErrorInfo {
    Internal(InternalError),
    UndefinedBehavior(UBInfo),
}

impl Debug for ErrorInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ErrorInfo::Internal(e) => write!(f, "{:?}", e),
            ErrorInfo::UndefinedBehavior(e) => write!(f, "UndefinedBehavior({})", e),
        }
    }
}

#[derive(Debug)]
pub enum UBInfo {
    InvalidProvenance,
    AccessOutOfBounds(Provenance, usize, usize),
    UseAfterFree(AllocId),
    GlobalFree(AllocId),
    StackFree(AllocId),
    AliasingViolation(Box<TreeError>),
}

pub type UBResult<T> = Result<T, UBInfo>;

impl From<UBInfo> for ErrorInfo {
    fn from(err: UBInfo) -> ErrorInfo {
        ErrorInfo::UndefinedBehavior(err)
    }
}

impl Display for UBInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UBInfo::InvalidProvenance => write!(f, "{:?}", self),
            UBInfo::AccessOutOfBounds(..) => write!(f, "{:?}", self),
            UBInfo::UseAfterFree(..) => write!(f, "{:?}", self),
            UBInfo::GlobalFree(..) => write!(f, "{:?}", self),
            UBInfo::StackFree(..) => write!(f, "{:?}", self),
            UBInfo::AliasingViolation(error) => {
                if let Some(access_event) = error.accessed_info.history.last_event() {
                    if let Some(conflict_event) = error.conflicting_info.history.last_event() {
                        let a_loc = access_event.span.span_data().source_location();
                        let c_loc = conflict_event.span.span_data().source_location();
                        match (a_loc, c_loc) {
                            (Some(a), Some(c)) => {
                                write!(f, "Access at {}\nConflict at {}", a, c)
                            }
                            (Some(a), None) => {
                                write!(
                                    f,
                                    "Access at {}\nConflict at ip 0x{:x}",
                                    a,
                                    conflict_event.span.addr()
                                )
                            }
                            (None, Some(c)) => {
                                write!(
                                    f,
                                    "Access at ip 0x{:x}\nConflict at {}",
                                    access_event.span.addr(),
                                    c
                                )
                            }
                            (None, None) => {
                                write!(
                                    f,
                                    "Access at ip 0x{:x}\nConflict at ip 0x{:x}",
                                    access_event.span.addr(),
                                    conflict_event.span.addr()
                                )
                            }
                        }
                    } else {
                        if let Some(a) = access_event.span.span_data().source_location() {
                            write!(f, "Access at {}\nConflict event not found", a)
                        } else {
                            write!(
                                f,
                                "Access at ip 0x{:x}\nConflict event not found",
                                access_event.span.addr()
                            )
                        }
                    }
                } else {
                    write!(f, "AliasingViolation: {:?}", error)
                }
            }
        }
    }
}

impl UBInfo {
    pub fn get_alloc_id(&self) -> Option<AllocId> {
        match self {
            UBInfo::UseAfterFree(alloc_id)
            | UBInfo::GlobalFree(alloc_id)
            | UBInfo::StackFree(alloc_id) => Some(*alloc_id),
            UBInfo::AliasingViolation(error) => Some(error.alloc_id),
            UBInfo::AccessOutOfBounds(prov, _access_size, _alloc_size) => Some(prov.alloc_id),
            UBInfo::InvalidProvenance => None,
        }
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
