// Components in this file were ported from Miri, and then modified by our team.
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{Debug, Display};

use bsan_shared::Permission;
use hashbrown::HashMap;

use crate::diagnostics::{AccessCause, HistoryData, NodeDebugInfo};
use crate::sanitizer_common_interface::SanitizerCommon;
use crate::span::Symbol;
use crate::AllocId;

pub type TreeTransitionResult<T> = core::result::Result<T, TransitionError>;

#[derive(Debug)]
pub enum UBInfo {
    AccessOutOfBounds(AllocId, usize, usize),
    UseAfterFree,
    AliasingViolation(Box<TreeError>),
}

pub type UBResult<T> = Result<T, UBInfo>;

impl Display for UBInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Undefined Behavior: ")?;
        match self {
            UBInfo::UseAfterFree => {
                write!(f, "trying to access an allocation that has been freed.")
            }
            UBInfo::AccessOutOfBounds(id, size, offset) => {
                write!(
                    f,
                    "an access of size {size} at offset {offset:x} is out of bounds for {id:?}."
                )
            }
            UBInfo::AliasingViolation(error) => write!(f, "{error}"),
        }
    }
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

impl core::fmt::Display for TreeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use TransitionError::*;
        let cause = self.access_cause;
        let error_offset = self.error_offset;
        let access = self.access_cause;
        let accessed = &self.accessed_info;
        let accessed_tag = accessed.tag;
        let conflicting = &self.conflicting_info;

        // An access is considered conflicting if it happened through a
        // different tag than the one who caused UB.
        // When doing a wildcard access (where `accessed` is `None`) we
        // do not know which precise tag the accessed happened from,
        // however we can be certain that it did not come from the
        // conflicting tag.
        // This is because the wildcard data structure already removes
        // all tags through which an access would cause UB.
        let accessed_is_conflicting = accessed.tag == conflicting.tag;
        let title = format!(
            "{cause} through {accessed_tag:?} at {alloc_id:?}[{error_offset:#x}] is forbidden",
            alloc_id = self.alloc_id
        );

        let (title, details, conflicting_tag_name) = match self.error_kind {
            ChildAccessForbidden(perm) => {
                let conflicting_tag_name =
                    if accessed_is_conflicting { "accessed" } else { "conflicting" };
                let mut details = Vec::new();
                if !accessed_is_conflicting {
                    details.push(format!(
                        "the accessed tag {accessed_tag:?} is a child of the conflicting tag {conflicting}"
                    ));
                }
                details.push(format!(
                    "the {conflicting_tag_name} tag {conflicting} has state {perm} which forbids this {access}"
                ));
                (title, details, conflicting_tag_name)
            }
            ProtectedDisabled(before_disabled) => {
                let conflicting_tag_name = "protected";
                let details = vec![
                    format!(
                        "the accessed tag {accessed_tag:?} is foreign to the {conflicting_tag_name} tag {conflicting} (i.e., it is not a child)"
                    ),
                    format!(
                        "this {access} would cause the {conflicting_tag_name} tag {conflicting} (currently {before_disabled}) to become Disabled"
                    ),
                    format!("protected tags must never be Disabled"),
                ];
                (title, details, conflicting_tag_name)
            }
            ProtectedDealloc => {
                let conflicting_tag_name = "strongly protected";
                let details = vec![
                    format!(
                        "the allocation of the accessed tag {accessed_tag:?} also contains the {conflicting_tag_name} tag {conflicting}"
                    ),
                    format!("the {conflicting_tag_name} tag {conflicting} disallows deallocations"),
                ];
                (title, details, conflicting_tag_name)
            }
        };
        let mut history = HistoryData::default();
        if !accessed_is_conflicting {
            history.extend(self.accessed_info.history.forget(), "accessed", false);
        }
        history.extend(
            self.conflicting_info.history.extract_relevant(error_offset),
            conflicting_tag_name,
            true,
        );

        writeln!(f, "{title}")?;
        for detail in details {
            writeln!(f, "help: {}", detail)?;
        }

        let mut file_cache: HashMap<String, String> = HashMap::new();
        for event in history.events {
            writeln!(f, "    help: {}", event.1)?;
            if let Some(span) = event.0 {
                let symbol = span.symbolize();
                writeln!(f, "      --> {}", symbol)?;
                if let Symbol::Resolved { file: path, line, col: _ } = symbol {
                    let file = file_cache
                        .entry(path.clone())
                        .or_insert_with(|| SanitizerCommon::read_file(&path).unwrap_or_default());
                    if let Some(content) = SanitizerCommon::get_source_line(file, line) {
                        writeln!(f, "         |")?;
                        writeln!(f, "{:>8} | {}", line, content)?;
                        writeln!(f, "         |")?;
                    }
                }
            }
            writeln!(f)?;
        }
        Ok(())
    }
}
