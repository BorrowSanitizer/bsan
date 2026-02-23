// Components in this file were ported from Miri, and then modified by our team.
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{Debug};

use hashbrown::HashMap;

use crate::borrow_tracker::Permission;
use crate::diagnostics::{AccessCause, HistoryData, NodeDebugInfo};
use crate::sanitizer_common_interface::SanitizerCommon;
use crate::span::{Span, Symbol};
use crate::AllocId;

pub type TreeTransitionResult<T> = core::result::Result<T, TransitionError>;

#[derive(Debug)]
pub enum UBInfo {
    AccessOutOfBounds { alloc_id: AllocId, access_size: usize, offset: usize, alloc_size: usize },
    UseAfterFree,
    AliasingViolation(Box<TreeError>),
}

pub type UBResult<T> = Result<T, UBInfo>;

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

#[derive(Default)]
pub struct ErrorFormatContext {
    file_cache: HashMap<String, String>,
}

impl ErrorFormatContext {
    pub fn display_ub(&mut self, info: UBInfo, current_span: Span) -> String {
        let mut result = String::new();
        let symbol = current_span.symbolize();
        result.push_str("Undefined Behavior: ");
        match info {
            UBInfo::UseAfterFree => {
                result.push_str("trying to access an allocation that has been freed.\n");
                result.push_str(&self.format_symbol(symbol));
                result.push_str("\n");

            }
            UBInfo::AccessOutOfBounds { alloc_id, access_size, alloc_size, offset } => {
                result.push_str(&format!(
                    "an access of size {access_size} at offset {offset:x} is out of bounds for {alloc_id:?} of size {alloc_size:x}.\n"
                ));
                result.push_str(&self.format_symbol(symbol));
                result.push_str("\n");
            }
            UBInfo::AliasingViolation(error) => {
                result.push_str(&self.display_tree_error(*error, symbol))
            }
        }
        result
    }

    fn display_tree_error(&mut self, error: TreeError, symbol: Symbol) -> String {
        let mut buffer = String::new();

        use TransitionError::*;
        let cause = error.access_cause;
        let error_offset = error.error_offset;
        let access = error.access_cause;
        let accessed = &error.accessed_info;
        let accessed_tag = accessed.tag;
        let conflicting = &error.conflicting_info;

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
            alloc_id = error.alloc_id
        );

        let (title, details, conflicting_tag_name) = match error.error_kind {
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
            history.extend(error.accessed_info.history.forget(), "accessed", false);
        }
        history.extend(
            error.conflicting_info.history.extract_relevant(error_offset),
            conflicting_tag_name,
            true,
        );

        buffer.push_str(&title);
        buffer.push_str("\n");
        buffer.push_str(&self.format_symbol(symbol));
        buffer.push_str("\n");
        for detail in details {
            buffer.push_str(&format!("help: {}\n", detail));
        }

        for event in history.events {
            buffer.push_str(&format!("    help: {}\n", event.1));
            if let Some(span) = event.0 {
                let symbol = span.symbolize();
                buffer.push_str(&self.format_symbol(symbol));
            }
            buffer.push('\n');
        }
        buffer
    }

    fn format_symbol(&mut self, symbol: Symbol) -> String {
        let mut buffer = String::new();
        buffer.push_str(&format!("      --> {}\n", symbol));
        if let Symbol::Resolved { file: path, line, col: _ } = symbol {
            let file = self
                .file_cache
                .entry(path.clone())
                .or_insert_with(|| SanitizerCommon::read_file(&path).unwrap_or_default());
            if let Some(content) = SanitizerCommon::get_source_line(file, line) {
                buffer.push_str("         |\n");
                buffer.push_str(&format!("{:>8} | {}\n", line, content));
                buffer.push_str("         |\n");
            }
        }
        buffer
    }
}
