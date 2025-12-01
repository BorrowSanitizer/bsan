use crate::errors::{BorsanResult, ErrorInfo};
use crate::global::BHashMap;
use crate::memory::hooks::BsanAllocHooks;
use crate::AllocId;

unsafe extern "C" {
    fn __bsan_printCurrentStackTrace();

    fn __bsan_printStackTrace(stackId: u32);

    /// Captures the current stack trace, puts it into the stack depot and returns its ID
    fn __bsan_StackDepotPut(max_depth: u32) -> u32;
}

/// Maximum depth of captured stack traces as defined in sanitizer_common/sanitizer_stacktrace.h
const K_STACK_TRACE_MAX: u32 = 255;

/// Prints the stack trace corresponding to the given stack ID or the current stack trace
pub(crate) fn print_stack_trace(stack_id: Option<StackTraceId>) {
    unsafe {
        match stack_id {
            Some(id) => __bsan_printStackTrace(id.0),
            None => __bsan_printCurrentStackTrace(),
        }
    }
}

/// Captures the current stack trace, puts it into the stack depot and returns its ID
/// Always inlined to not add an extra frame for this function to the stack.
#[inline(always)]
pub(crate) fn capture_current_stack_trace(max_depth: Option<u32>) -> StackTraceId {
    let max_depth = max_depth.unwrap_or(K_STACK_TRACE_MAX);
    unsafe { StackTraceId(__bsan_StackDepotPut(max_depth)) }
}

#[derive(Copy, Clone)]
pub(crate) struct StackTraceId(pub(crate) u32);
pub(crate) struct StackTraceDepot {
    /// map from allocation ID to its stack ID
    alloc_stacks: BHashMap<AllocId, StackTraceId>,
}

impl StackTraceDepot {
    pub(crate) fn new_in(hooks: BsanAllocHooks) -> Self {
        Self { alloc_stacks: BHashMap::new_in(hooks) }
    }

    pub(crate) fn capture_stack(
        &mut self,
        alloc_id: AllocId,
        max_depth: Option<u32>,
    ) -> BorsanResult<()> {
        let max_depth = max_depth.unwrap_or(K_STACK_TRACE_MAX);
        let stack_id = unsafe { StackTraceId(__bsan_StackDepotPut(max_depth)) };
        match self.alloc_stacks.insert(alloc_id, stack_id) {
            None => Ok(()),
            Some(_) => Err(ErrorInfo::Internal(crate::errors::InternalError::Unexpected(format!(
                "Stack trace for allocation ID {:?} already exists",
                alloc_id
            )))),
        }
    }

    pub(crate) fn print_trace(&self, alloc_id: &AllocId) -> BorsanResult<StackTraceId> {
        let stack_id = self.alloc_stacks.get(alloc_id);
        match stack_id {
            Some(id) => Ok(*id),
            None => Err(ErrorInfo::Internal(crate::errors::InternalError::Unexpected(format!(
                "No stack trace found for allocation ID {:?}",
                alloc_id
            )))),
        }
    }
}

impl core::fmt::Debug for StackTraceDepot {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Ok(())
    }
}
