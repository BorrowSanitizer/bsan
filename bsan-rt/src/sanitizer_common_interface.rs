use crate::alloc::string::{String, ToString};
use crate::errors::{BorsanResult, ErrorInfo};
use crate::global::BHashMap;
use crate::memory::hooks::BsanAllocHooks;
use crate::{span, AllocId, SpanData, SrcLoc};

unsafe extern "C" {
    fn __bsan_printCurrentStackTrace();

    fn __bsan_printStackTrace(stackId: u32);

    /// Captures the current stack trace, puts it into the stack depot and returns its ID
    fn __bsan_StackDepotPut(pc: usize, bp: usize, max_depth: u32) -> u32;

    /// Gets the top frame PC address from a stack trace ID
    fn __bsan_GetTopFramePC(pc: usize) -> usize;

    /// Symbolize a single PC into file:line:column and returns 1 on success.
    fn __bsan_symbolizePC(
        pc: usize,
        file_buf: *mut u8,
        file_buf_len: usize,
        line: *mut u32,
        column: *mut u32,
    ) -> i32;
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
pub(crate) fn capture_current_stack_trace(
    pc: usize,
    bp: usize,
    max_depth: Option<u32>,
) -> StackTraceId {
    let max_depth = max_depth.unwrap_or(K_STACK_TRACE_MAX);
    unsafe { StackTraceId(__bsan_StackDepotPut(pc, bp, max_depth)) }
}

/// Gets the top frame PC address from this stack trace.
/// This is the adjusted PC address as stored by sanitizer_common.
pub(crate) fn get_top_frame_pc(pc: usize) -> usize {
    unsafe { __bsan_GetTopFramePC(pc) }
}

/// Symbolize a single PC and return a `SrcLoc` (file, line, column) on success
pub(crate) fn symbolize_pc_into(pc: usize) -> Option<SrcLoc> {
    let mut buf = [0u8; 512];
    let mut line: u32 = 0;
    let mut column: u32 = 0;
    let ok = unsafe { __bsan_symbolizePC(pc, buf.as_mut_ptr(), buf.len(), &mut line, &mut column) };
    if ok == 1 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        if let Ok(s) = core::str::from_utf8(&buf[..end]) {
            return Some(SrcLoc { file: s.to_string(), line, col: column });
        }
    }
    None
}

#[derive(Copy, Clone, Debug)]
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
        span_data: SpanData,
    ) -> BorsanResult<()> {
        let max_depth = max_depth.unwrap_or(K_STACK_TRACE_MAX);
        let stack_id =
            unsafe { StackTraceId(__bsan_StackDepotPut(span_data.ip, span_data.fp.fp, max_depth)) };
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
