use alloc::ffi::CString;
use core::ffi::c_char;

use crate::alloc::string::{String, ToString};
use crate::span::{FramePtr, Span, Symbol};

/// Maximum depth of captured stack traces as defined
/// in sanitizer_common/sanitizer_stacktrace.h
#[allow(unused)]
const STACK_TRACE_MAX: u32 = 255;
const SRC_LINE_LEN_MAX: u32 = 100;

#[allow(unused)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct StackTraceId(pub(crate) u32);

unsafe extern "C" {
    fn __bsan_print_current_stack_trace();

    fn __bsan_print_stack_trace(stackId: u32);

    /// Captures the current stack trace, puts it into the stack depot and returns its ID
    fn __bsan_stack_depot_put(pc: usize, bp: usize, max_depth: u32) -> u32;

    /// Gets the top frame PC address from a stack trace ID
    fn __bsan_get_top_frame_pc(pc: usize) -> usize;

    /// Symbolize a single PC into "file:line:column" and returns 1 on success.
    fn __bsan_symbolize_pc(
        pc: usize,
        file_buf: *mut u8,
        file_buf_len: usize,
        line: *mut u32,
        column: *mut u32,
    ) -> i32;

    /// Reads the source line from a file into the provided buffer.
    fn __bsan_read_src_line(path: *const u8, line: u32, buf: *mut u8, buf_len: usize) -> u32;
}

pub struct SanitizerCommon;

impl SanitizerCommon {
    /// Gets the top frame PC address from this stack trace.
    /// This is the adjusted PC address as stored by sanitizer_common.
    #[allow(unused)]
    pub fn get_span(fp: FramePtr) -> Span {
        unsafe { Span(__bsan_get_top_frame_pc(fp.addr())) }
    }

    pub fn symbolize(span: Span) -> Symbol {
        let mut buf = [0u8; 512];
        let mut line: u32 = 0;
        let mut column: u32 = 0;
        let ok = unsafe {
            __bsan_symbolize_pc(span.0, buf.as_mut_ptr(), buf.len(), &mut line, &mut column)
        };
        if ok == 1 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            if let Ok(s) = core::str::from_utf8(&buf[..end]) {
                return Symbol::Resolved { file: s.to_string(), line, col: column };
            }
        }
        Symbol::Unknown
    }

    /// Captures the current stack trace, puts it into the stack depot and returns its ID
    #[allow(unused)]
    pub fn capture_stack_trace(fp: FramePtr, max_depth: Option<u32>) -> StackTraceId {
        let max_depth = max_depth.unwrap_or(STACK_TRACE_MAX);
        unsafe { StackTraceId(__bsan_stack_depot_put(fp.addr(), fp.caller_span().0, max_depth)) }
    }

    #[allow(unused)]
    pub fn print_current_stack_trace() {
        unsafe { __bsan_print_current_stack_trace() }
    }

    #[allow(unused)]
    pub fn print_stack_trace(id: StackTraceId) {
        unsafe { __bsan_print_stack_trace(id.0) }
    }

    pub fn get_source_line(file: &str, line: u32) -> Option<String> {
        let mut buf = [0 as c_char; SRC_LINE_LEN_MAX as usize];
        let c_path = CString::new(file).ok()?;
        let read =
            unsafe { __bsan_read_src_line(c_path.as_ptr(), line, buf.as_mut_ptr(), buf.len()) };
        if read == 0 {
            return None;
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(read as usize);
        core::str::from_utf8(&buf[..end]).ok().map(|s| s.trim().to_string())
    }
}
