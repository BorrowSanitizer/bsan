use crate::alloc::string::ToString;
use crate::span::Symbol;

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

/// Prints the stack trace corresponding to the given stack ID or the current stack trace
#[allow(unused)]
pub(crate) fn print_stack_trace() {
    unsafe { __bsan_printCurrentStackTrace() }
}

pub(crate) fn symbolize_pc_into(pc: usize) -> Symbol {
    let mut buf = [0u8; 512];
    let mut line: u32 = 0;
    let mut column: u32 = 0;
    let ok = unsafe { __bsan_symbolizePC(pc, buf.as_mut_ptr(), buf.len(), &mut line, &mut column) };
    if ok == 1 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        if let Ok(s) = core::str::from_utf8(&buf[..end]) {
            return Symbol::Resolved { file: s.to_string(), line, col: column };
        }
    }
    Symbol::Unknown
}
