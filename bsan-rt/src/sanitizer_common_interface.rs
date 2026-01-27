use crate::alloc::string::ToString;
use crate::span::Symbol;

unsafe extern "C" {
    fn __bsan_symbolize_pc(
        pc: usize,
        file_buf: *mut u8,
        file_buf_len: usize,
        line: *mut u32,
        column: *mut u32,
    ) -> i32;
}

pub(crate) fn symbolize_pc_into(pc: usize) -> Symbol {
    let mut buf = [0u8; 512];
    let mut line: u32 = 0;
    let mut column: u32 = 0;
    let ok =
        unsafe { __bsan_symbolize_pc(pc, buf.as_mut_ptr(), buf.len(), &mut line, &mut column) };
    if ok == 1 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        if let Ok(s) = core::str::from_utf8(&buf[..end]) {
            return Symbol::Resolved { file: s.to_string(), line, col: column };
        }
    }
    Symbol::Unknown
}
