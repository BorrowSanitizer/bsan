use alloc::ffi::CString;
use alloc::string::{String, ToString};
use core::ffi::c_char;
use core::{fmt, ptr, slice};

/// The immediate caller PC of a runtime hook, captured at the retag/access
/// site by the C++ interceptors. Symbolized lazily at display time as the
/// error's origin note; the primary error location comes from the live unwind
/// in the `HANDLE_ERROR` macro. Must match `Span` in `bsan.h`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct Span(pub usize);

#[allow(dead_code)]
impl Span {
    pub const fn dummy() -> Self {
        Self(0)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Symbol {
    Resolved { file: String, line: u32, col: u32 },
    Unresolved { pc: usize },
    Unused,
}

impl Symbol {
    pub fn line_length(&self) -> usize {
        match self {
            Symbol::Resolved { file: _, line, col: _ } => {
                if *line > 0 {
                    line.ilog10() as usize + 1
                } else {
                    1
                }
            }
            _ => 0,
        }
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Symbol::Resolved { file, line, col } => {
                write!(f, "{file}:{line}:{col}")
            }
            Symbol::Unresolved { pc } => {
                write!(f, "pc:0x{pc:x}")
            }
            Symbol::Unused => write!(f, "<unused>"),
        }
    }
}

pub struct SanitizerCommon;

impl SanitizerCommon {
    /// Symbolizes `pc` to a [`Symbol`], reporting whether it lies in an
    /// internal library path.
    fn symbolize_pc(pc: usize) -> (Symbol, bool) {
        let mut buf = [0u8; 512];
        let mut line: u32 = 0;
        let mut column: u32 = 0;
        let ok =
            unsafe { __bsan_symbolize_pc(pc, buf.as_mut_ptr(), buf.len(), &mut line, &mut column) };
        if ok != 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            if let Ok(s) = core::str::from_utf8(&buf[..end]) {
                return (Symbol::Resolved { file: s.to_string(), line, col: column }, ok == 2);
            }
        }
        (Symbol::Unresolved { pc }, false)
    }

    /// Symbolizes the immediate access site `pc` as an origin note, returning
    /// `Some` only when it lies in library code.
    fn library_origin(pc: usize) -> Option<Symbol> {
        let (sym, internal) = Self::symbolize_pc(pc);
        internal.then_some(sym)
    }

    /// Resolves the primary error location and an optional origin note.
    ///
    /// `user_frame_pc` is the first user-code frame located by the live unwind
    /// in `HANDLE_ERROR`; when present it is the primary location and the
    /// captured access site becomes the origin (only if it is library code).
    /// When the unwind found no user frame (`0`), we fall back to symbolizing
    /// the captured span directly.
    pub fn resolve_error_location(
        user_frame_pc: usize,
        captured: Span,
    ) -> (Symbol, Option<Symbol>) {
        if user_frame_pc == 0 {
            return Self::symbolize_with_origin(captured);
        }
        (Self::symbolize_pc(user_frame_pc).0, Self::library_origin(captured.0))
    }

    /// Symbolizes `span`'s single captured PC. The origin is always `None`
    /// here: with only one frame there is no caller to attribute it to.
    pub fn symbolize_with_origin(span: Span) -> (Symbol, Option<Symbol>) {
        if span.0 == 0 {
            return (Symbol::Unused, None);
        }
        (Self::symbolize_pc(span.0).0, None)
    }

    /// Read entire file into a String
    pub fn read_file(path: &str) -> Option<String> {
        let c_path = CString::new(path).ok()?;

        let mut buf_ptr: *mut c_char = ptr::null_mut();
        let mut buf_size: usize = 0;

        unsafe {
            let bytes_read = __bsan_read_file(c_path.as_ptr(), &mut buf_ptr, &mut buf_size);
            if bytes_read == 0 {
                return None;
            }

            let bytes = slice::from_raw_parts(buf_ptr as *const u8, bytes_read);
            let result = String::from_utf8_lossy(bytes).into_owned();
            __bsan_free_buffer(buf_ptr, buf_size);
            Some(result)
        }
    }

    /// Read a specific line from a file
    pub fn get_source_line(content: &str, line_number: u32) -> Option<String> {
        if line_number == 0 {
            return None;
        }
        content.lines().nth((line_number - 1) as usize).map(|s| s.to_string())
    }
}

unsafe extern "C" {
    #[thread_local]
    pub unsafe static mut __bsan_had_error: usize;

    /// Symbolize a single PC into "file:line:column" and returns 1 on success.
    fn __bsan_symbolize_pc(
        pc: usize,
        file_buf: *mut u8,
        file_buf_len: usize,
        line: *mut u32,
        column: *mut u32,
    ) -> i32;

    /// Reads the source line from a file into the provided buffer.
    fn __bsan_read_file(
        path: *const c_char,
        file_buf: *mut *mut c_char,
        file_buf_size: *mut usize,
    ) -> usize;

    /// Free the buffer allocated by __bsan_read_file
    fn __bsan_free_buffer(buf: *mut c_char, size: usize);
}
