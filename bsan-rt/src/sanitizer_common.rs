use alloc::ffi::CString;
use alloc::string::{String, ToString};
use core::ffi::c_char;
use core::{fmt, ptr, slice};

/// Number of raw caller PCs captured per span. Must match `kSpanMaxFrames`
/// in `bsan.h`.
pub const SPAN_MAX_FRAMES: usize = 12;

/// Raw caller-PC chain captured by the C++ interceptors, innermost first.
/// `pcs[0]` is the immediate retag/access site; deeper entries let
/// display-time symbolization skip library code and report the user call
/// site instead. Unused entries are 0.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Span {
    pub pcs: [usize; SPAN_MAX_FRAMES],
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

    /// Symbolizes `pc`, returning `Some` only when it resolves to user code.
    fn symbolize_user(pc: usize) -> Option<Symbol> {
        match Self::symbolize_pc(pc) {
            (sym @ Symbol::Resolved { .. }, false) => Some(sym),
            _ => None,
        }
    }

    /// Resolves `span` to its primary location and an optional origin note.
    ///
    /// When the immediate access site is library code, the primary location
    /// becomes the nearest user-code caller and the access site is returned as
    /// the origin. The origin is `None` when the access site is already user
    /// code, or when no caller resolves to user code.
    pub fn symbolize_with_origin(span: Span) -> (Symbol, Option<Symbol>) {
        if span.pcs[0] == 0 {
            return (Symbol::Unused, None);
        }
        let (immediate, internal) = Self::symbolize_pc(span.pcs[0]);

        if !internal && matches!(immediate, Symbol::Resolved { .. }) {
            return (immediate, None);
        }

        let user_caller =
            span.pcs[1..].iter().copied().take_while(|&pc| pc != 0).find_map(Self::symbolize_user);
        match user_caller {
            Some(caller) => (caller, internal.then_some(immediate)),
            None => (immediate, None),
        }
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

        content.lines().nth((line_number - 1) as usize).map(|s| s.trim().to_string())
    }
}

unsafe extern "C" {
    #[thread_local]
    pub unsafe static mut __bsan_had_error: usize;

    /// Symbolize a single PC into "file:line:column". Returns 0 on failure,
    /// 1 for user code, 2 for internal library code (cargo/rustup paths).
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
