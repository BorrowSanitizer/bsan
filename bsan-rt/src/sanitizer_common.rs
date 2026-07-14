use alloc::ffi::CString;
use alloc::string::{String, ToString};
use core::ffi::c_char;
use core::{fmt, ptr, slice};

/// The immediate caller PC of a runtime hook, captured at the retag/access
/// site by the C++ interceptors and symbolized lazily. Node-execution logging
/// captures the full caller stack separately (see [`resolve_log_locations`]),
/// so the span itself stays a single word. Must match `Span` in `bsan.h`.
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
    /// internal library path (`.cargo`/`.rustup`) and whether it lies in the
    /// testbench (its file path or module/function contains "test").
    fn symbolize_pc(pc: usize) -> (Symbol, bool, bool) {
        let mut buf = [0u8; 512];
        let mut line: u32 = 0;
        let mut column: u32 = 0;
        let mut is_test = false;
        let ok = unsafe {
            __bsan_symbolize_pc(
                pc,
                buf.as_mut_ptr(),
                buf.len(),
                &mut line,
                &mut column,
                &mut is_test,
            )
        };
        if ok != 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            if let Ok(s) = core::str::from_utf8(&buf[..end]) {
                return (
                    Symbol::Resolved { file: s.to_string(), line, col: column },
                    ok == 2,
                    is_test,
                );
            }
        }
        (Symbol::Unresolved { pc }, false, false)
    }

    /// Symbolizes the immediate access site `pc` as an origin note, returning
    /// `Some` only when it lies in library code.
    fn library_origin(pc: usize) -> Option<Symbol> {
        let (sym, internal, _) = Self::symbolize_pc(pc);
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

    /// Symbolizes a span's caller PC. The origin is always `None` here: the
    /// primary error location comes from the live unwind instead.
    pub fn symbolize_with_origin(span: Span) -> (Symbol, Option<Symbol>) {
        if span.0 == 0 {
            return (Symbol::Unused, None);
        }
        (Self::symbolize_pc(span.0).0, None)
    }

    /// Resolves, in a single pass over the full caller stack captured by the
    /// most recent `GET_SPAN` on this thread (innermost first, no depth limit),
    /// two source locations for node-execution logging:
    /// - the first user-code frame (not under `.cargo`/`.rustup`) — the line
    ///   that most directly triggered the node's creation; falls back to the
    ///   first resolvable frame, then the raw immediate PC;
    /// - the first testbench frame (path or module/function contains "test"),
    ///   or [`Symbol::Unused`] when the node originates outside any test.
    fn resolve_log_locations() -> (Symbol, Symbol) {
        let mut frames_ptr: *const usize = ptr::null();
        let n = unsafe { __bsan_captured_frames(&mut frames_ptr) };
        let frames = if frames_ptr.is_null() || n == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(frames_ptr, n) }
        };
        let immediate = frames.first().copied().unwrap_or(0);

        let mut user: Option<Symbol> = None;
        let mut user_fallback: Option<Symbol> = None;
        let mut test: Option<Symbol> = None;
        for &pc in frames {
            if pc == 0 {
                break;
            }
            let (sym, is_library, is_test) = Self::symbolize_pc(pc);
            if !matches!(sym, Symbol::Resolved { .. }) {
                continue;
            }
            if user_fallback.is_none() {
                user_fallback = Some(sym.clone());
            }
            if user.is_none() && !is_library {
                user = Some(sym.clone());
            }
            if test.is_none() && is_test {
                test = Some(sym.clone());
            }
            if user.is_some() && test.is_some() {
                break;
            }
        }
        let user = user.or(user_fallback).unwrap_or(Symbol::Unresolved { pc: immediate });
        (user, test.unwrap_or(Symbol::Unused))
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

    /// Whether node-execution logging is enabled (the `BSAN_NODE_LOG`
    /// environment variable is set). Cached after the first query so the hot
    /// path stays cheap when logging is off.
    pub fn node_logging_enabled() -> bool {
        use core::sync::atomic::{AtomicU8, Ordering};
        // 0 = unknown, 1 = enabled, 2 = disabled.
        static STATE: AtomicU8 = AtomicU8::new(0);
        match STATE.load(Ordering::Relaxed) {
            1 => true,
            2 => false,
            _ => {
                let enabled = unsafe { __bsan_node_logging_enabled() };
                STATE.store(if enabled { 1 } else { 2 }, Ordering::Relaxed);
                enabled
            }
        }
    }

    /// Returns the trimmed source line at `line` of `file`, caching file
    /// contents so repeated node logging does not re-read the same file.
    fn cached_source_line(file: &str, line: u32) -> Option<String> {
        use crate::helpers::FxHashMap;
        if line == 0 {
            return None;
        }
        static CACHE: spin::Mutex<Option<FxHashMap<String, Option<String>>>> =
            spin::Mutex::new(None);
        let mut guard = CACHE.lock();
        let cache = guard.get_or_insert_with(FxHashMap::default);
        let content = cache.entry(file.to_string()).or_insert_with(|| Self::read_file(file));
        content.as_ref().and_then(|c| Self::get_source_line(c, line))
    }

    /// Quotes a field for CSV output if it contains a delimiter, quote, or
    /// newline, doubling any embedded quotes per RFC 4180.
    fn csv_field(s: &str) -> String {
        if s.contains([',', '"', '\n', '\r']) {
            alloc::format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    }

    /// Expands a resolved location into `(file, line, col, source)` CSV
    /// fields, reading the source line for a resolved frame. Unresolved frames
    /// report the raw PC as the file; `Unused` yields empty fields.
    fn location_fields(sym: Symbol) -> (String, u32, u32, String) {
        match sym {
            Symbol::Resolved { file, line, col } => {
                let source = Self::cached_source_line(&file, line).unwrap_or_default();
                (file, line, col, source)
            }
            Symbol::Unresolved { pc } => (alloc::format!("0x{pc:x}"), 0, 0, String::new()),
            Symbol::Unused => (String::new(), 0, 0, String::new()),
        }
    }

    /// Emits one CSV row describing a tree node as it is created: the tree's
    /// allocation id, the node's borrow tag, and two source locations — the
    /// first user-code line and the first testbench line that led to its
    /// creation (each as file, line, column, source text). Testbench fields are
    /// empty for nodes created outside any test. Uses the caller stack captured
    /// by the enclosing hook's `GET_SPAN`, so it must be called synchronously
    /// during that hook. A no-op unless
    /// [`node_logging_enabled`](Self::node_logging_enabled).
    pub fn log_node(alloc_id: usize, bor_tag: usize) {
        if !Self::node_logging_enabled() {
            return;
        }
        let (user, test) = Self::resolve_log_locations();
        let (uf, ul, uc, us) = Self::location_fields(user);
        let (tf, tl, tc, ts) = Self::location_fields(test);
        let row = alloc::format!(
            "{alloc_id},{bor_tag},{},{ul},{uc},{},{},{tl},{tc},{}\n",
            Self::csv_field(&uf),
            Self::csv_field(&us),
            Self::csv_field(&tf),
            Self::csv_field(&ts),
        );
        unsafe { __bsan_append_log(row.as_ptr(), row.len()) };
    }
}

unsafe extern "C" {
    #[thread_local]
    pub unsafe static mut __bsan_had_error: usize;

    /// Tree-node visits accumulated since the last GC request.
    pub unsafe static __bsan_visits_since_gc: core::sync::atomic::AtomicUsize;

    /// Symbolize a single PC into "file:line:column". Returns 0 on failure,
    /// 1 for user code, 2 for internal library code; sets `*is_test` when the
    /// resolved frame's path or module/function contains "test".
    fn __bsan_symbolize_pc(
        pc: usize,
        file_buf: *mut u8,
        file_buf_len: usize,
        line: *mut u32,
        column: *mut u32,
        is_test: *mut bool,
    ) -> i32;

    /// Reads the source line from a file into the provided buffer.
    fn __bsan_read_file(
        path: *const c_char,
        file_buf: *mut *mut c_char,
        file_buf_size: *mut usize,
    ) -> usize;

    /// Free the buffer allocated by __bsan_read_file
    fn __bsan_free_buffer(buf: *mut c_char, size: usize);

    /// Whether node-execution logging is enabled (`BSAN_NODE_LOG` is set).
    fn __bsan_node_logging_enabled() -> bool;

    /// Points `*out` at this thread's most recent captured caller-PC stack
    /// (innermost first) and returns its length. Valid only until the next
    /// capture on this thread.
    fn __bsan_captured_frames(out: *mut *const usize) -> usize;

    /// Appends a preformatted CSV row to the node log file, opening it (and
    /// writing the header) on first use.
    fn __bsan_append_log(buf: *const u8, len: usize);
}
