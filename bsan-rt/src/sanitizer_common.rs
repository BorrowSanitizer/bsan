use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::string::{String, ToString};
use core::cell::UnsafeCell;
use core::ffi::c_char;
use core::sync::atomic::{AtomicU64, Ordering};
use core::{fmt, ptr, slice};

use ptr::NonNull;

use crate::errors::{ErrorFormatContext, UBInfo};
use crate::tree_borrows::data_structures::UniIndex;
use crate::AllocId;

/// We link against the Rust component of our runtime
/// via weak symbols. Unless we intervene, the linker
/// will always discard the Rust component, because
/// strong dependencies are necessary to "pull" a symbol
/// from a static archive. To avoid this situation, we
/// define a dedicated, unused "anchor" symbol on the Rust
/// side to create a strong link between the two components.
/// When we run BorrowSanitizer in no-op mode, we define
/// this symbol manually by passing a flag to the linker.
#[unsafe(no_mangle)]
extern "C" fn __bsan_rust_runtime_anchor() {}

/// Thread-local slot for a boxed `(UBInfo, Span)` set by `handle_error` and
/// consumed by `__bsan_format_pending_ub` once the C++ side has captured the
/// stack and located the first user-code frame.
#[thread_local]
pub(crate) static PENDING_ERROR: UnsafeCell<*mut (UBInfo, Span)> =
    UnsafeCell::new(core::ptr::null_mut());

/// We use a slab allocator to create allocation-level metadata. The slab
/// hands out 128-byte "blocks" of memory.
pub type Block = [u8; 128];

/// A type that can be stored within a [`Block`].
unsafe trait Blockable: Sized {
    fn into(ptr: NonNull<Block>) -> NonNull<Self>;
    fn validate() {
        assert!(size_of::<Self>() == size_of::<Block>());
        assert!(align_of::<Self>() == size_of::<Block>());
    }
}

/// Unique identifier for a node within the tree
#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BorTag(u64);

impl BorTag {
    #[inline]
    pub fn is_wildcard(self) -> bool {
        self == Self::wildcard()
    }

    #[inline]
    pub fn is_invalid(self) -> bool {
        self == Self::invalid()
    }

    #[inline]
    pub fn is_omnivalid(self) -> bool {
        self == Self::omnivalid()
    }

    #[inline]
    pub fn is_concrete(&self) -> bool {
        self.0 > Self::wildcard().0
    }

    #[inline]
    pub const fn omnivalid() -> Self {
        BorTag(0)
    }

    #[inline]
    pub const fn invalid() -> Self {
        BorTag(1)
    }

    #[inline]
    pub const fn wildcard() -> Self {
        BorTag(2)
    }

    #[inline]
    pub fn get(&self) -> u64 {
        self.0
    }
}

impl Default for BorTag {
    fn default() -> Self {
        BorTag(unsafe { __BSAN_BOR_TAG_CTR.fetch_add(1, Ordering::Relaxed) })
    }
}

impl fmt::Debug for BorTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}>", self.0)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawProvenance {
    info: *mut Block,
    id: AllocId,
    idx: UniIndex,
}

unsafe impl Sync for RawProvenance {}
unsafe impl Send for RawProvenance {}

/// Configuration options set by the user via `BSAN_OPTIONS`.
///
/// This mirrors a definition in the LLVM wrapper (`bsan_flags.h`).
/// New options must be added to each definition, and initialized
/// within `InitializeFlags` in C++.
#[repr(C)]
#[derive(Debug, Clone)]
pub(crate) struct SharedSanitizerFlags {
    pub wildcard: bool,
    pub node_debug_info: bool,
    pub max_compacted_children: usize,
    pub tree_gc_min_nodes: usize,
}

impl Default for SharedSanitizerFlags {
    fn default() -> Self {
        // These values should be kept in sync
        // with those defined in `bsan_flags.inc`
        Self {
            wildcard: true,
            node_debug_info: true,
            max_compacted_children: 16,
            tree_gc_min_nodes: 64,
        }
    }
}

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

pub struct Bridge;

impl Bridge {
    pub fn prepare_error(ub_info: UBInfo, pc: Span) {
        unsafe {
            let old_ptr = *PENDING_ERROR.get();
            if !old_ptr.is_null() {
                drop(alloc::boxed::Box::from_raw(old_ptr));
            }
            let ptr = Box::into_raw(Box::new((ub_info, pc)));
            *PENDING_ERROR.get() = ptr;
            __bsan_had_error = 1;
        }
    }

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
    #[link_name = "__bsan_bor_tag_ctr"]
    unsafe static __BSAN_BOR_TAG_CTR: AtomicU64;

    #[thread_local]
    pub unsafe static mut __bsan_had_error: usize;

    /// Tree-node visits accumulated since the last GC request.
    pub unsafe static __bsan_visits_since_gc: core::sync::atomic::AtomicUsize;

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
    fn __bsan_abort() -> !;
}

/// Called from the `HANDLE_ERROR` C++ macro after the stack trace has been
/// captured and the first user-code frame PC has been located.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __bsan_format_pending_ub(user_frame_pc: usize) {
    let ptr = unsafe { *PENDING_ERROR.get() };
    if ptr.is_null() {
        return;
    }
    unsafe { *PENDING_ERROR.get() = core::ptr::null_mut() };
    let (ub_info, original_pc) = unsafe { *alloc::boxed::Box::from_raw(ptr) };
    let (primary, origin) =
        crate::sanitizer_common::Bridge::resolve_error_location(user_frame_pc, original_pc);
    let mut ctx = ErrorFormatContext::default();
    crate::eprint!("error: {}", ctx.display_ub(ub_info, primary, origin));
}
