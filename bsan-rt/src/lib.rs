//! BorrowSanitizer's "core" runtime library. This library
//! provides APIs for creating and updating allocation-level
//! metadata. This began as a fork of Miri's Tree Borrows
//! implementation. We have adapted it to support concurrent
//! accesses and a different garbage collection algorithm.
#![cfg_attr(not(test), no_std)]
#![feature(thread_local)]
#![feature(allocator_api)]
#![allow(internal_features)]
#[macro_use]
extern crate alloc;

use core::ffi::c_void;
use core::fmt::{self, Debug};
// We use a custom panic handler in release mode,
// which is necessary for `#[no_std]`. However,
// panics are compiled away as aborts, so it is never
// actually executed.
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr::{self, NonNull};
use core::slice;
use core::sync::atomic::{AtomicUsize, Ordering};

use libc_print::std_name::*;

mod borrow_tracker;
use spin::Mutex;
mod tree_borrows;

mod global;
use global::*;
mod helpers;
mod sanitizer_common;
use borrow_tracker::*;

mod errors;

use crate::helpers::{AllocRange, Size};
use crate::sanitizer_common::{SharedSanitizerFlags, Span};
use crate::tree_borrows::perms::AccessKind;
use crate::tree_borrows::refcount::RefCount;
use crate::tree_borrows::Tree;

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

/// A struct for summarizing debug information about memory operations
#[cfg(feature = "debug")]
struct DebugSummary {
    op: &'static str,
    ptr: usize,
    bor_tag: BorTag,
    info: AllocInfoSummary,
}

#[cfg(feature = "debug")]
impl fmt::Display for DebugSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.info {
            AllocInfoSummary::Omnivalid => {
                write!(f, "[{}] 0x{:x} @{:?} -> (omnivalid)", self.op, self.ptr, self.bor_tag)
            }
            AllocInfoSummary::Wildcard => {
                write!(f, "[{}] 0x{:x} @{:?} -> (wildcard)", self.op, self.ptr, self.bor_tag)
            }
            AllocInfoSummary::Null => {
                write!(f, "[{}] 0x{:x} @{:?} -> (null)", self.op, self.ptr, self.bor_tag)
            }
            AllocInfoSummary::Valid { alloc_id, base_addr, size } => write!(
                f,
                "[{}] 0x{:x} @{:?} -> ({:?}, {:?}, {:?})",
                self.op, self.ptr, self.bor_tag, alloc_id, base_addr, size
            ),
        }
    }
}

macro_rules! debug_bsan {
    ($op:literal, $p:ident, $bor_tag:ident, $alloc_info:expr) => {
        #[cfg(feature = "debug")]
        {
            #[allow(unused_unsafe)]
            let info = match $bor_tag.0 {
                0 => AllocInfoSummary::Omnivalid,
                1 => AllocInfoSummary::Null,
                2 => AllocInfoSummary::Wildcard,
                _ => unsafe { &*$alloc_info }.summarize(),
            };
            let summary = DebugSummary { op: $op, ptr: 0, bor_tag: $bor_tag, info };
            libc_print::std_name::println!("{}", summary);
        }
    };
}

/// A global atomic counter used to generate unique allocation IDs.
/// The count begins at 1, to reserve 0 as a default value for
/// uninitialized allocations.
#[unsafe(no_mangle)]
pub static ALLOC_ID_CTR: AtomicUsize = AtomicUsize::new(1);

/// A unique identifier for an allocation
#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq)]
pub struct AllocId(usize);

impl AllocId {
    const ZERO: AllocId = AllocId(0);
    #[must_use]
    pub fn get(&self) -> usize {
        self.0
    }
}

impl Default for AllocId {
    fn default() -> Self {
        AllocId(ALLOC_ID_CTR.fetch_add(1, Ordering::Relaxed))
    }
}

impl fmt::Debug for AllocId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "a{}", self.0)
        } else {
            write!(f, "alloc{}", self.0)
        }
    }
}

impl fmt::Display for AllocId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{self:?}"))
    }
}

// A global atomic counter for generating borrow tags, which
// uniquely identify a node within a tree. This needs to be
// defined within the LLVM core, because it is directly incremented
// by the runtime to create new identifiers.
unsafe extern "C" {
    #[link_name = "__bsan_bor_tag_ctr"]
    unsafe static BOR_TAG_CTR: AtomicUsize;
}

/// Globally unique identifier for a node within a tree.
#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BorTag(usize);

impl BorTag {
    /// Permits any access.
    const OMNIVALID: BorTag = BorTag(0);
    /// Does not permit any access.
    const INVALID: BorTag = BorTag(1);
    /// Optimistically permits accesses through
    /// allocations that have been "exposed" to
    /// pointer to integer conversion.
    const WILDCARD: BorTag = BorTag(2);

    /// Returns `true` if the borrow tag corresponds
    /// to a node within a tree, and is not one of the
    /// values dedicated to omnivalid, invalid, or
    /// wildcard provenance.
    #[inline]
    #[must_use]
    pub fn is_concrete(self) -> bool {
        self > Self::WILDCARD
    }

    /// Returns the integer value of the borrow tag.
    #[inline]
    #[must_use]
    pub fn get(&self) -> usize {
        self.0
    }
}

impl Default for BorTag {
    fn default() -> Self {
        BorTag(unsafe { BOR_TAG_CTR.fetch_add(1, Ordering::Relaxed) })
    }
}

impl fmt::Debug for BorTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}>", self.0)
    }
}

/// Metadata associated with a pointer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Provenance {
    /// An identifier for the node in the tree
    /// containing the access permission for this pointer.
    bor_tag: BorTag,
    /// The allocation that this pointer is permitted to access.
    alloc_info: *mut AllocInfo,
}

/// Metadata associated with an allocation.
#[repr(C)]
pub struct AllocInfo {
    /// The number of provenance values stored within shadow
    /// memory that have a reference to this allocation.
    rc: RefCount,
    /// The state of this allocation: its tree, size, base
    /// address, and other information specific to its lifetime.
    state: Mutex<AllocState>,
}

impl AllocInfo {
    /// Returns invalid allocation metadata. Any attempt to validate
    /// an access using this metadata will throw an error for undefined
    /// behavior.
    fn invalid() -> Self {
        AllocInfo { rc: RefCount::new(), state: Mutex::default() }
    }

    /// Returns a valid metadata for a new allocation.
    fn new(base_addr: Size, size: Size, root_tag: BorTag, span: Span) -> Self {
        AllocInfo {
            rc: RefCount::new(),
            state: Mutex::new(AllocState::new(root_tag, base_addr, size, span)),
        }
    }

    /// Initializes metadata for a new allocation within an existing object,
    /// preserving the reference count.
    fn new_in(dest: NonNull<AllocInfo>, base_addr: Size, size: Size, root_tag: BorTag, span: Span) {
        unsafe {
            let mut init = Self::new(base_addr, size, root_tag, span);
            init.rc = (*dest.as_ptr()).rc.clone();
            dest.write(init);
        }
    }

    #[cfg(feature = "debug")]
    fn summarize(&self) -> AllocInfoSummary {
        let state = self.state.lock();
        AllocInfoSummary::Valid {
            alloc_id: state.alloc_id,
            base_addr: state.base_addr,
            size: state.tree_opt().map_or(Size::ZERO, |tree| tree.size()),
        }
    }
}

/// A shallow version of [`AllocInfo`], for use in debug logging.
#[cfg(feature = "debug")]
#[derive(Debug)]
pub(crate) enum AllocInfoSummary {
    Omnivalid,
    Wildcard,
    Null,
    Valid { alloc_id: AllocId, base_addr: Size, size: Size },
}

/// Initializes the global state of the runtime.
///
/// # Safety
/// This function must be called once when the runtime is initialized.
/// Every other API function depends on this function having been called.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_internal_init(flags: NonNull<SharedSanitizerFlags>) {
    unsafe {
        init_global_ctx(flags);
    }
}

bitflags::bitflags! {
    /// Flags that determine the kind of permission created by a retag.
    /// This must be kept in sync with the definition in `rustc_codegen_ssa`.
    #[repr(C)]
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
    pub struct RetagFlags: u8 {
        /// If this is a function-entry retag.
        const IS_PROTECTED = 1 << 0;
        /// If this is a mutable reference or a `Box`.
        const IS_MUTABLE = 1 << 1;
        /// If this is a `Box`.
        const IS_BOX = 1 << 2;
        /// If the pointee type is `Freeze`
        const IS_FREEZE = 1 << 3;
    }
}

/// The size and kind of permission created by a retag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RetagInfo<'a> {
    /// The initial range of memory for the permission.
    pub size: Size,
    /// The kind of permission.
    pub flags: RetagFlags,
    /// The subranges that should be treated as interior mutable.
    pub im_layout: Option<&'a [[Size; 2]]>,
    /// The subranges that should be treated as `UnsafePinned`
    pub pin_layout: Option<&'a [[Size; 2]]>,
}

/// Creates a new permission within a tree.
/// Retagging is the central mechanism of Tree Borrows. Every
/// operation that creates or moves a reference requires a retag
/// to create a new permission. This function receives a provenance
/// value and retags it to create a new provenance value with the
/// same allocation metadata object, but a different borrow tag. The
/// new value is written to the provided destination. If the provenance
/// value is omnivalid, or the semantics of the retag are a no-op, then
/// the input provenance will be written to the output destination,
/// unchanged. Returns `true` if the call triggered undefined behavior.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_retag_impl(
    ptr: *mut c_void,
    size: Size,
    flags: RetagFlags,
    im_data: Option<NonNull<[Size; 2]>>,
    im_len: usize,
    pin_data: Option<NonNull<[Size; 2]>>,
    pin_len: usize,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    dest: NonNull<Provenance>,
    pc: Span,
    checked: bool,
) -> bool {
    debug_bsan!("retag", object_addr, bor_tag, alloc_info);
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };
    let opt_slice = |opt_ptr: Option<NonNull<[Size; 2]>>, len| -> Option<_> {
        opt_ptr.map(|ptr| unsafe { slice::from_raw_parts(ptr.as_ptr(), len) })
    };

    let retag_info = RetagInfo {
        size,
        flags,
        im_layout: opt_slice(im_data, im_len),
        pin_layout: opt_slice(pin_data, pin_len),
    };

    let offset = Size::from_addr(ptr);
    let retag_res = if checked {
        unsafe {
            BorrowTracker::for_access_unchecked(ctx, prov, offset, size, |mut bt| {
                bt.retag(ctx, retag_info, pc).map(Some)
            })
        }
    } else {
        BorrowTracker::for_access(ctx, prov, offset, Some(size), |mut bt| {
            bt.retag(ctx, retag_info, pc).map(Some)
        })
    };

    let prov = match retag_res {
        // The retag succeeded, creating a new provenance value.
        Ok(Some(prov)) => prov,
        // The retag was a no-op, write the input provenance unchanged.
        Ok(None) => prov,
        // This retag was UB. Prepare the contents of the error message and
        // return true, indicating to the caller that there was an error.
        Err(err) => {
            ctx.handle_error(err, pc);
            return true;
        }
    };
    unsafe { dest.write(prov) };
    false
}

/// Removes a protector for the permission specified by the provenance value. This will
/// never trigger undefined behavior.
#[unsafe(no_mangle)]
extern "C" fn __bsan_protector_end_impl(bor_tag: BorTag, alloc_info: *mut AllocInfo, pc: Span) {
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };
    BorrowTracker::for_alloc_weak(prov, |mut bt| {
        let _ = bt.protector_end(ctx, pc);
    });
}

/// Applies the effects of a read access for the given size, base address, and provenance.
/// Returns `true` if the access was undefined behavior,
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_read_impl(
    ptr: *mut c_void,
    access_size: Size,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    pc: Span,
    checked: bool,
) -> bool {
    debug_bsan!("read", ptr, bor_tag, alloc_info);
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };
    let acc_res = if checked {
        unsafe {
            BorrowTracker::for_access_unchecked(
                ctx,
                prov,
                Size::from_addr(ptr),
                access_size,
                |mut bt| bt.access(ctx, AccessKind::Read, pc),
            )
        }
    } else {
        BorrowTracker::for_access(ctx, prov, Size::from_addr(ptr), Some(access_size), |mut bt| {
            bt.access(ctx, AccessKind::Read, pc)
        })
    };
    if let Err(err) = acc_res {
        ctx.handle_error(err, pc);
        true
    } else {
        false
    }
}

/// Applies the effects of a read access for the given size, base address, and provenance.
/// Returns `true` if the access was undefined behavior,
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_write_impl(
    ptr: *mut c_void,
    access_size: Size,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    pc: Span,
    checked: bool,
) -> bool {
    debug_bsan!("write", ptr, bor_tag, alloc_info);
    let ctx = unsafe { global_ctx() };
    let offset = Size::from_addr(ptr);
    let prov = Provenance { bor_tag, alloc_info };
    let acc_res = if checked {
        unsafe {
            BorrowTracker::for_access_unchecked(ctx, prov, offset, access_size, |mut bt| {
                bt.access(ctx, AccessKind::Write, pc)
            })
        }
    } else {
        BorrowTracker::for_access(ctx, prov, offset, Some(access_size), |mut bt| {
            bt.access(ctx, AccessKind::Write, pc)
        })
    };
    if let Err(err) = acc_res {
        ctx.handle_error(err, pc);
        true
    } else {
        false
    }
}

// Creates a new metadata object for an allocation of the given size and base address.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_alloc_impl(
    base_addr: *mut c_void,
    size: Size,
    bor_tag: BorTag,
    dest: NonNull<AllocInfo>,
    pc: Span,
) {
    let ctx = unsafe { global_ctx() };
    let range = AllocRange { start: Size::from_addr(base_addr), size };
    ctx.removing_exposed_provenance(range, false, || {
        unsafe {
            dest.write(AllocInfo::new(Size::from_addr(base_addr), size, bor_tag, pc));
        }
        debug_bsan!("alloc", base_addr, bor_tag, dest.as_ptr());
    })
}

/// Applies the effects of a deallocation for the given base address and provenance.
/// Returns `true` if the access was undefined behavior.
#[unsafe(no_mangle)]
extern "C" fn __bsan_dealloc(
    ptr: *mut c_void,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    pc: Span,
    checked: bool,
) -> bool {
    debug_bsan!("dealloc", ptr, bor_tag, alloc_info);
    let ctx = unsafe { global_ctx() };
    let offset = Size::from_addr(ptr);
    let prov: Provenance = Provenance { bor_tag, alloc_info };
    let acc_res = if checked {
        BorrowTracker::for_alloc(prov, |bt| bt.dealloc(ctx, pc))
    } else {
        BorrowTracker::for_access(ctx, prov, offset, None, |bt| bt.dealloc(ctx, pc))
    };
    if let Err(err) = acc_res {
        ctx.handle_error(err, pc);
        true
    } else {
        false
    }
}

/// Increments the reference count associated with a provenance value,
/// returning `true` if the count transitioned from zero to one.
///
/// If the state associated with this allocation has been invalidated,
/// then the reference count update is applied to the allocation as a whole.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_rc_inc_impl(bor_tag: BorTag, alloc_info: *mut AllocInfo) -> bool {
    let prov = Provenance { bor_tag, alloc_info };
    BorrowTracker::increment(prov)
}

/// Decrements the reference count associated with the given provenance value,
/// returning `true` if the count transitioned from zero to one.
///
/// If the state associated with this allocation has been invalidated,
/// then the reference count update is applied to the allocation as a whole.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_rc_dec_impl(bor_tag: BorTag, alloc_info: *mut AllocInfo) -> bool {
    let prov = Provenance { bor_tag, alloc_info };
    BorrowTracker::decrement(prov)
}

/// Initializes stack allocation metadata in-place, invalidating the
/// provenance associated with this allocation in a previous lifetime.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_alloc_stack_impl(
    base_addr: *mut c_void,
    size: Size,
    bor_tag: BorTag,
    alloc_info: NonNull<AllocInfo>,
    pc: Span,
) {
    debug_bsan!("alloc_stack", base_addr, bor_tag, alloc_info.as_ptr());
    let global_ctx = unsafe { global_ctx() };
    let start = Size::from_addr(base_addr);
    let range = AllocRange { start, size };
    global_ctx.removing_exposed_provenance(range, false, || {
        AllocInfo::new_in(alloc_info, start, size, bor_tag, pc);
    });
}

/// Applies the effects of a deallocation to the given base address and provenance.
/// Used exclusively for stack allocations. If the allocation has already been
/// deallocated then this is a no-op, following LLVM's lifetime.start semantics.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_dealloc_stack_impl(
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    span: Span,
) {
    debug_bsan!("dealloc", ptr, bor_tag, alloc_info);
    let ctx = unsafe { global_ctx() };
    let prov: Provenance = Provenance { bor_tag, alloc_info };
    BorrowTracker::for_alloc_weak(prov, |bt| {
        let _ = bt.dealloc(ctx, span);
    });
}

/// Records that a pointer's provenance has been exposed (e.g. via a
/// pointer-to-integer cast), so that it can later be recovered when an
/// integer is cast back to a pointer with wildcard provenance.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_expose_prov_impl(bor_tag: BorTag, alloc_info: *mut AllocInfo) {
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };
    BorrowTracker::for_alloc_weak(prov, |mut bt| {
        let _ = bt.expose_tag(ctx);
    });
}

/// Prunes a series of nodes that are identified by the list of borrow tags.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_prune(
    alloc_info: NonNull<AllocInfo>,
    bor_tags: *mut BorTag,
    len: usize,
) -> bool {
    let global_ctx = unsafe { global_ctx() };
    let alloc: AllocInfoPtr = alloc_info.into();
    let dead_tags = unsafe { slice::from_raw_parts_mut(bor_tags, len) };
    if let Some(tree) = alloc.state.lock().tree_opt_mut() {
        tree.remove_dead_tags(global_ctx, dead_tags)
    } else {
        // The tree is already deallocated, so we can zero out dead_tags
        dead_tags.fill(BorTag::OMNIVALID);
        false
    }
}

/// Deallocates an allocation metadata object. This instance must
/// be unreachable from any provenance value in shadow memory.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_eject(alloc_info: NonNull<AllocInfo>) {
    unsafe {
        // # Safety
        // Normally, we would have to lock the instance prior
        // to deallocating it. However, we can assume that it is no
        // longer reachable in shadow memory, so it is not subject
        // to races (at least, until it's been returned to the bump
        // allocator by `destroy_alloc_info`).
        drop(alloc_info.replace(AllocInfo::invalid()));
    }
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_print(bor_tag: BorTag, alloc_info: *mut AllocInfo) {
    let prov = Provenance { bor_tag, alloc_info };
    crate::println!("{prov:?}");
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_print_borrow_state(bor_tag: BorTag, alloc_info: *mut AllocInfo) {
    let prov = Provenance { bor_tag, alloc_info };
    BorrowTracker::for_alloc_weak(prov, |bt| {
        bt.debug_print_tree(false);
    });
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_tree_size(bor_tag: BorTag, alloc_info: *mut AllocInfo) {
    let prov = Provenance { bor_tag, alloc_info };
    BorrowTracker::for_alloc_weak(prov, |bt| {
        crate::println!("Tree size: {}", bt.debug_tree_size());
    });
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_snapshot(bor_tag: BorTag, alloc_info: *mut AllocInfo) {
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };
    BorrowTracker::for_alloc_weak(prov, |bt| {
        bt.debug_take_snapshot(ctx);
    });
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_print_diff(bor_tag: BorTag, alloc_info: *mut AllocInfo) {
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };
    BorrowTracker::for_alloc_weak(prov, |bt| bt.debug_print_diff(ctx));
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    eprintln!("The BorrowSanitizer runtime panicked! {:?}", info);
    loop {}
}
