#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), feature(core_intrinsics))]
#![feature(thread_local)]
#![feature(allocator_api)]
#![allow(internal_features)]

#[macro_use]
extern crate alloc;
use core::cell::Cell;
use core::ffi::c_void;
use core::fmt::Debug;
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::{fmt, ptr, slice};

mod borrow_tracker;
use libc_print::std_name::*;
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
use crate::tree_borrows::tree::AllocStateImpl;
use crate::tree_borrows::AllocState;

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

#[unsafe(no_mangle)]
pub static __BSAN_ALLOC_ID_CTR: AtomicUsize = AtomicUsize::new(3);

/// Unique identifier for an allocation
#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct AllocId(usize);

impl AllocId {
    pub fn get(&self) -> usize {
        self.0
    }
    /// Represents any valid allocation
    pub const fn wildcard() -> Self {
        AllocId(0)
    }

    /// An invalid allocation
    pub const fn invalid() -> Self {
        AllocId(1)
    }

    /// A global or stack allocation, which cannot be manually freed
    pub const fn sticky() -> Self {
        AllocId(2)
    }

    pub const fn min() -> Self {
        AllocId(3)
    }
}

impl Default for AllocId {
    fn default() -> Self {
        AllocId(__BSAN_ALLOC_ID_CTR.fetch_add(1, Ordering::Relaxed))
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
        f.write_fmt(format_args!("{:?}", self))
    }
}

unsafe extern "C" {
    #[link_name = "__bsan_bor_tag_ctr"]
    unsafe static __BSAN_BOR_TAG_CTR: AtomicUsize;
}

/// Unique identifier for a node within the tree
#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BorTag(usize);

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
    pub fn get(&self) -> usize {
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
pub struct Provenance {
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
}

unsafe impl Sync for Provenance {}
unsafe impl Send for Provenance {}

/// Every allocation is associated with a "lock" object, which is an instance of `AllocInfo`.
/// Provenance is the "key" to this lock. To validate a memory access, we compare the allocation ID
/// of a pointer's provenance with the value stored in its corresponding `AllocInfo` object. If the values
/// do not match, then the access is invalid. If they do match, then we proceed to validate the access against
/// the tree for the allocation.
#[repr(C)]
pub struct AllocInfo {
    alloc_id: Cell<AllocId>,
    offset: Cell<Size>,
    size: Cell<Size>,
    tree: Mutex<Option<AllocStateImpl>>,
}

impl AllocInfo {
    fn invalid() -> Self {
        AllocInfo {
            alloc_id: Cell::new(AllocId::invalid()),
            offset: Cell::new(Size::ZERO),
            size: Cell::new(Size::ZERO),
            tree: Mutex::default(),
        }
    }

    fn new(offset: Size, size: Size, bor_tag: BorTag, span: Span) -> Self {
        Self {
            alloc_id: Cell::new(AllocId::default()),
            offset: Cell::new(offset),
            size: Cell::new(size),
            tree: Mutex::new(Some(AllocStateImpl::new(bor_tag, size, span))),
        }
    }

    #[cfg(feature = "debug")]
    fn summarize(&self) -> AllocInfoSummary {
        AllocInfoSummary::Valid {
            alloc_id: self.alloc_id,
            base_addr: self.base_addr,
            size: self.size,
        }
    }
}

/// A shallow version of `AllocInfo`, for use in debug logging.
#[cfg(feature = "debug")]
#[derive(Debug)]
pub(crate) enum AllocInfoSummary {
    Omnivalid,
    /// When Prov is wildcard, AllocInfo is invalid
    Wildcard,
    /// When Prov is null, AllocInfo is invalid
    Null,
    /// When Prov is valid, only drop the tree_lock field
    Valid {
        alloc_id: AllocId,
        base_addr: FreeListAddrUnion,
        size: Size,
    },
}

/// Initializes the global state of the runtime library.
/// The safety of this library is entirely dependent on this
/// function having been executed. We assume the global invariant that
/// no other API functions will be called prior to that point.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_internal_init(flags: NonNull<SharedSanitizerFlags>) {
    unsafe {
        init_global_ctx(flags);
    }
}

/// Deinitializes the global state of the runtime library.
/// We assume the global invariant that no other API functions
/// will be called after this function has executed.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_internal_deinit() {
    unsafe {
        deinit_global_ctx();
    }
}

bitflags::bitflags! {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RetagInfo<'a> {
    pub size: Size,
    pub flags: RetagFlags,
    pub im_layout: Option<&'a [[Size; 2]]>,
    pub pin_layout: Option<&'a [[Size; 2]]>,
}

/// Creates a new borrow tag for the given provenance object.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_retag_impl(
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
) {
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

    let prov = if checked {
        unsafe {
            BorrowTracker::for_access_unchecked(
                ctx,
                prov,
                Size::from_addr(ptr),
                Some(size),
                |mut bt| bt.retag(ctx, retag_info, pc).map(Some),
            )
        }
    } else {
        BorrowTracker::for_access(ctx, prov, Size::from_addr(ptr), Some(size), |mut bt| {
            bt.retag(ctx, retag_info, pc).map(Some)
        })
    }
    .map(|opt| opt.unwrap_or(prov))
    .unwrap_or_else(|err| {
        ctx.handle_error(err, pc);
        prov
    });

    unsafe { dest.write(prov) };
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_protector_end_impl(bor_tag: BorTag, alloc_info: *mut AllocInfo, pc: Span) {
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };
    BorrowTracker::for_alloc_weak(prov, |mut bt| {
        let _ = bt.protector_end(ctx, pc);
    });
}

/// Records a read access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_read_impl(
    ptr: *mut c_void,
    access_size: Size,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    pc: Span,
    checked: bool,
) {
    debug_bsan!("read", ptr, bor_tag, alloc_info);
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };
    if checked {
        unsafe {
            BorrowTracker::for_access_unchecked(
                ctx,
                prov,
                Size::from_addr(ptr),
                Some(access_size),
                |mut bt| bt.access(ctx, AccessKind::Read, pc),
            )
        }
    } else {
        BorrowTracker::for_access(ctx, prov, Size::from_addr(ptr), Some(access_size), |mut bt| {
            bt.access(ctx, AccessKind::Read, pc)
        })
    }
    .unwrap_or_else(|err| ctx.handle_error(err, pc));
}

/// Records a write access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_write_impl(
    ptr: *mut c_void,
    access_size: Size,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    pc: Span,
    checked: bool,
) {
    debug_bsan!("write", ptr, bor_tag, alloc_info);
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };
    if checked {
        unsafe {
            BorrowTracker::for_access_unchecked(
                ctx,
                prov,
                Size::from_addr(ptr),
                Some(access_size),
                |mut bt| bt.access(ctx, AccessKind::Write, pc),
            )
        }
    } else {
        BorrowTracker::for_access(ctx, prov, Size::from_addr(ptr), Some(access_size), |mut bt| {
            bt.access(ctx, AccessKind::Write, pc)
        })
    }
    .unwrap_or_else(|err| ctx.handle_error(err, pc));
}

// Registers a heap allocation of size `size`, storing its provenance in the return pointer.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_alloc_impl(
    base_addr: *mut c_void,
    size: Size,
    bor_tag: BorTag,
    info_dest: NonNull<AllocInfo>,
    pc: Span,
) {
    let ctx = unsafe { global_ctx() };
    let range = AllocRange { start: Size::from_addr(base_addr), size };
    ctx.removing_exposed_provenance(range, false, || {
        let offset = Size::from_addr(base_addr);
        let info = AllocInfo::new(offset, size, bor_tag, pc);
        unsafe {
            info_dest.write(info);
        }
        debug_bsan!("alloc", base_addr, bor_tag, info_dest.as_ptr());
    })
}

/// Deregisters a heap allocation
#[unsafe(no_mangle)]
extern "C" fn __bsan_dealloc(
    ptr: *mut c_void,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    pc: Span,
    checked: bool,
) {
    debug_bsan!("dealloc", ptr, bor_tag, alloc_info);
    let ctx = unsafe { global_ctx() };
    let prov: Provenance = Provenance { bor_tag, alloc_info };

    if checked {
        unsafe {
            BorrowTracker::for_access_unchecked(ctx, prov, Size::from_addr(ptr), None, |bt| {
                bt.dealloc(ctx, pc)
            })
        }
    } else {
        BorrowTracker::for_access(ctx, prov, Size::from_addr(ptr), None, |bt| bt.dealloc(ctx, pc))
    }
    .unwrap_or_else(|err| ctx.handle_error(err, pc));
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_dealloc_stack_impl(
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

/// Increments the reference count associated with a provenance value.
///
/// Returns `true` if the count transitioned from zero to one.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_rc_inc_impl(
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
) -> bool {
    // A null `alloc_info` denotes an empty/cleared shadow slot (e.g. one whose
    // info was nulled by `ClearShadow` while a stale tag lingered). There is no
    // allocation to deref, so there is nothing to count.
    if alloc_info.is_null() {
        return false;
    }
    let prov = Provenance { bor_tag, alloc_info };
    BorrowTracker::for_alloc(prov, |bt| bt.increment()).unwrap_or(false)
}

/// Decrements the reference count associated with a provenance value.
///
/// Returns `true` if the count reached zero.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_rc_dec_impl(
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
) -> bool {
    // See `__bsan_rc_inc_impl`: a null `alloc_info` is an empty shadow slot with
    // no live reference to release.
    if alloc_info.is_null() {
        return false;
    }
    let prov = Provenance { bor_tag, alloc_info };
    BorrowTracker::for_alloc(prov, |bt| bt.decrement()).unwrap_or(false)
}

/// Initializes stack allocation metadata in-place.
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
    global_ctx.removing_exposed_provenance(range, false, || unsafe {
        alloc_info.write(AllocInfo::new(start, size, bor_tag, pc));
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
    match alloc.tree.lock().as_mut() {
        Some(tree) => tree.remove_dead_tags(global_ctx, dead_tags),
        None => {
            // The tree is already deallocated, so we can zero out dead_tags
            dead_tags.fill(BorTag::omnivalid());
            false
        }
    }
}

/// Deallocates an instance of [AllocInfo]. This instance must
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
    core::intrinsics::abort()
}
