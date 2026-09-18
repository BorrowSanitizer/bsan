#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), feature(core_intrinsics))]
#![feature(thread_local)]
#![feature(allocator_api)]
#![allow(internal_features)]
#[macro_use]
extern crate alloc;
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
mod memory;

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

#[unsafe(no_mangle)]
pub static __BSAN_ALLOC_ID_CTR: AtomicUsize = AtomicUsize::new(1);

/// Unique identifier for an allocation
#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
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
        f.write_fmt(format_args!("{self:?}"))
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
    const OMNIVALID: BorTag = BorTag(0);
    const INVALID: BorTag = BorTag(1);
    const WILDCARD: BorTag = BorTag(2);

    #[inline]
    #[must_use]
    pub fn is_concrete(self) -> bool {
        self > Self::WILDCARD
    }

    #[inline]
    #[must_use]
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

#[repr(C)]
pub struct AllocInfo {
    rc: RefCount,
    state: Mutex<AllocState>,
}

impl AllocInfo {
    fn invalid() -> Self {
        AllocInfo { rc: RefCount::new(), state: Mutex::default() }
    }

    fn new(base_addr: Size, size: Size, root_tag: BorTag, span: Span) -> Self {
        AllocInfo {
            rc: RefCount::new(),
            state: Mutex::new(AllocState::new(root_tag, base_addr, size, span)),
        }
    }

    unsafe fn new_in(
        dest: NonNull<AllocInfo>,
        base_addr: Size,
        size: Size,
        root_tag: BorTag,
        span: Span,
    ) {
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

/// Initializes the global state of the runtime library.
/// The safety of this library is entirely dependent on this
/// function having been executed. We assume the global invariant that
/// no other API functions will be called prior to that point.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_internal_init(flags: NonNull<SharedSanitizerFlags>) {
    unsafe {
        init_global_ctx(flags);
    }
}

/// Deinitializes the global state of the runtime library.
/// We assume the global invariant that no other API functions
/// will be called after this function has executed.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_internal_deinit() {
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

    let offset = Size::from_addr(ptr);
    let prov = if checked {
        unsafe {
            BorrowTracker::for_access_unchecked(ctx, prov, offset, size, |mut bt| {
                bt.retag(ctx, retag_info, pc).map(Some)
            })
        }
    } else {
        BorrowTracker::for_access(ctx, prov, offset, Some(size), |mut bt| {
            bt.retag(ctx, retag_info, pc).map(Some)
        })
    }
    .map_or_else(
        |err| {
            ctx.handle_error(err, pc);
            prov
        },
        |opt| opt.unwrap_or(prov),
    );

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

#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_read_impl(
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
                access_size,
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

#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_write_impl(
    ptr: *mut c_void,
    access_size: Size,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    pc: Span,
    checked: bool,
) {
    debug_bsan!("write", ptr, bor_tag, alloc_info);
    let ctx = unsafe { global_ctx() };
    let offset = Size::from_addr(ptr);
    let prov = Provenance { bor_tag, alloc_info };
    if checked {
        unsafe {
            BorrowTracker::for_access_unchecked(ctx, prov, offset, access_size, |mut bt| {
                bt.access(ctx, AccessKind::Write, pc)
            })
        }
    } else {
        BorrowTracker::for_access(ctx, prov, offset, Some(access_size), |mut bt| {
            bt.access(ctx, AccessKind::Write, pc)
        })
    }
    .unwrap_or_else(|err| ctx.handle_error(err, pc));
}

// Registers a heap allocation of size `size`, storing its provenance in the return pointer.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_alloc_impl(
    base_addr: *mut c_void,
    size: Size,
    bor_tag: BorTag,
    pc: Span,
) -> NonNull<AllocInfo> {
    let ctx = unsafe { global_ctx() };
    let range = AllocRange { start: Size::from_addr(base_addr), size };
    ctx.removing_exposed_provenance(range, false, || {
        #[allow(clippy::let_and_return)]
        let alloc_info =
            ctx.create_alloc_info(AllocInfo::new(Size::from_addr(base_addr), size, bor_tag, pc));
        debug_bsan!("alloc", base_addr, bor_tag, alloc_info.as_ptr());
        alloc_info
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
    let offset = Size::from_addr(ptr);
    let prov: Provenance = Provenance { bor_tag, alloc_info };
    if checked {
        BorrowTracker::for_alloc(prov, |bt| bt.dealloc(ctx, pc))
    } else {
        BorrowTracker::for_access(ctx, prov, offset, None, |bt| bt.dealloc(ctx, pc))
    }
    .unwrap_or_else(|err| ctx.handle_error(err, pc));
}

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

/// Reserves a stack slot for allocation metadata.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_reserve_stack_slot_impl() -> NonNull<AllocInfo> {
    unsafe { global_ctx().create_alloc_info(AllocInfo::invalid()) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_destroy_stack_slot_impl(slot: NonNull<AllocInfo>) {
    unsafe { global_ctx().destroy_alloc_info(slot) };
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
        AllocInfo::new_in(alloc_info, start, size, bor_tag, pc);
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
    if let Some(mut state) = alloc.state.try_lock() {
        if let Some(tree) = state.tree_opt_mut() {
            tree.remove_dead_tags(global_ctx, dead_tags)
        } else {
            false
        }
    }else{
        false
    }
}

/// Deallocates an allocation metadata object. This instance must
/// be unreachable from any provenance value in shadow memory.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_eject(alloc_info: NonNull<AllocInfo>) {
    let ctx = unsafe { global_ctx() };
    unsafe {
        // # Safety
        // Normally, we would have to lock the instance prior
        // to deallocating it. However, we can assume that it is no
        // longer reachable in shadow memory, so it is not subject
        // to races (at least, until it's been returned to the bump
        // allocator by `destroy_alloc_info`).
        drop(alloc_info.replace(AllocInfo::invalid()));
        ctx.destroy_alloc_info(alloc_info);
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
