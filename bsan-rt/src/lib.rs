#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), feature(core_intrinsics))]
#![cfg_attr(test, feature(test))]
#![feature(thread_local)]
#![feature(allocator_api)]
#![feature(never_type)]
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

mod local;

mod errors;
mod memory;

use crate::helpers::Size;
use crate::local::{deinit_local_ctx, init_local_ctx};
use crate::sanitizer_common::Span;
use crate::tree_borrows::perms::AccessKind;
use crate::tree_borrows::tree::Tree;

#[thread_local]
#[unsafe(no_mangle)]
pub static mut __BSAN_HAD_ERROR: usize = 0;

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

#[unsafe(no_mangle)]
pub static __BSAN_THREAD_ID_CTR: AtomicUsize = AtomicUsize::new(3);

/// Unique identifier for a thread
#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ThreadId(usize);

impl ThreadId {
    pub fn get(&self) -> usize {
        self.0
    }
}

impl Default for ThreadId {
    fn default() -> Self {
        ThreadId(__BSAN_THREAD_ID_CTR.fetch_add(1, Ordering::Relaxed))
    }
}

impl fmt::Debug for ThreadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "t{}", self.0)
        } else {
            write!(f, "thread{}", self.0)
        }
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
    pub fn is_wildcard(&self) -> bool {
        *self == Self::wildcard()
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
        let global = unsafe { global_ctx() };
        let protector = match global.protected_tags().get_protector_kind(*self) {
            Some(kind) => &format!("{:?}", kind),
            None => "unprotected",
        };
        write!(f, "<{}>({})", self.0, protector)
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

impl Provenance {
    /// The default provenance value, which is assigned to dangling or invalid
    /// pointers.
    #[allow(unused)]
    const fn null() -> Self {
        Provenance { bor_tag: BorTag::invalid(), alloc_info: core::ptr::null_mut() }
    }

    /// Pointers cast from integers receive a "wildcard" provenance value,
    /// which permits any access.
    #[allow(unused)]
    const fn wildcard() -> Self {
        Provenance { bor_tag: BorTag::omnivalid(), alloc_info: core::ptr::null_mut() }
    }
}

#[derive(Clone, Copy)]
pub(crate) union FreeListAddrUnion {
    pub addr: usize,
    pub free_list_next: Option<NonNull<AllocInfo>>,
}

impl Debug for FreeListAddrUnion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:x}", unsafe { self.addr })
    }
}

/// Every allocation is associated with a "lock" object, which is an instance of `AllocInfo`.
/// Provenance is the "key" to this lock. To validate a memory access, we compare the allocation ID
/// of a pointer's provenance with the value stored in its corresponding `AllocInfo` object. If the values
/// do not match, then the access is invalid. If they do match, then we proceed to validate the access against
/// the tree for the allocation.
#[repr(C)]
pub(crate) struct AllocInfo {
    pub alloc_id: AllocId,
    pub base_addr: FreeListAddrUnion,
    pub size: usize,
    pub tree_lock: Option<Mutex<Tree>>,
}

impl AllocInfo {
    fn invalid() -> Self {
        AllocInfo {
            alloc_id: AllocId::invalid(),
            base_addr: FreeListAddrUnion { addr: 0 },
            size: 0,
            tree_lock: None,
        }
    }

    fn new(base_addr: *mut c_void, size: usize, bor_tag: BorTag, span: Span) -> Self {
        Self {
            alloc_id: AllocId::default(),
            base_addr: FreeListAddrUnion { addr: base_addr.addr() },
            size,
            tree_lock: Some(Mutex::new(Tree::new(bor_tag, Size::from_bytes(size), span))),
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
    Valid { alloc_id: AllocId, base_addr: FreeListAddrUnion, size: usize },
}

/// Initializes the global state of the runtime library.
/// The safety of this library is entirely dependent on this
/// function having been executed. We assume the global invariant that
/// no other API functions will be called prior to that point.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_internal_init() {
    unsafe {
        init_global_ctx();
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

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_local_init(prov: *mut NonNull<Provenance>) {
    unsafe {
        let ctx = global_ctx();
        init_local_ctx(ctx, prov);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_local_deinit() {
    unsafe {
        let ctx = global_ctx();
        deinit_local_ctx(ctx);
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
    pub size: usize,
    pub flags: RetagFlags,
    pub im_layout: Option<&'a [[Size; 2]]>,
    pub pin_layout: Option<&'a [[Size; 2]]>,
}

/// Creates a new borrow tag for the given provenance object.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_retag_impl(
    object_addr: *mut c_void,
    size: usize,
    flags: RetagFlags,
    im_data: *const [Size; 2],
    im_len: usize,
    pin_data: *const [Size; 2],
    pin_len: usize,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    pc: Span,
) -> BorTag {
    debug_bsan!("retag", object_addr, bor_tag, alloc_info);
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };
    let opt_slice = |ptr, len| -> Option<_> {
        (!im_data.is_null()).then(|| unsafe { slice::from_raw_parts(ptr, len) })
    };

    let retag_info = RetagInfo {
        size,
        flags,
        im_layout: opt_slice(im_data, im_len),
        pin_layout: opt_slice(pin_data, pin_len),
    };

    BorrowTracker::retag(ctx, prov, object_addr, retag_info, pc).unwrap_or_else(|err| {
        ctx.handle_error(err, pc);
        bor_tag
    })
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_expose_tag(bor_tag: BorTag, alloc_info: *mut AllocInfo, pc: Span) {
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };
    if let Err(ub) = BorrowTracker::expose(ctx, prov) {
        ctx.handle_error(ub, pc);
    }
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_protector_end_impl(bor_tag: BorTag, alloc_info: *mut AllocInfo, pc: Span) {
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };
    let _ = BorrowTracker::for_alloc(prov, |mut bt| bt.protector_end(ctx, pc));
    ctx.protected_tags_mut().remove_protector(prov.bor_tag);
}

/// Records a read access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_read_impl(
    ptr: *mut c_void,
    access_size: usize,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    pc: Span,
) {
    debug_bsan!("read", ptr, bor_tag, alloc_info);
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };
    BorrowTracker::for_access(prov, ptr, Some(access_size), |mut bt| {
        bt.access(ctx, AccessKind::Read, pc)
    })
    .unwrap_or_else(|err| {
        let _: () = ctx.handle_error(err, pc);
        ().into()
    });
}

/// Records a write access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_write_impl(
    ptr: *mut c_void,
    access_size: usize,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    pc: Span,
) {
    debug_bsan!("write", ptr, bor_tag, alloc_info);
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };

    BorrowTracker::for_access(prov, ptr, Some(access_size), |mut bt| {
        bt.access(ctx, AccessKind::Write, pc)
    })
    .unwrap_or_else(|err| {
        let _: () = ctx.handle_error(err, pc);
        ().into()
    });
}

// Registers a heap allocation of size `size`, storing its provenance in the return pointer.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_alloc(
    base_addr: *mut c_void,
    size: usize,
    bor_tag: BorTag,
    pc: Span,
) -> NonNull<AllocInfo> {
    let ctx = unsafe { global_ctx() };
    #[allow(clippy::let_and_return)]
    let alloc_info = ctx.create_alloc_info(AllocInfo::new(base_addr, size, bor_tag, pc));
    debug_bsan!("alloc", base_addr, bor_tag, alloc_info.as_ptr());
    alloc_info
}

/// Deregisters a heap allocation
#[unsafe(no_mangle)]
extern "C" fn __bsan_dealloc(
    ptr: *mut c_void,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    pc: Span,
) {
    debug_bsan!("dealloc", ptr, bor_tag, alloc_info);
    let ctx = unsafe { global_ctx() };
    let prov: Provenance = Provenance { bor_tag, alloc_info };
    BorrowTracker::for_access(prov, ptr, None, |mut bt| bt.dealloc(ctx, pc)).unwrap_or_else(
        |err| {
            let _: () = ctx.handle_error(err, pc);
            ().into()
        },
    );
    if let Some(alloc_info) = NonNull::new(alloc_info) {
        unsafe { ctx.destroy_alloc_info(alloc_info) };
    }
}

// Registers a heap allocation of size `size`, storing its provenance in the return pointer.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_dealloc_stack_impl(
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    pc: Span,
) {
    debug_bsan!("dealloc", ptr, bor_tag, alloc_info);
    let ctx = unsafe { global_ctx() };
    let prov: Provenance = Provenance { bor_tag, alloc_info };
    if alloc_info.is_null() {
        return;
    }
    if prov.bor_tag == BorTag::invalid() {
        return;
    }
    if unsafe { (*prov.alloc_info).tree_lock.is_none() } {
        return;
    }
    BorrowTracker::for_alloc(prov, |mut bt| bt.dealloc(ctx, pc)).unwrap_or_else(|err| {
        let _: () = ctx.handle_error(err, pc);
        ().into()
    });
}

/// Copies the provenance stored in the range `[src_addr, src_addr + access_size)` within the shadow heap
/// to the address `dst_addr`. This function will silently fail, so it should only be called in conjunction with
/// `bsan_read` and `bsan_write` or as part of an interceptor.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_shadow_transfer(
    dst: *mut c_void,
    src: *const c_void,
    size: usize,
) {
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();
    heap.memcpy(dst.addr(), src.addr(), size)
}

/// Clears the provenance stored in the range `[dst_addr, dst_addr + access_size)` within the
/// shadow heap.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_shadow_clear(dst: *mut c_void, size: usize) {
    let ctx = unsafe { global_ctx() };
    ctx.shadow_heap().clear(dst.addr(), size)
}

/// Loads the provenance of a given address from shadow memory and stores
/// the result in the return pointer.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_shadow(addr: *mut c_void) -> NonNull<Provenance> {
    unsafe { global_ctx().shadow_heap().get(addr.addr()) }
}

/// Stores the given provenance value into shadow memory at the location for the given address.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_rc_store(
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    dest: NonNull<Provenance>,
) {
    let prov = Provenance { bor_tag, alloc_info };
    unsafe { dest.write(prov) };
}

/// Reserves a stack slot for allocation metadata.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_reserve_stack_slot() -> NonNull<AllocInfo> {
    unsafe { global_ctx().create_alloc_info(AllocInfo::invalid()) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_destroy_stack_slot(slot: NonNull<AllocInfo>) {
    let ctx = unsafe { global_ctx() };
    unsafe {
        ctx.destroy_alloc_info(slot);
    }
}

/// Initializes stack allocation metadata in-place.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_alloc_stack_impl(
    base_addr: *mut c_void,
    size: usize,
    bor_tag: BorTag,
    alloc_info: NonNull<AllocInfo>,
    pc: Span,
) {
    debug_bsan!("alloc_stack", base_addr, bor_tag, alloc_info.as_ptr().cast::<AllocInfo>());
    unsafe {
        alloc_info.write(AllocInfo::new(base_addr, size, bor_tag, pc));
    }
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_print(bor_tag: BorTag, alloc_info: *mut AllocInfo) {
    let prov = Provenance { bor_tag, alloc_info };
    crate::println!("{prov:?}");
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_print_borrow_state(bor_tag: BorTag, alloc_info: *mut AllocInfo) {
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };
    let _ = BorrowTracker::for_alloc(prov, |bt| {
        bt.debug_print_tree(ctx, false);
        Ok(())
    });
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_tree_size(bor_tag: BorTag, alloc_info: *mut AllocInfo) {
    let prov = Provenance { bor_tag, alloc_info };
    let _ = BorrowTracker::for_alloc(prov, |bt| {
        crate::println!("Tree size: {}", bt.debug_tree_size());
        Ok(())
    });
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_snapshot(bor_tag: BorTag, alloc_info: *mut AllocInfo) {
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };
    let _ = BorrowTracker::for_alloc(prov, |bt| {
        bt.debug_take_snapshot(ctx);
        Ok(())
    });
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_print_diff(bor_tag: BorTag, alloc_info: *mut AllocInfo) {
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };
    let _ = BorrowTracker::for_alloc(prov, |bt| {
        bt.debug_print_diff(ctx);
        Ok(())
    });
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    eprintln!("The BorrowSanitizer runtime panicked! {:?}", info);
    core::intrinsics::abort()
}
