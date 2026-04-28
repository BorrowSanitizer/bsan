#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), feature(core_intrinsics))]
#![cfg_attr(test, feature(test))]

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
use core::{fmt, ptr};

use borrow_tracker::{AccessKind, RetagInfo, RetagPtrKind, Size};
use libc_print::std_name::*;
use spin::Mutex;

mod global;
use global::*;
mod helpers;
mod sanitizer_common;

mod borrow_tracker;
use borrow_tracker::*;

mod diagnostics;

mod errors;
mod memory;

use crate::borrow_tracker::tree::Tree;
use crate::sanitizer_common::Span;

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
            AllocInfoSummary::WildCard => {
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
    ($op:literal, $ptr:ident, $bor_tag:ident, $alloc_info:expr) => {
        #[cfg(feature = "debug")]
        {
            #[allow(unused_unsafe)]
            let info = match $bor_tag.0 {
                0 => AllocInfoSummary::WildCard,
                1 => AllocInfoSummary::Null,
                _ => unsafe { &*$alloc_info }.summarize(),
            };
            let summary = DebugSummary { op: $op, ptr: $ptr.addr(), bor_tag: $bor_tag, info };
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

#[unsafe(no_mangle)]
pub static __BSAN_BOR_TAG_CTR: AtomicUsize = AtomicUsize::new(2);

/// Unique identifier for a node within the tree
#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BorTag(usize);

impl BorTag {
    pub const fn wildcard() -> Self {
        BorTag(0)
    }

    pub const fn invalid() -> Self {
        BorTag(1)
    }

    pub fn get(&self) -> usize {
        self.0
    }
}

impl Default for BorTag {
    fn default() -> Self {
        BorTag(__BSAN_BOR_TAG_CTR.fetch_add(1, Ordering::Relaxed))
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

impl Default for Provenance {
    fn default() -> Self {
        Provenance::wildcard()
    }
}

impl Provenance {
    /// The default provenance value, which is assigned to dangling or invalid
    /// pointers.
    const fn null() -> Self {
        Provenance { bor_tag: BorTag::invalid(), alloc_info: core::ptr::null_mut() }
    }

    /// Pointers cast from integers receive a "wildcard" provenance value,
    /// which permits any access.
    const fn wildcard() -> Self {
        Provenance { bor_tag: BorTag::wildcard(), alloc_info: core::ptr::null_mut() }
    }
}

#[unsafe(no_mangle)]
static __BSAN_WILDCARD_PROVENANCE: Provenance = Provenance::wildcard();

#[unsafe(no_mangle)]
static __BSAN_NULL_PROVENANCE: Provenance = Provenance::null();

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
    pub tree_lock: Option<Mutex<tree::Tree>>,
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
            tree_lock: Some(Mutex::new(Tree::new_in(
                bor_tag,
                Size::from_bytes(size),
                span,
                alloc::alloc::Global,
            ))),
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
    /// When Prov is wildcard, AllocInfo is invalid
    WildCard,
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
unsafe extern "C-unwind" fn __bsan_new_bor_tag() -> BorTag {
    BorTag::default()
}

/// Creates a new borrow tag for the given provenance object.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_retag_impl(
    object_addr: *mut c_void,
    access_size: usize,
    is_protected: u8,
    ty_is_freeze: u8,
    _ty_is_unpin: u8,
    ptr_kind: RetagPtrKind,
    im_data: *const [usize; 2],
    im_len: usize,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    pc: Span,
) -> BorTag {
    debug_bsan!("retag", object_addr, bor_tag, alloc_info);
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };
    let retag_info = unsafe {
        RetagInfo::from_raw(access_size, is_protected, ty_is_freeze, ptr_kind, im_data, im_len)
    };
    BorrowTracker::retag(ctx, prov, object_addr, access_size, retag_info, pc).unwrap_or_else(
        |err| {
            ctx.handle_error(err, pc);
            bor_tag
        },
    )
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
    ctx.shadow_heap().clear(dst.addr(), size, __BSAN_WILDCARD_PROVENANCE)
}

/// Loads the provenance of a given address from shadow memory and stores
/// the result in the return pointer.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_shadow_load(addr: *mut c_void, dest: NonNull<Provenance>) {
    unsafe {
        let ctx = global_ctx();
        let prov = ctx.shadow_heap().get_src(addr.addr()).read();
        dest.write(prov);
    }
}

/// Stores the given provenance value into shadow memory at the location for the given address.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_shadow_store(
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    ptr: *mut c_void,
) {
    let ctx = unsafe { global_ctx() };
    let prov = Provenance { bor_tag, alloc_info };
    let dest = ctx.shadow_heap().get_dest(ptr.addr());
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
