#![cfg_attr(not(test), no_std)]
#![allow(internal_features)]
#![warn(clippy::transmute_ptr_to_ptr)]
#![warn(clippy::borrow_as_ptr)]
#![feature(sync_unsafe_cell)]
#![feature(strict_overflow_ops)]
#![feature(thread_local)]
#![feature(allocator_api)]
#![feature(alloc_layout_extra)]
#![feature(format_args_nl)]
#![feature(core_intrinsics)]
#![feature(yeet_expr)]
#![feature(unsafe_cell_access)]
#![feature(stmt_expr_attributes)]

#[macro_use]
extern crate alloc;

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::fmt::Debug;
use core::mem::MaybeUninit;
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr::NonNull;
use core::{fmt, ptr};

use bsan_shared::{AccessKind, RetagInfo, Size};
use libc_print::std_name::*;
use spin::Mutex;

mod global;
pub use global::*;

mod local;
pub use local::*;

pub mod borrow_tracker;
use borrow_tracker::*;

mod diagnostics;

mod span;
use span::Span;

mod memory;

mod errors;

use crate::borrow_tracker::tree::Tree;
use crate::errors::BorsanResult;
use crate::memory::hooks;

macro_rules! println {
    ($($arg:tt)*) => {
        libc_print::std_name::println!($($arg)*);
    };
}

pub(crate) use println;

macro_rules! handle_err {
    ($err:expr, $gtx:expr) => {{
        #[cfg(test)]
        {
            panic!("Error in test mode: {:?}", $err);
        }
        #[cfg(not(test))]
        {
            $gtx.handle_error($err);
        }
    }};
}

/// Unique identifier for an allocation
#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct AllocId(usize);

impl AllocId {
    pub fn new(i: usize) -> Self {
        AllocId(i)
    }
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

impl fmt::Debug for AllocId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "a{}", self.0)
        } else {
            write!(f, "alloc{}", self.0)
        }
    }
}

/// Unique identifier for a thread
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ThreadId(usize);

impl ThreadId {
    pub fn new(i: usize) -> Self {
        ThreadId(i)
    }
    pub fn get(&self) -> usize {
        self.0
    }
}

/// Unique identifier for a node within the tree
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct BorTag(usize);

impl BorTag {
    pub const fn new(i: usize) -> Self {
        BorTag(i)
    }
    pub fn get(&self) -> usize {
        self.0
    }
}

impl fmt::Debug for BorTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}>", self.0)
    }
}

/// Pointers have provenance (RFC #3559). In Tree Borrows, this includes an allocation ID
/// and a borrow tag. We also include a pointer to the "lock" location for the allocation,
/// which contains all other metadata used to detect undefined behavior.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(private_interfaces)]
pub struct Provenance {
    pub alloc_id: AllocId,
    pub bor_tag: BorTag,
    pub alloc_info: *mut AllocInfo,
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
        Provenance {
            alloc_id: AllocId::invalid(),
            bor_tag: BorTag::new(1),
            alloc_info: core::ptr::null_mut(),
        }
    }

    /// Pointers cast from integers receive a "wildcard" provenance value,
    /// which permits any access.
    const fn wildcard() -> Self {
        Provenance {
            alloc_id: AllocId::wildcard(),
            bor_tag: BorTag::new(0),
            alloc_info: core::ptr::null_mut(),
        }
    }
}

/// A sumtype that represents the base address of `AllocInfo` and used as a pointer to
/// the next free list `AllocInfo` object
#[derive(Copy, Clone)]
pub union FreeListAddrUnion {
    free_list_next: Option<NonNull<AllocInfo>>,
    // Must be a raw pointer for union field access safety
    base_addr: *mut c_void,
}

impl fmt::Debug for FreeListAddrUnion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe { write!(f, "{:?}", self.base_addr) }
    }
}

impl Default for FreeListAddrUnion {
    fn default() -> Self {
        Self { base_addr: core::ptr::null_mut() }
    }
}

#[derive(Debug)]
struct ProvenanceVecView {
    len: usize,
    curr: usize,
    id_buffer: *mut AllocId,
    tag_buffer: *mut BorTag,
    info_buffer: *mut *mut AllocInfo,
}

impl ProvenanceVecView {
    fn new(
        len: usize,
        id_buffer: *mut AllocId,
        tag_buffer: *mut BorTag,
        info_buffer: *mut *mut AllocInfo,
    ) -> Self {
        Self { len, curr: 0, id_buffer, tag_buffer, info_buffer }
    }
}

impl Extend<Provenance> for ProvenanceVecView {
    fn extend<T: IntoIterator<Item = Provenance>>(&mut self, iter: T) {
        for elem in iter {
            if self.curr < self.len {
                let Provenance { alloc_id, bor_tag, alloc_info } = elem;
                unsafe {
                    *self.id_buffer.add(self.curr) = alloc_id;
                    *self.tag_buffer.add(self.curr) = bor_tag;
                    *self.info_buffer.add(self.curr) = alloc_info;
                    self.curr += 1;
                }
            }
        }
    }
}

impl Iterator for ProvenanceVecView {
    type Item = Provenance;

    fn next(&mut self) -> Option<Self::Item> {
        if self.curr == self.len {
            None
        } else {
            unsafe {
                let alloc_id = *self.id_buffer.add(self.curr);
                let bor_tag = *self.tag_buffer.add(self.curr);
                let alloc_info = *self.info_buffer.add(self.curr);
                self.curr += 1;
                Some(Provenance { alloc_id, bor_tag, alloc_info })
            }
        }
    }
}

#[unsafe(no_mangle)]
static __BSAN_WILDCARD_PROVENANCE: Provenance = Provenance::wildcard();

#[unsafe(no_mangle)]
static __BSAN_NULL_PROVENANCE: Provenance = Provenance::null();

/// Every allocation is associated with a "lock" object, which is an instance of `AllocInfo`.
/// Provenance is the "key" to this lock. To validate a memory access, we compare the allocation ID
/// of a pointer's provenance with the value stored in its corresponding `AllocInfo` object. If the values
/// do not match, then the access is invalid. If they do match, then we proceed to validate the access against
/// the tree for the allocation.
#[derive(Debug)]
#[repr(C)]
pub struct AllocInfo {
    /// An identifier for this allocation.
    pub alloc_id: AllocId,
    pub base_addr: FreeListAddrUnion,
    pub size: usize,
    pub tree_lock: Mutex<Option<tree::Tree<hooks::BsanAllocHooks>>>,
}

impl AllocInfo {
    unsafe fn force_dealloc(&mut self) {
        self.alloc_id = AllocId::invalid();
        self.base_addr = FreeListAddrUnion { base_addr: ptr::null_mut() };
        self.size = 0;
        self.tree_lock.lock().take();
    }
}

/// Initializes the global state of the runtime library.
/// The safety of this library is entirely dependent on this
/// function having been executed. We assume the global invariant that
/// no other API functions will be called prior to that point.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_init() {
    unsafe {
        let ctx = init_global_ctx(hooks::DEFAULT_HOOKS);
        let _ = init_local_ctx(ctx);
    }
    ui_test!("bsan_init");
}

/// Deinitializes the global state of the runtime library.
/// We assume the global invariant that no other API functions
/// will be called after this function has executed.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_deinit() {
    ui_test!("bsan_deinit");
    unsafe {
        deinit_local_ctx();
        deinit_global_ctx();
    }
}

/// Creates a new borrow tag for the given provenance object.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_retag(
    object_addr: *mut c_void,
    access_size: usize,
    perm: u64,
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
) -> BorTag {
    let global_ctx = unsafe { global_ctx() };
    let local_ctx = unsafe { local_ctx_mut() };
    let prov = Provenance { alloc_id, bor_tag, alloc_info };
    let retag_info = unsafe { RetagInfo::from_raw(access_size, perm) };

    BorrowTracker::new(prov, object_addr, Some(access_size))
        .and_then(|opt| opt.map(|bt| bt.retag(global_ctx, local_ctx, retag_info)).transpose())
        .unwrap_or_else(|err| handle_err!(err, global_ctx))
        .unwrap_or(bor_tag)
}

/// Records a read access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_read(
    ptr: *mut c_void,
    access_size: usize,
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
) {
    let global_ctx = unsafe { global_ctx() };
    let prov = Provenance { alloc_id, bor_tag, alloc_info };
    BorrowTracker::new(prov, ptr, Some(access_size))
        .and_then(|bt| bt.iter().try_for_each(|t| t.access(global_ctx, AccessKind::Read)))
        .unwrap_or_else(|err| handle_err!(err, global_ctx));
}

/// Records a write access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_write(
    ptr: *mut c_void,
    access_size: usize,
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
) {
    let global_ctx = unsafe { global_ctx() };
    let prov = Provenance { alloc_id, bor_tag, alloc_info };
    BorrowTracker::new(prov, ptr, Some(access_size))
        .and_then(|bt| bt.iter().try_for_each(|t| t.access(global_ctx, AccessKind::Write)))
        .unwrap_or_else(|err| handle_err!(err, global_ctx));
}

/// Deregisters a heap allocation
#[unsafe(no_mangle)]
extern "C" fn __bsan_dealloc(
    ptr: *mut c_void,
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
) {
    let global_ctx = unsafe { global_ctx() };
    let prov: Provenance = Provenance { alloc_id, bor_tag, alloc_info };
    BorrowTracker::new(prov, ptr, None)
        .and_then(|mut bt| bt.iter_mut().try_for_each(|t| t.dealloc(global_ctx)))
        .unwrap_or_else(|err| handle_err!(err, global_ctx));
}

// Registers a heap allocation of size `size`, storing its provenance in the return pointer.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_alloc(
    base_addr: *mut c_void,
    size: usize,
    alloc_id: AllocId,
    bor_tag: BorTag,
) -> NonNull<AllocInfo> {
    let ctx = unsafe { global_ctx() };
    unsafe {
        bsan_alloc(ctx, base_addr, size, alloc_id, bor_tag)
            .unwrap_or_else(|info| ctx.handle_error(info))
    }
}

#[inline]
unsafe fn bsan_alloc(
    global_ctx: &GlobalCtx,
    base_addr: *mut c_void,
    size: usize,
    alloc_id: AllocId,
    bor_tag: BorTag,
) -> BorsanResult<NonNull<AllocInfo>> {
    // Initialize `AllocInfo`
    let mut alloc_info = unsafe {
        global_ctx.allocate_lock_location(AllocInfo {
            alloc_id,
            base_addr: FreeListAddrUnion { base_addr },
            size,
            tree_lock: Mutex::new(None),
        })?
    };
    unsafe {
        let mut tree = alloc_info.as_mut().tree_lock.lock();
        let _ = tree.insert(Tree::new_in(
            bor_tag,
            Size::from_bytes(size),
            Span::new(),
            global_ctx.allocator(),
        ));
    }
    Ok(alloc_info)
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_new_alloc_id() -> AllocId {
    let global_ctx = unsafe { global_ctx() };
    global_ctx.new_alloc_id()
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_new_tag() -> BorTag {
    let global_ctx = unsafe { global_ctx() };
    global_ctx.new_borrow_tag()
}

/// Copies the provenance stored in the range `[src_addr, src_addr + access_size)` within the shadow heap
/// to the address `dst_addr`. This function will silently fail, so it should only be called in conjunction with
/// `bsan_read` and `bsan_write` or as part of an interceptor.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_shadow_copy(src: *mut u8, dst: *mut u8, access_size: usize) {
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();
    heap.memcpy(ctx.hooks(), src.addr(), dst.addr(), access_size)
        .unwrap_or_else(|info| ctx.handle_error(info.into()))
}

/// Clears the provenance stored in the range `[dst_addr, dst_addr + access_size)` within the
/// shadow heap.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_shadow_clear(dst: *mut u8, access_size: usize) {
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();
    heap.clear(dst.addr(), access_size);
}

/// Loads the provenance of a given address from shadow memory and stores
/// the result in the return pointer.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_shadow_src(addr: *mut u8) -> *const Provenance {
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();
    heap.get_src(addr.addr())
}

/// Stores the given provenance value into shadow memory at the location for the given address.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_shadow_dest(addr: *mut u8) -> *mut Provenance {
    let ctx = unsafe { global_ctx() };
    bsan_shadow_dest(ctx, addr).unwrap_or_else(|info| ctx.handle_error(info))
}

#[inline]
fn bsan_shadow_dest(ctx: &GlobalCtx, addr: *mut u8) -> BorsanResult<*mut Provenance> {
    let heap = ctx.shadow_heap();
    Ok(heap.get_dest(ctx.hooks(), addr.addr())?)
}

/// Copy provenance values from split arrays into the shadow heap.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_shadow_load_vector(
    src: *mut u8,
    len: usize,
    id_buffer: *mut AllocId,
    tag_buffer: *mut BorTag,
    info_buffer: *mut *mut AllocInfo,
) {
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();

    let prov_vec = ProvenanceVecView::new(len, id_buffer, tag_buffer, info_buffer);
    heap.load_consecutive(src.addr(), len, prov_vec);
}

/// Load provenance values from the shadow heap into split arrays.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_shadow_store_vector(
    dst: *mut u8,
    len: usize,
    id_buffer: *mut AllocId,
    tag_buffer: *mut BorTag,
    info_buffer: *mut *mut AllocInfo,
) {
    let ctx = unsafe { global_ctx() };
    let view = ProvenanceVecView::new(len, id_buffer, tag_buffer, info_buffer);
    ctx.shadow_heap()
        .store_consecutive(ctx.hooks(), dst.addr(), view)
        .unwrap_or_else(|info| ctx.handle_error(info.into()));
}

/// Reserves a stack slot for allocation metadata.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_reserve_stack_slot() -> NonNull<AllocInfo> {
    let global_ctx = unsafe { global_ctx() };
    let local_ctx = unsafe { local_ctx_mut() };
    local_ctx.allocas.reserve_slots(1).unwrap_or_else(|info| global_ctx.handle_error(info.into()))
}

/// Initializes stack allocation metadata in-place.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_alloc_in_place(
    base_addr: *mut c_void,
    size: usize,
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: NonNull<MaybeUninit<AllocInfo>>,
) {
    let ctx = unsafe { global_ctx() };
    bsan_alloc_in_place(ctx, base_addr, size, alloc_id, bor_tag, alloc_info)
        .unwrap_or_else(|info| ctx.handle_error(info))
}

#[inline]
fn bsan_alloc_in_place(
    global_ctx: &GlobalCtx,
    base_addr: *mut c_void,
    size: usize,
    alloc_id: AllocId,
    bor_tag: BorTag,
    mut alloc_info: NonNull<MaybeUninit<AllocInfo>>,
) -> BorsanResult<()> {
    unsafe {
        alloc_info.as_mut().write(AllocInfo {
            alloc_id,
            base_addr: FreeListAddrUnion { base_addr },
            size,
            tree_lock: Mutex::new(Some(Tree::new_in(
                bor_tag,
                Size::from_bytes(size),
                Span::new(),
                global_ctx.allocator(),
            ))),
        });
    }
    Ok(())
}

/// Pushes a stack frame
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_push_retag_frame() {
    let global_ctx = unsafe { global_ctx() };
    let local_ctx = unsafe { local_ctx_mut() };
    local_ctx
        .protected_tags
        .push_frame()
        .unwrap_or_else(|info| global_ctx.handle_error(info.into()));
}

/// Pushes a stack frame
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_push_alloca_frame() {
    let ctx = unsafe { global_ctx() };
    let local_ctx = unsafe { local_ctx_mut() };
    local_ctx.allocas.push_frame().unwrap_or_else(|info| ctx.handle_error(info.into()))
}

/// Pushes a stack frame
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_pop_alloca_frame() {
    let local_ctx = unsafe { local_ctx_mut() };
    for info in local_ctx.allocas.current_frame_mut() {
        unsafe { info.force_dealloc() };
    }
    unsafe { local_ctx.allocas.pop_frame() }
}

/// Pushes a stack frame
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_pop_retag_frame() {
    let global_ctx: &GlobalCtx = unsafe { global_ctx() };
    let local_ctx = unsafe { local_ctx_mut() };
    global_ctx.remove_protected_tags(local_ctx.protected_tags.current_frame());
    unsafe { local_ctx.protected_tags.pop_frame() }
}

/// Marks the borrow tag for `prov` as "exposed," allowing it to be resolved to
/// validate accesses through "wildcard" pointers.
#[allow(unused)]
#[unsafe(no_mangle)]
extern "C" fn __bsan_expose_tag(alloc_id: AllocId, bor_tag: BorTag, alloc_info: *mut AllocInfo) {}

// Code is more readable with explicit return
#[allow(clippy::needless_return)]
#[unsafe(no_mangle)]
extern "C" fn __bsan_debug_assert_null(
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
) {
    let global_ctx = unsafe { global_ctx() };
    let prov = Provenance { alloc_id, bor_tag, alloc_info };
    if prov != Provenance::null() {
        crate::eprintln!("Expected null provenance, got {prov:?}");
        global_ctx.exit(1);
    }
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_debug_assert_wildcard(
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
) {
    let global_ctx = unsafe { global_ctx() };
    let prov = Provenance { alloc_id, bor_tag, alloc_info };
    if prov != Provenance::wildcard() {
        crate::eprintln!("Expected wildcard provenance, got {prov:?}");
        global_ctx.exit(1);
    }
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_debug_assert_valid(
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
) {
    let prov = Provenance { alloc_id, bor_tag, alloc_info };
    assert_ne!(prov, Provenance::null());
    assert_ne!(prov, Provenance::wildcard());
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_debug_assert_invalid(
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
) {
    let global_ctx = unsafe { global_ctx() };
    let prov = Provenance { alloc_id, bor_tag, alloc_info };

    if !(prov == Provenance::null() || prov == Provenance::wildcard()) {
        global_ctx.exit(1);
    }
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_debug_print(alloc_id: AllocId, bor_tag: BorTag, alloc_info: *mut AllocInfo) {
    let prov = Provenance { alloc_id, bor_tag, alloc_info };
    crate::println!("{prov:?}");
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    crate::eprintln!("The BorrowSanitizer runtime panicked!");
    crate::eprintln!("{info}");
    core::intrinsics::abort()
}

#[cfg(test)]
mod tests {
    use crate::*;

    fn with_init(unit_test: fn()) {
        unsafe { __bsan_init() };
        unit_test();
        unsafe { __bsan_deinit() };
    }

    fn with_heap_object(unit_test: fn(obj: *mut c_void, size: usize)) {
        let obj = unsafe { libc::malloc(64) };
        unit_test(obj, 64);
        unsafe { libc::free(obj) };
    }

    fn create_metadata(base_addr: *mut c_void, size: usize) -> Provenance {
        unsafe {
            let alloc_id = __bsan_new_alloc_id();
            let bor_tag = __bsan_new_tag();
            let alloc_info = __bsan_alloc(base_addr, size, alloc_id, bor_tag).as_ptr();
            Provenance { alloc_id, bor_tag, alloc_info }
        }
    }

    fn destroy_metadata(ptr: *mut c_void, prov: Provenance) {
        __bsan_dealloc(ptr, prov.alloc_id, prov.bor_tag, prov.alloc_info);
    }

    #[test]
    fn bsan_alloc_increasing_alloc_id() {
        with_init(|| {
            with_heap_object(|obj1, size1| {
                let prov1 = create_metadata(obj1, size1);
                assert_eq!(prov1.alloc_id, AllocId::min());
                with_heap_object(|obj2, size2| {
                    let prov2 = create_metadata(obj2, size2);
                    assert_eq!(prov2.alloc_id, AllocId(AllocId::min().get() + 1));
                    destroy_metadata(obj2, prov2);
                });
                destroy_metadata(obj1, prov1);
            });
        });
    }

    #[test]
    fn bsan_alloc_and_dealloc() {
        with_init(|| {
            with_heap_object(|obj, size| unsafe {
                let prov = create_metadata(obj, size);
                destroy_metadata(obj, prov);
                let alloc_metadata = &*prov.alloc_info;
                assert_eq!(alloc_metadata.alloc_id, AllocId::invalid());
            });
        })
    }

    #[test]
    #[should_panic]
    #[cfg(not(miri))]
    fn bsan_dealloc_detect_double_free() {
        with_init(|| {
            with_heap_object(|obj, size| {
                let prov = create_metadata(obj, size);
                destroy_metadata(obj, prov);
                destroy_metadata(obj, prov);
            })
        });
    }

    #[test]
    #[should_panic]
    #[cfg(not(miri))]
    fn bsan_dealloc_detect_invalid_free() {
        with_init(|| {
            with_heap_object(|obj, size| {
                let prov = create_metadata(obj, size);
                let mut modified_prov = prov;
                modified_prov.alloc_id = AllocId::new(99);
                destroy_metadata(obj, modified_prov);
            });
        })
    }

    #[test]
    fn bsan_read() {
        with_init(|| {
            with_heap_object(|obj: *mut c_void, size: usize| unsafe {
                let prov = create_metadata(obj, size);
                __bsan_read(obj, size, prov.alloc_id, prov.bor_tag, prov.alloc_info);
                destroy_metadata(obj, prov);
            });
        });
    }

    #[test]
    fn bsan_write() {
        with_init(|| {
            with_heap_object(|obj, size| unsafe {
                let prov = create_metadata(obj, size);
                __bsan_write(obj, size, prov.alloc_id, prov.bor_tag, prov.alloc_info);
                destroy_metadata(obj, prov);
            });
        });
    }
}
