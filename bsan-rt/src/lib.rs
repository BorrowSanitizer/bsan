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
#![feature(nonnull_provenance)]
#![feature(core_intrinsics)]
#![feature(yeet_expr)]
#![feature(unsafe_cell_access)]

#[macro_use]
extern crate alloc;

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::fmt::Debug;
use core::num::NonZero;
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr::NonNull;
use core::{fmt, mem, ptr};

use bsan_shared::{AccessKind, RetagInfo, Size};
use libc_print::std_name::*;
use spin::Mutex;

mod global;
pub use global::*;

mod local;
pub use local::*;

pub mod borrow_tracker;
use borrow_tracker::*;

mod block;
mod diagnostics;
mod shadow;

mod span;
use span::Span;

mod errors;
mod hooks;
mod stack;
mod utils;

use crate::block::Linkable;
use crate::borrow_tracker::tree::Tree;
use crate::hooks::BsanAllocHooks;

macro_rules! println {
    ($($arg:tt)*) => {
        libc_print::std_name::println!($($arg)*);
    };
}
pub(crate) use println;

/// Unique identifier for an allocation
#[repr(transparent)]
#[derive(Default, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct AllocId(usize);

impl AllocId {
    pub fn new(i: usize) -> Self {
        AllocId(i)
    }
    pub fn get(&self) -> usize {
        self.0
    }
    /// An invalid allocation
    pub const fn invalid() -> Self {
        AllocId(0)
    }

    /// Represents any valid allocation
    pub const fn wildcard() -> Self {
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
        Provenance::null()
    }
}

impl Provenance {
    /// The default provenance value, which is assigned to dangling or invalid
    /// pointers.
    const fn null() -> Self {
        Provenance {
            alloc_id: AllocId::invalid(),
            bor_tag: BorTag::new(0),
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
pub union FreeListAddrUnion {
    free_list_next: *mut AllocInfo,
    // Must be a raw pointer for union field access safety
    base_addr: *mut u8,
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
struct ProvenanceArrayView {
    len: usize,
    curr: usize,
    data: *mut Provenance,
}

impl ProvenanceArrayView {
    fn new(len: usize, data: *mut Provenance) -> Self {
        Self { len, curr: 0, data }
    }
}

impl Extend<Provenance> for ProvenanceArrayView {
    fn extend<T: IntoIterator<Item = Provenance>>(&mut self, iter: T) {
        for elem in iter {
            if self.curr < self.len {
                unsafe { *self.data.add(self.curr) = elem }
                self.curr += 1;
            }
        }
    }
}

impl Iterator for ProvenanceArrayView {
    type Item = Provenance;

    fn next(&mut self) -> Option<Self::Item> {
        if self.curr == self.len {
            None
        } else {
            unsafe { Some(*self.data.add(self.curr)) }
        }
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
#[derive(Debug, Default)]
#[repr(C)]
pub struct AllocInfo {
    pub alloc_id: AllocId,
    pub base_addr: FreeListAddrUnion,
    pub size: usize,
    pub align: usize,
    pub tree_lock: Mutex<Option<tree::Tree<BsanAllocHooks>>>,
}

unsafe impl Linkable<AllocInfo> for AllocInfo {
    fn next(&mut self) -> *mut *mut AllocInfo {
        // we are re-using the space of base_addr to store the free list pointer
        // SAFETY: this is safe because both union fields are raw pointers
        unsafe { &raw mut self.base_addr.free_list_next }
    }
}
/// Initializes the global state of the runtime library.
/// The safety of this library is entirely dependent on this
/// function having been executed. We assume the global invariant that
/// no other API functions will be called prior to that point.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_init() {
    unsafe {
        let ctx = init_global_ctx(hooks::DEFAULT_HOOKS);
        init_local_ctx(ctx);
    }
    ui_test!("bsan_init");
}

/// Deinitializes the global state of the runtime library.
/// We assume the global invariant that no other API functions
/// will be called after this function has executed.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_deinit() {
    ui_test!("bsan_deinit");
    unsafe {
        deinit_local_ctx();
        deinit_global_ctx();
    }
}

/// Creates a new borrow tag for the given provenance object.
// TODO: Retag is often called more than __bsan_alloc, should look into where we should init the tree
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_retag(
    object_addr: *mut c_void,
    access_size: usize,
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    perm_kind: u16,
    protector_kind: u8,
    access_kind: u8,
) {
    let global_ctx = unsafe { global_ctx() };
    let local_ctx = unsafe { local_ctx_mut() };
    let prov = Provenance { alloc_id, bor_tag, alloc_info };
    let retag_info =
        unsafe { RetagInfo::from_raw(access_size, perm_kind, protector_kind, access_kind) };
    let bt = BorrowTracker::new(prov, object_addr, Some(access_size));
    let _ = bt.iter().flatten().try_for_each(|bt| bt.retag(global_ctx, local_ctx, retag_info));
}

/// Records a read access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_read(
    ptr: *mut c_void,
    access_size: usize,
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
) {
    // Assuming root tag has been initialized in the tree
    let global_ctx = unsafe { global_ctx() };
    let prov = Provenance { alloc_id, bor_tag, alloc_info };
    let bt = BorrowTracker::new(prov, ptr, Some(access_size));
    let _ = bt.iter().flatten().try_for_each(|bt| bt.access(global_ctx, AccessKind::Read));
}

/// Records a write access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_write(
    ptr: *mut c_void,
    access_size: usize,
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
) {
    let global_ctx = unsafe { global_ctx() };
    let prov = Provenance { alloc_id, bor_tag, alloc_info };
    let bt = BorrowTracker::new(prov, ptr, Some(access_size));
    let _ = bt.iter().flatten().try_for_each(|bt| bt.access(global_ctx, AccessKind::Write));
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
    let mut bt = BorrowTracker::new(prov, ptr, None);
    let _ = bt.iter_mut().flatten().try_for_each(|bt| bt.dealloc(global_ctx));
}

// Registers a heap allocation of size `size`, storing its provenance in the return pointer.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_alloc(
    base_addr: *mut u8,
    size: usize,
    alloc_id: AllocId,
    bor_tag: BorTag,
) -> NonNull<AllocInfo> {
    let ctx = unsafe { global_ctx() };

    // Initialize `AllocInfo`
    let mut alloc_info = unsafe {
        ctx.allocate_lock_location(AllocInfo {
            alloc_id,
            base_addr: FreeListAddrUnion { base_addr },
            size,
            align: 0,
            tree_lock: Mutex::new(None),
        })
    };

    // Initialize the tree once
    unsafe {
        let mut tree = alloc_info.as_mut().tree_lock.lock();
        let _ = tree.insert(Tree::new_in(
            bor_tag,
            Size::from_bytes(size),
            Span::new(),
            ctx.allocator(),
        ));
    }
    alloc_info
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_new_alloc_id() -> AllocId {
    let global_ctx = unsafe { global_ctx() };
    global_ctx.new_alloc_id()
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_new_tag() -> BorTag {
    let global_ctx = unsafe { global_ctx() };
    global_ctx.new_borrow_tag()
}

/// Copies the provenance stored in the range `[src_addr, src_addr + access_size)` within the shadow heap
/// to the address `dst_addr`. This function will silently fail, so it should only be called in conjunction with
/// `bsan_read` and `bsan_write` or as part of an interceptor.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_shadow_copy(src: *mut u8, dst: *mut u8, access_size: usize) {
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();
    heap.memcpy(ctx.hooks(), src.addr(), dst.addr(), access_size);
}

/// Clears the provenance stored in the range `[dst_addr, dst_addr + access_size)` within the
/// shadow heap.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_shadow_clear(dst: *mut u8, access_size: usize) {
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();
    heap.clear(dst.addr(), access_size);
}

/// Loads the provenance of a given address from shadow memory and stores
/// the result in the return pointer.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_get_shadow_src(addr: *mut u8) -> *const Provenance {
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();
    heap.get_src(addr.addr())
}

/// Stores the given provenance value into shadow memory at the location for the given address.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_get_shadow_dest(addr: *mut u8) -> *mut Provenance {
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();
    heap.get_dest(ctx.hooks(), addr.addr())
}

/// Copies provenance values from an array into three consecutive arrays of their components.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_join_provenance(
    dest: *mut Provenance,
    length: usize,
    id_buffer: *mut usize,
    tag_buffer: *mut usize,
    info_buffer: *mut *mut c_void,
) {
    let info_buffer = info_buffer.cast::<*mut AllocInfo>();
    for offset in 0..length {
        unsafe {
            let alloc_id = AllocId(*id_buffer.add(offset));
            let bor_tag = BorTag(*tag_buffer.add(offset));
            let alloc_info = *info_buffer.add(offset);
            *dest.add(offset) = Provenance { alloc_id, bor_tag, alloc_info };
        }
    }
}

/// Copies provenance values from an array into three consecutive arrays of their components.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_split_provenance(
    array: *mut Provenance,
    length: usize,
    id_buffer: *mut AllocId,
    tag_buffer: *mut BorTag,
    info_buffer: *mut *mut c_void,
) {
    let info_buffer = info_buffer.cast::<*mut AllocInfo>();
    for offset in 0..length {
        unsafe {
            let Provenance { alloc_id, bor_tag, alloc_info } = *array.add(offset);
            *id_buffer = alloc_id;
            *tag_buffer = bor_tag;
            *info_buffer = alloc_info;
        }
    }
}

/// Load provenance values from the shadow heap into split arrays.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_shadow_load_array(src: *mut u8, data: *mut Provenance, len: usize) {
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();
    let prov_array = ProvenanceArrayView::new(len, data);
    heap.load_consecutive(src.addr(), len, prov_array);
}

/// Copy provenance values from split arrays into the shadow heap.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_shadow_load_vector(
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

/// Store provenance values from the shadow heap into an array.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_shadow_store_array(dst: *mut u8, data: *mut Provenance, len: usize) {
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();
    let prov_array = ProvenanceArrayView::new(len, data);
    heap.store_consecutive(ctx.hooks(), dst.addr(), prov_array);
}

/// Load provenance values from the shadow heap into split arrays.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_shadow_store_vector(
    dst: *mut u8,
    len: usize,
    id_buffer: *mut AllocId,
    tag_buffer: *mut BorTag,
    info_buffer: *mut *mut AllocInfo,
) {
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();
    let prov_vec = ProvenanceVecView::new(len, id_buffer, tag_buffer, info_buffer);
    heap.store_consecutive(ctx.hooks(), dst.addr(), prov_vec);
}

/// Pushes a shadow stack frame
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_push_frame() {
    let local_ctx = unsafe { local_ctx_mut() };
    local_ctx.protected_tags.push_frame();
}

/// Allocates shadow stack space for a number of provenance elements.
/// Used for implementing dynamic allocas.
#[inline(always)]
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_push_elems(elems: usize) -> *mut MaybeUninit<Provenance> {
    let local_ctx: &mut LocalCtx = unsafe { local_ctx_mut() };
    unsafe { local_ctx.provenance.push_elems(elems).as_ptr() }
}

/// Pops a shadow stack frame, deallocating all shadow allocations created by `bsan_alloc_stack`
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_pop_frame() {
    let local_ctx: &mut LocalCtx = unsafe { local_ctx_mut() };
    unsafe {
        local_ctx.protected_tags.pop_frame();
    }
}

/// Marks the borrow tag for `prov` as "exposed," allowing it to be resolved to
/// validate accesses through "wildcard" pointers.
#[allow(unused)]
#[unsafe(no_mangle)]
extern "C" fn __bsan_expose_tag(alloc_id: usize, bor_tag: usize, alloc_info: *mut c_void) {}

#[cfg(test)]
mod test {
    use super::*;

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
            let alloc_info = __bsan_alloc(base_addr.cast::<u8>(), size, alloc_id, bor_tag).as_ptr();
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

    // Below tests should panic due to unwrap call in end points
    // Should display correct error messages in stdout
    // #[test]
    // #[should_panic]
    // fn bsan_dealloc_detect_double_free() {
    //     init_bsan_with_test_hooks();
    //     let m_size = 20;
    //     let some_object_addr = unsafe { libc::malloc(m_size) };
    //     unsafe {
    //         let mut prov = create_metadata(some_object_addr, m_size);

    //         //__bsan_retag(&raw mut prov, 20, 0, 0, some_object_addr);
    //         __bsan_dealloc(&raw mut prov, some_object_addr);
    //         __bsan_dealloc(&mut prov as *mut _, some_object_addr);
    //     }
    // }

    // #[test]
    // #[should_panic]
    // fn bsan_dealloc_detect_invalid_free() {
    //     init_bsan_with_test_hooks();
    //     let m_size = 20;
    //     let some_object_addr = unsafe { libc::malloc(m_size) };
    //     unsafe {
    //         let mut prov = create_metadata(some_object_addr, m_size);
    //         let mut modified_prov = prov;
    //         modified_prov.alloc_id = AllocId::new(99);
    //         __bsan_dealloc(&mut modified_prov as *mut _, some_object_addr);
    //     }
    // }

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
        unsafe { __bsan_init() };
        with_init(|| {
            with_heap_object(|obj, size| unsafe {
                let prov = create_metadata(obj, size);
                __bsan_write(obj, size, prov.alloc_id, prov.bor_tag, prov.alloc_info);
                destroy_metadata(obj, prov);
            });
        });
    }

    // TODO: Implement this test
    // #[test]
    // fn bsan_aliasing_violation() {}
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::intrinsics::abort()
}
