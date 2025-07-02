#![cfg_attr(not(test), no_std)]
#![feature(sync_unsafe_cell)]
#![feature(strict_overflow_ops)]
#![feature(thread_local)]
#![feature(allocator_api)]
#![feature(alloc_layout_extra)]
#![feature(format_args_nl)]
#![allow(unused)]

#[macro_use]
extern crate alloc;
use core::alloc::{AllocError, Allocator, GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_ulonglong, c_void};
use core::mem::MaybeUninit;
use core::num::NonZero;
use core::ops::Index;
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr::{slice_from_raw_parts, NonNull};
use core::{fmt, mem, ptr};

mod global;
use bsan_shared::perms::RetagInfo;
pub use global::*;

mod local;
use libc::off_t;
use libc_print::std_name::*;
pub use local::*;

mod block;
pub mod borrow_tracker;
mod diagnostics;
mod shadow;
mod span;

mod hooks;
mod stack;
mod utils;

macro_rules! println {
    ($($arg:tt)*) => {
        libc_print::std_name::println!($($arg)*);
    };
}
pub(crate) use println;

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
    /// An invalid allocation
    pub const fn null() -> Self {
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
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
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
#[derive(Clone, Copy, Debug)]
pub struct Provenance {
    pub alloc_id: AllocId,
    pub bor_tag: BorTag,
    pub alloc_info: *mut c_void,
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
            alloc_id: AllocId::null(),
            bor_tag: BorTag::new(0),
            alloc_info: core::ptr::null_mut(),
        }
    }

    /// Pointers cast from integers receive a "wildcard" provenance value, which permits
    /// any access.
    const fn wildcard() -> Self {
        Provenance {
            alloc_id: AllocId::wildcard(),
            bor_tag: BorTag::new(0),
            alloc_info: core::ptr::null_mut(),
        }
    }
}

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
            if (self.curr < self.len) {
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

struct ProvenanceVecView {
    len: usize,
    curr: usize,
    id_buffer: *mut usize,
    tag_buffer: *mut usize,
    info_buffer: *mut *mut c_void,
}

impl ProvenanceVecView {
    fn new(
        len: usize,
        id_buffer: *mut usize,
        tag_buffer: *mut usize,
        info_buffer: *mut *mut c_void,
    ) -> Self {
        Self { len, curr: 0, id_buffer, tag_buffer, info_buffer }
    }
}

impl Extend<Provenance> for ProvenanceVecView {
    fn extend<T: IntoIterator<Item = Provenance>>(&mut self, iter: T) {
        for elem in iter {
            if (self.curr < self.len) {
                let Provenance { alloc_id, bor_tag, alloc_info } = elem;
                unsafe {
                    *self.id_buffer.add(self.curr) = alloc_id.0;
                    *self.tag_buffer.add(self.curr) = bor_tag.0;
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
                let alloc_id = AllocId(*self.id_buffer.add(self.curr));
                let bor_tag = BorTag(*self.tag_buffer.add(self.curr));
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
#[repr(C)]
struct AllocInfo {
    pub alloc_id: AllocId,
    pub base_addr: usize,
    pub size: usize,
    pub align: usize,
    pub tree: *mut c_void,
}

impl AllocInfo {
    /// When we deallocate an allocation, we need to invalidate its metadata.
    /// so that any uses-after-free are detectable.
    fn dealloc(&mut self) {
        self.alloc_id = AllocId::null();
        self.base_addr = 0;
        self.size = 0;
        self.align = 1;
        // FIXME: free the tree
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
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_retag(
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut c_void,
    obj_address: *mut c_void,
    size: usize,
    perm_kind: u8,
    protector_kind: u8,
) -> usize {
    let ctx = unsafe { global_ctx() };
    let info = unsafe { RetagInfo::from_raw(size, perm_kind, protector_kind) };
    ctx.new_borrow_tag().0
}

/// Records a read access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_read(
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut c_void,
    ptr: *mut u8,
    access_size: usize,
) {
}

/// Records a write access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_write(
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut c_void,
    ptr: *mut u8,
    access_size: usize,
) {
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
    let ctx = unsafe { global_ctx() };
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
    id_buffer: *mut usize,
    tag_buffer: *mut usize,
    info_buffer: *mut *mut c_void,
) {
    let ctx = unsafe { global_ctx() };
    for offset in 0..length {
        unsafe {
            let Provenance { alloc_id, bor_tag, alloc_info } = *array.add(offset);
            *id_buffer = alloc_id.0;
            *tag_buffer = bor_tag.0;
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
    id_buffer: *mut usize,
    tag_buffer: *mut usize,
    info_buffer: *mut *mut c_void,
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
    id_buffer: *mut usize,
    tag_buffer: *mut usize,
    info_buffer: *mut *mut c_void,
) {
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();
    let prov_vec = ProvenanceVecView::new(len, id_buffer, tag_buffer, info_buffer);
    heap.store_consecutive(ctx.hooks(), dst.addr(), prov_vec);
}

/// Pushes a shadow stack frame
#[inline(always)]
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_push_frame() {
    let local_ctx = unsafe { local_ctx_mut() };
    local_ctx.protected_tags.push_frame();
}

/// Pops a shadow stack frame, deallocating all shadow allocations created by `bsan_alloc_stack`
#[inline(always)]
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_pop_frame() {
    let local_ctx: &mut LocalCtx = unsafe { local_ctx_mut() };
    unsafe {
        local_ctx.protected_tags.pop_frame();
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_new_alloc_id() -> usize {
    let global_ctx = unsafe { global_ctx() };
    global_ctx.new_alloc_id().0
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_new_tag() -> usize {
    let global_ctx = unsafe { global_ctx() };
    global_ctx.new_borrow_tag().0
}

// Registers a heap allocation of size `size`
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_alloc(id: usize, tag: usize, ptr: *mut u8, size: usize) -> *mut c_void {
    core::ptr::null_mut()
}

/// Deregisters a heap allocation
#[unsafe(no_mangle)]
extern "C" fn __bsan_dealloc(
    ptr: *mut u8,
    alloc_id: usize,
    bor_tag: usize,
    alloc_info: *mut c_void,
) {
}

/// Marks the borrow tag for `prov` as "exposed," allowing it to be resolved to
/// validate accesses through "wildcard" pointers.
#[unsafe(no_mangle)]
extern "C" fn __bsan_expose_tag(alloc_id: usize, bor_tag: usize, alloc_info: *mut c_void) {}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    loop {}
}
