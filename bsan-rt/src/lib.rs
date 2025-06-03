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
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr::NonNull;
use core::{fmt, mem, ptr};

mod global;
use bsan_shared::RetagInfo;
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

macro_rules! println {
    ($($arg:tt)*) => {
        libc_print::std_name::println!($($arg)*);
    };
}
pub(crate) use println;

pub type MMap = unsafe extern "C" fn(*mut c_void, usize, i32, i32, i32, off_t) -> *mut c_void;
pub type MUnmap = unsafe extern "C" fn(*mut c_void, usize) -> i32;
pub type Malloc = unsafe extern "C" fn(usize) -> *mut c_void;
pub type Free = unsafe extern "C" fn(*mut c_void);
pub type Exit = unsafe extern "C" fn() -> !;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct BsanHooks {
    alloc: BsanAllocHooks,
    mmap: MMap,
    munmap: MUnmap,
    exit: Exit,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BsanAllocHooks {
    malloc: Malloc,
    free: Free,
}

unsafe impl Allocator for BsanAllocHooks {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        unsafe {
            match layout.size() {
                0 => Ok(NonNull::slice_from_raw_parts(layout.dangling(), 0)),
                size => {
                    let ptr = (self.malloc)(layout.size());
                    if ptr.is_null() {
                        return Err(AllocError);
                    }
                    let ptr = NonNull::new_unchecked(ptr as *mut u8);
                    Ok(NonNull::slice_from_raw_parts(ptr, size))
                }
            }
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        unsafe {
            let ptr = mem::transmute::<*mut u8, *mut libc::c_void>(ptr.as_ptr());
            (self.free)(ptr);
        }
    }
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
#[derive(Clone, Copy, Debug)]
pub struct Provenance {
    pub alloc_id: AllocId,
    pub bor_tag: BorTag,
    pub alloc_info: *mut c_void,
}

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
extern "C" fn __bsan_init() {
    unsafe {
        let ctx = init_global_ctx(global::DEFAULT_HOOKS);
        init_local_ctx(ctx);
    }
    ui_test!("bsan_init");
}

/// Deinitializes the global state of the runtime library.
/// We assume the global invariant that no other API functions
/// will be called after this function has executed.
#[unsafe(no_mangle)]
extern "C" fn __bsan_deinit() {
    ui_test!("bsan_deinit");
    unsafe {
        deinit_local_ctx();
        deinit_global_ctx();
    }
}

/// Creates a new borrow tag for the given provenance object.
#[unsafe(no_mangle)]
extern "C" fn __bsan_retag(prov: *mut Provenance, size: usize, perm_kind: u8, protector_kind: u8) {
    let _ = unsafe { RetagInfo::from_raw(size, perm_kind, protector_kind) };
}

/// Records a read access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
extern "C" fn __bsan_read(prov: *const Provenance, addr: usize, access_size: u64) {}

/// Records a write access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
extern "C" fn __bsan_write(prov: *const Provenance, addr: usize, access_size: u64) {}

/// Copies the provenance stored in the range `[src_addr, src_addr + access_size)` within the shadow heap
/// to the address `dst_addr`. This function will silently fail, so it should only be called in conjunction with
/// `bsan_read` and `bsan_write` or as part of an interceptor.
#[unsafe(no_mangle)]
extern "C" fn __bsan_shadow_copy(dst_addr: usize, src_addr: usize, access_size: usize) {}

/// Clears the provenance stored in the range `[dst_addr, dst_addr + access_size)` within the
/// shadow heap. This function will silently fail, so it should only be called in conjunction with
/// `bsan_read` and `bsan_write` or as part of an interceptor.
#[unsafe(no_mangle)]
extern "C" fn __bsan_shadow_clear(addr: usize, access_size: usize) {}

/// Loads the provenance of a given address from shadow memory and stores
/// the result in the return pointer.
#[unsafe(no_mangle)]
extern "C" fn __bsan_load_prov(prov: *mut Provenance, addr: usize) {
    debug_assert!(!prov.is_null());
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();

    unsafe {
        *prov = heap.load_prov(addr);
    }
}

/// Stores the given provenance value into shadow memory at the location for the given address.
#[unsafe(no_mangle)]
extern "C" fn __bsan_store_prov(prov: *const Provenance, addr: usize) {
    debug_assert!(!prov.is_null());

    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();

    heap.store_prov(ctx.hooks(), prov, addr);
}

/// Pushes a shadow stack frame
#[unsafe(no_mangle)]
extern "C" fn __bsan_push_frame() {}

/// Pops a shadow stack frame, deallocating all shadow allocations created by `bsan_alloc_stack`
#[unsafe(no_mangle)]
extern "C" fn __bsan_pop_frame() {}

// Registers a heap allocation of size `size`
#[unsafe(no_mangle)]
extern "C" fn __bsan_alloc(prov: *mut MaybeUninit<Provenance>, addr: usize, size: usize) {
    debug_assert!(!prov.is_null());
    unsafe {
        (*prov).write(Provenance::null());
    }
}

/// Registers a stack allocation of size `size`.
#[unsafe(no_mangle)]
extern "C" fn __bsan_alloc_stack(prov: *mut MaybeUninit<Provenance>, size: usize) {
    debug_assert!(!prov.is_null());
    unsafe {
        (*prov).write(Provenance::null());
    }
}

/// Deregisters a heap allocation
#[unsafe(no_mangle)]
extern "C" fn __bsan_dealloc(prov: *mut Provenance) {}

/// Marks the borrow tag for `prov` as "exposed," allowing it to be resolved to
/// validate accesses through "wildcard" pointers.
#[unsafe(no_mangle)]
extern "C" fn __bsan_expose_tag(prov: *const Provenance) {}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    loop {}
}
