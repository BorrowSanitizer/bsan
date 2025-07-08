#![cfg_attr(not(test), no_std)]
#![allow(unused)]
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

#[macro_use]
extern crate alloc;
use alloc::alloc::Global;
use alloc::sync::Arc;
use core::alloc::{AllocError, Allocator, GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_ulonglong, c_void};
use core::fmt::Debug;
use core::mem::MaybeUninit;
use core::num::NonZero;
use core::ops::DerefMut;
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};
use core::{fmt, mem, ptr};

use bsan_shared::{RetagInfo, Size};
use libc::{off_t, LOCK_EX};
use libc_print::std_name::*;
use spin::{Mutex, Once};

mod global;
pub use global::*;

mod local;
pub use local::*;

pub mod borrow_tracker;
use borrow_tracker::tree::Tree;
use borrow_tracker::*;

mod block;
mod diagnostics;
mod shadow;

mod span;
use span::Span;

mod hooks;
mod stack;
mod utils;

use crate::block::Linkable;
use crate::borrow_tracker::tree::AllocRange;
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

    /// Pointers cast from integers receive a "wildcard" provenance value, which permits
    /// any access.
    const fn wildcard() -> Self {
        Provenance {
            alloc_id: AllocId::wildcard(),
            bor_tag: BorTag::new(0),
            alloc_info: core::ptr::null_mut(),
        }
    }

    fn is_wildcard(&self) -> bool {
        *self == Provenance::wildcard()
    }

    fn is_null(&self) -> bool {
        *self == Provenance::null()
    }
}

/// A sumtype that represents the base address of `AllocInfo` and used as a pointer to
/// the next free list `AllocInfo` object
pub union FreeListAddrUnion {
    free_list_next: *mut AllocInfo,
    // Must be a raw pointer for union field access safety
    base_addr: *const c_void,
}

impl core::fmt::Debug for FreeListAddrUnion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe { write!(f, "{:?}", self.base_addr) }
    }
}

impl Default for FreeListAddrUnion {
    fn default() -> Self {
        Self { base_addr: core::ptr::null() }
    }
}

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
    pub tree_lock: Mutex<Option<Tree<BsanAllocHooks>>>,
}

// TODO: Discuss whether the initialization and deallocation of the tree should happen
// here
impl AllocInfo {
    /// When we deallocate an allocation, we need to invalidate its metadata.
    /// so that any uses-after-free are detectable.
    fn dealloc(&mut self, ctx: &GlobalCtx) {}

    fn base_addr(&self) -> *const c_void {
        // SAFETY: Both union fields are raw pointers
        unsafe { self.base_addr.base_addr }
    }

    // Calculate the base offset: The difference in bytes between the object
    // address and the base address
    fn base_offset(&self, object_addr: *const c_void) -> Size {
        Size::from_bytes((object_addr as usize).abs_diff(self.base_addr() as usize))
    }

    fn get_raw(prov: *const Provenance) -> *mut Self {
        // Casts the raw void ptr into an AllocInfo raw ptr and reborrows as a `AllocInfo` reference
        unsafe { ((*prov).alloc_info) }
    }
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
extern "C" fn __bsan_retag(
    object_addr: *const c_void,
    prov: *mut Provenance,
    size: usize,
    perm_kind: u16,
    protector_kind: u8,
    access_kind: u8,
) {
    let retag_info = unsafe { RetagInfo::from_raw(size, perm_kind, protector_kind, access_kind) };

    // Get the global context (used for the allocator for now)
    let ctx = unsafe { global_ctx() };

    // TODO: Handle these results with proper errors
    let bt = unsafe { BorrowTracker::new(prov, ctx, object_addr).unwrap() };

    // Now we can assume tree is initialized
    bt.retag(&retag_info).unwrap();
}

/// Records a read access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
extern "C" fn __bsan_read(prov: *const Provenance, addr: *const c_void, access_size: u64) {
    // Assuming root tag has been initialized in the tree
    let ctx = unsafe { global_ctx() };

    let bt = unsafe { BorrowTracker::new(prov, ctx, addr).unwrap() };

    let offset = unsafe { (*(*prov).alloc_info).base_offset(addr) };

    bt.access(
        bsan_shared::AccessKind::Read,
        AllocRange { start: offset, size: Size::from_bytes(access_size) },
    )
    .unwrap();
}

/// Records a write access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
extern "C" fn __bsan_write(prov: *const Provenance, addr: *const c_void, access_size: u64) {
    // Assuming root tag has been initialized in the tree

    let ctx = unsafe { global_ctx() };

    let bt = unsafe { BorrowTracker::new(prov, ctx, addr).unwrap() };

    let offset = unsafe { (*(*prov).alloc_info).base_offset(addr) };
    bt.access(
        bsan_shared::AccessKind::Write,
        AllocRange { start: offset, size: Size::from_bytes(access_size) },
    )
    .unwrap();
}

/// Copies the provenance stored in the range `[src_addr, src_addr + access_size)` within the shadow heap
/// to the address `dst_addr`. This function will silently fail, so it should only be called in conjunction with
/// `bsan_read` and `bsan_write` or as part of an interceptor.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_shadow_copy(dst_addr: usize, src_addr: usize, access_size: usize) {}

/// Clears the provenance stored in the range `[dst_addr, dst_addr + access_size)` within the
/// shadow heap. This function will silently fail, so it should only be called in conjunction with
/// `bsan_read` and `bsan_write` or as part of an interceptor.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_shadow_clear(addr: usize, access_size: usize) {}

/// Loads the provenance of a given address from shadow memory and stores
/// the result in the return pointer.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_load_prov(prov: *mut Provenance, addr: usize) {
    debug_assert!(!prov.is_null());
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();

    unsafe {
        *prov = heap.load_prov(addr);
    }
}

/// Stores the given provenance value into shadow memory at the location for the given address.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_store_prov(prov: *const Provenance, addr: usize) {
    debug_assert!(!prov.is_null());

    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();

    heap.store_prov(ctx.hooks(), prov, addr);
}

/// Pushes a shadow stack frame
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_push_frame(elems: usize) -> *mut MaybeUninit<Provenance> {
    let local_ctx = unsafe { local_ctx_mut() };
    local_ctx.protected_tags.push_frame();
    local_ctx.provenance.push_frame_with(elems).as_ptr()
}

/// Pops a shadow stack frame, deallocating all shadow allocations created by `bsan_alloc_stack`
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_pop_frame() {
    let local_ctx = unsafe { local_ctx_mut() };
    unsafe {
        local_ctx.provenance.pop_frame();
        local_ctx.protected_tags.pop_frame();
    }
}

// Registers a heap allocation of size `size`, storing its provenance in the return pointer.
#[unsafe(no_mangle)]
extern "C" fn __bsan_alloc(
    prov: *mut MaybeUninit<Provenance>,
    object_addr: *const c_void,
    alloc_size: usize,
) {
    debug_assert!(!prov.is_null());

    let ctx = unsafe { global_ctx() };
    let bor_tag = ctx.new_bor_tag();
    let alloc_id = ctx.new_alloc_id();
    let allocator = ctx.allocator();

    let prov = unsafe { (*prov).as_mut_ptr() };

    // Initialize `AllocInfo`
    let alloc_info = unsafe {
        ctx.allocate_lock_location(AllocInfo {
            alloc_id,
            base_addr: FreeListAddrUnion { base_addr: object_addr },
            size: alloc_size,
            align: 0,
            tree_lock: Mutex::new(None),
        })
        .as_mut()
    };

    // Initialize the tree once
    unsafe {
        alloc_info.tree_lock.lock().insert(Tree::new_in(
            bor_tag,
            Size::from_bytes(alloc_size),
            Span::new(),
            ctx.allocator(),
        ));
    }

    unsafe {
        (*prov).alloc_id = alloc_id;
        (*prov).bor_tag = bor_tag;
        (*prov).alloc_info = alloc_info;
    };
}

/// Extends the current stack frame to store `num_elems` additional provenance values.
#[unsafe(no_mangle)]
extern "C" fn __bsan_extend_frame(num_elems: usize) {
    let local_ctx = unsafe { local_ctx_mut() };
    unsafe {
        local_ctx.provenance.push_elems(num_elems);
    }
}

/// Deregisters a heap allocation
#[unsafe(no_mangle)]
extern "C" fn __bsan_dealloc(prov: *mut Provenance, object_addr: *const c_void) {
    // Assuming root tag has been initialized in the tree
    let ctx = unsafe { global_ctx() };
    let mut bt = unsafe { BorrowTracker::new(prov, ctx, object_addr).unwrap() };
    match bt.dealloc(object_addr) {
        Ok(()) => {}
        Err(e) => {
            // TODO: Handle errors here
        }
    }
}

/// Marks the borrow tag for `prov` as "exposed," allowing it to be resolved to
/// validate accesses through "wildcard" pointers.
#[unsafe(no_mangle)]
extern "C" fn __bsan_expose_tag(prov: *const Provenance) {}

#[cfg(test)]
mod test {
    use core::alloc::{GlobalAlloc, Layout};
    use core::fmt::Pointer;
    use core::mem::MaybeUninit;
    use core::ptr::NonNull;

    use bsan_shared::*;

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

    fn create_metadata(object_addr: *const c_void, size: usize) -> Provenance {
        let mut prov = MaybeUninit::<Provenance>::uninit();
        let prov_ptr = (&raw mut prov);
        unsafe {
            __bsan_alloc(prov_ptr, object_addr, size);
            prov.assume_init()
        }
    }

    #[test]
    fn bsan_alloc_increasing_alloc_id() {
        with_init(|| {
            with_heap_object(|obj1, size1| unsafe {
                let mut prov1 = create_metadata(obj1, size1);
                assert_eq!(prov1.alloc_id.get(), 3);
                assert_eq!(AllocId::min().get(), 3);

                with_heap_object(|obj2, size2| {
                    let mut prov2 = create_metadata(obj2, size2);
                    assert_eq!(prov2.alloc_id.get(), 4);
                    __bsan_dealloc(&raw mut prov2, obj2);
                });

                __bsan_dealloc(&raw mut prov1, obj1);
            });
        });
    }

    fn bsan_alloc_and_dealloc() {
        with_init(|| {
            with_heap_object(|obj, size| unsafe {
                let mut prov = create_metadata(obj, size);
                __bsan_dealloc(&raw mut prov, obj);
                let alloc_metadata = &*prov.alloc_info;
                assert_eq!(alloc_metadata.alloc_id.get(), AllocId::invalid().get());
                assert_eq!(alloc_metadata.alloc_id.get(), 0);
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
                let mut prov = create_metadata(obj, size);
                __bsan_read(&raw mut prov, obj, size as u64);
                __bsan_dealloc(&raw mut prov, obj);
            });
        });
    }

    #[test]
    fn bsan_write() {
        unsafe { __bsan_init() };
        with_init(|| {
            with_heap_object(|obj, size| unsafe {
                let mut prov = create_metadata(obj, size);
                __bsan_write(&raw mut prov, obj, size as u64);
                __bsan_dealloc(&raw mut prov, obj);
            });
        });
    }

    // TODO: Implement this test
    // #[test]
    // fn bsan_aliasing_violation() {}
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    core::intrinsics::abort()
}
