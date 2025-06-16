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
use core::fmt::Debug;
use core::mem::MaybeUninit;
use core::num::NonZero;
use core::ops::DerefMut;
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};
use core::{fmt, mem, ptr};

mod global;
use alloc::alloc::Global;
use alloc::sync::Arc;

use borrow_tracker::tree::Tree;
use borrow_tracker::*;
use bsan_shared::{RetagInfo, Size};
pub use global::*;

mod local;
use libc::{off_t, LOCK_EX};
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
use lazy_static::lazy_static;
use parking_lot::{Mutex, Once};
pub(crate) use println;
use span::Span;

use crate::block::Linkable;
use crate::borrow_tracker::tree::AllocRange;

pub type MMap = unsafe extern "C" fn(*mut c_void, usize, i32, i32, i32, off_t) -> *mut c_void;
pub type MUnmap = unsafe extern "C" fn(*mut c_void, usize) -> i32;
pub type Malloc = unsafe extern "C" fn(usize) -> *mut c_void;
pub type Free = unsafe extern "C" fn(*mut c_void);
pub type Exit = unsafe extern "C" fn() -> !;

static ALLOC_COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

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
#[derive(Clone, Copy, Debug)]
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
}

/// A sumtype that represents the base address of `AllocInfo` and used as a pointer to
/// the next free list `AllocInfo` object
union FreeListAddrUnion {
    free_list_next: *mut AllocInfo,
    // Must be a raw pointer for union field access safety
    base_addr: *const c_void,
}

impl core::fmt::Debug for FreeListAddrUnion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe { write!(f, "{:?}", self.base_addr) }
    }
}

// TODO: Implement thread-safety for c_void
// reference: https://github.com/BorrowSanitizer/bsan/issues/35
#[derive(Debug)]
struct TreeThreadSafe(Mutex<*mut c_void>);

unsafe impl Send for TreeThreadSafe {}
unsafe impl Sync for TreeThreadSafe {}

impl TreeThreadSafe {
    pub fn new() -> Self {
        TreeThreadSafe(Mutex::new(core::ptr::null_mut()))
    }

    // SAFETY: Locks the `tree_lock` before performing exclusive access via raw *mut pointer
    unsafe fn lock_tree(&self, tree_lock: &AtomicBool) -> *mut Tree<BsanAllocHooks> {
        let _tree_guard = TreeGuard::set(tree_lock);
        unsafe { (&raw mut (*self.0.lock())) as *mut Tree<BsanAllocHooks> }
    }
}
/// The tree pointer is a ~~lazily unitialized~~ global variable stored in a thread safe wrapper with
/// a mutex
/// The tree is initialized during an allocation via a call to `bt_init_tree`
lazy_static! {
    static ref TREE_PTR: Arc<TreeThreadSafe> = { Arc::new(TreeThreadSafe::new()) };
}

/// A simple RAII TreeGuard that tracks the tree's lock state
// TODO: Discuss the usage of this tree guard, is it an extra abstraction over the existing mutex or is it neccessary?
#[derive(Debug)]
struct TreeGuard<'a> {
    tree_lock: &'a AtomicBool,
}

impl<'a> TreeGuard<'a> {
    pub fn set(flag: &'a AtomicBool) -> Self {
        flag.store(true, Ordering::Release);

        TreeGuard { tree_lock: flag }
    }

    pub fn get(&self) -> bool {
        self.tree_lock.load(Ordering::Acquire)
    }
}

impl<'a> Drop for TreeGuard<'a> {
    fn drop(&mut self) {
        self.tree_lock.store(false, Ordering::Release);
    }
}

/// Every allocation is associated with a "lock" object, which is an instance of `AllocInfo`.
/// Provenance is the "key" to this lock. To validate a memory access, we compare the allocation ID
/// of a pointer's provenance with the value stored in its corresponding `AllocInfo` object. If the values
/// do not match, then the access is invalid. If they do match, then we proceed to validate the access against
/// the tree for the allocation.
#[derive(Debug)]
#[repr(C)]
struct AllocInfo {
    pub alloc_id: AllocId,
    pub base_addr: FreeListAddrUnion,
    pub size: usize,
    pub align: usize,
    pub tree_lock: AtomicBool,
}

// TODO: Discuss whether the initialization and deallocation of the tree should happen
// here
impl AllocInfo {
    /// When we deallocate an allocation, we need to invalidate its metadata.
    /// so that any uses-after-free are detectable.
    fn dealloc(&mut self) {
        self.alloc_id = AllocId::invalid();
        let base_addr_default = 0;
        self.base_addr = FreeListAddrUnion { base_addr: core::ptr::null() };
        self.size = 0;
        self.align = 1;

        // Tree is freed by `__bsan_dealloc`
        // Set the tree pointer to NULL
        let tree_lock = &self.tree_lock;
        let _ = unsafe { TREE_PTR.lock_tree(tree_lock) };

        // SAFETY: Exclusive access to *mut raw pointer is ensured by the above
        // tree lock
        unsafe { *TREE_PTR.0.data_ptr() = core::ptr::null_mut() };
    }

    fn base_addr(&self) -> *const c_void {
        // SAFETY: Both union fields are raw pointers
        unsafe { self.base_addr.base_addr }
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
    let retag_info = unsafe { RetagInfo::from_raw(size, perm_kind, protector_kind) };

    // Get the global context (used for the allocator for now)
    let ctx = unsafe { global_ctx() };

    // Run the validation `middleware`
    // TODO: Handle these results with proper errors
    let alloc_ptr = unsafe { bt_validate_prov(prov, ctx).unwrap() };

    let alloc_info = unsafe { &*alloc_ptr };
    let tree_lock = &alloc_info.tree_lock;

    let mut prov = unsafe { &mut *prov };

    // Initialize the tree if it is uninitialized
    unsafe {
        bt_init_tree(
            TREE_PTR.lock_tree(tree_lock),
            prov.bor_tag,
            Size::from_bytes(size),
            ctx.allocator(),
        )
        .unwrap()
    };

    // Now we can assume tree is initialized
    bt_retag(unsafe { &mut *TREE_PTR.lock_tree(tree_lock) }, prov, ctx, &retag_info).unwrap();
}

/// Records a read access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
extern "C" fn __bsan_read(prov: *const Provenance, addr: usize, access_size: u64) {
    // Assuming root tag has been initialized in the tree
    let ctx = unsafe { global_ctx() };

    let alloc_info_ptr = unsafe { bt_validate_prov(prov, ctx).unwrap() };
    let alloc_info = unsafe { &*alloc_info_ptr };
    let tree_lock = &alloc_info.tree_lock;

    // Safety land
    let prov = unsafe { &*prov };

    bt_access(
        unsafe { &mut *TREE_PTR.lock_tree(tree_lock) },
        prov,
        ctx,
        bsan_shared::AccessKind::Read,
        Size::from_bytes(addr),
        Size::from_bytes(access_size),
    )
    .unwrap();
}

/// Records a write access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
extern "C" fn __bsan_write(prov: *const Provenance, addr: usize, access_size: u64) {
    // Assuming root tag has been initialized in the tree

    let ctx = unsafe { global_ctx() };

    let alloc_info_ptr = unsafe { bt_validate_prov(prov, ctx).unwrap() };

    let prov = unsafe { &*prov };

    let alloc_info = unsafe { &*alloc_info_ptr };
    let tree_lock = &alloc_info.tree_lock;

    bt_access(
        unsafe { &mut *TREE_PTR.lock_tree(tree_lock) },
        prov,
        ctx,
        bsan_shared::AccessKind::Write,
        Size::from_bytes(addr),
        Size::from_bytes(access_size),
    )
    .unwrap();
}

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
    let alloc_info = unsafe { ctx.allocate_lock_location().as_mut() };

    let info = AllocInfo {
        alloc_id,
        base_addr: FreeListAddrUnion { base_addr: object_addr },
        size: alloc_size,
        align: 0,
        tree_lock: AtomicBool::new(TREE_PTR.0.is_locked()),
    };

    let alloc_info = unsafe { alloc_info.write(info) as *mut AllocInfo };

    unsafe {
        //*(*prov).alloc_info = alloc_info;
        // TODO: Discuss difference between the two
        (*prov).alloc_id = alloc_id;
        (*prov).bor_tag = bor_tag;
        (*prov).alloc_info = alloc_info;
    };
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
extern "C" fn __bsan_dealloc(prov: *mut Provenance) {
    // Assuming root tag has been initialized in the tree
    let ctx = unsafe { global_ctx() };

    let alloc_info_ptr = unsafe { bt_validate_prov(prov, ctx).unwrap() };

    let prov = unsafe { &*prov };

    let alloc_info = unsafe { &mut *(alloc_info_ptr as *mut AllocInfo) };
    let tree_lock = &alloc_info.tree_lock;
    let tree = unsafe { &mut *TREE_PTR.lock_tree(tree_lock) };

    let lock_addr_id = prov.alloc_id.get();
    let metadata_id = alloc_info.alloc_id.get();

    println!("Alloc Info: {:?}", unsafe { &*prov.alloc_info });

    if lock_addr_id != metadata_id {
        // TODO: Implement proper error handling, possibly via thiserror_no_std
        println!("Allocation ID in pointer metadata does not match the one in the lock address.\nLock address ID: {:?}\nPointer metadata ID: {:?}", lock_addr_id, metadata_id);
    }

    // TODO: Handle the result properly
    // and lock the tree
    tree.dealloc(
        prov.bor_tag,
        AllocRange {
            start: Size::from_bytes(unsafe { *(alloc_info.base_addr() as *const usize) }),
            size: Size::from_bytes(alloc_info.size),
        },
        ctx,
        prov.alloc_id,
        Span::new(),
        ctx.allocator(),
    )
    .unwrap();

    // // // TODO: Deallocate the AllocInfo
    // // // Potentially using a port of `AllocMetadata::dealloc`
    // alloc_info.dealloc();
}

/// Marks the borrow tag for `prov` as "exposed," allowing it to be resolved to
/// validate accesses through "wildcard" pointers.
#[unsafe(no_mangle)]
extern "C" fn __bsan_expose_tag(prov: *const Provenance) {}

#[cfg(test)]
mod test {
    use core::alloc::{GlobalAlloc, Layout};
    use core::mem::MaybeUninit;
    use core::ptr::NonNull;

    use bsan_shared::*;

    use super::*;

    fn init_bsan_with_test_hooks() {
        unsafe {
            __bsan_init();
        }
    }

    fn create_metadata() -> Provenance {
        let mut prov = MaybeUninit::<Provenance>::uninit();
        let prov_ptr = (&mut prov) as *mut _;
        unsafe {
            // TODO: Discuss this object address
            __bsan_alloc(prov_ptr, 0xaaaaaaa8 as *const c_void, 10);
            prov.assume_init()
        }
    }

    #[test]
    fn bsan_alloc_increasing_alloc_id() {
        init_bsan_with_test_hooks();
        unsafe {
            // log::debug!("before bsan_alloc");
            let prov1 = create_metadata();
            // log::debug!("directly after bsan_alloc");
            assert_eq!(prov1.alloc_id.get(), 3);
            assert_eq!(AllocId::min().get(), 3);
            let prov2 = create_metadata();
            assert_eq!(prov2.alloc_id.get(), 4);
        }
    }

    // FIXME: Fix these tests
    // #[test]
    // fn bsan_alloc_and_dealloc() {
    //     init_bsan_with_test_hooks();
    //     unsafe {
    //         let mut prov = create_metadata();
    //         println!("Alloc Info before dealloc: {:?}", *prov.alloc_info);
    //         __bsan_dealloc(&mut prov as *mut _);
    //         let alloc_metadata = &*prov.alloc_info;
    //         assert_eq!(alloc_metadata.alloc_id.get(), AllocId::invalid().get());
    //         assert_eq!(alloc_metadata.alloc_id.get(), 0);
    //     }
    // }

    // #[test]
    // fn bsan_dealloc_detect_double_free() {
    //     init_bsan_with_test_hooks();
    //     unsafe {
    //         let mut prov = create_metadata();
    //         let _ = __inner_bsan_dealloc(Span::new(), &mut prov as *mut _);
    //         let result = __inner_bsan_dealloc(Span::new(), &mut prov as *mut _);
    //         assert!(result.is_err());
    //     }
    // }

    // #[test]
    // fn bsan_dealloc_detect_invalid_free() {
    //     init_bsan_with_test_hooks();
    //     unsafe {
    //         let mut prov = create_metadata();
    //         let mut modified_prov = prov;
    //         modified_prov.alloc_id = AllocId::new(99);
    //         let result = __inner_bsan_dealloc(span, &mut modified_prov as *mut _);
    //         assert!(result.is_err());
    //     }
    // }
}

// TODO: Figure out why this is giving an error
// #[cfg(not(test))]
// #[panic_handler]
// fn panic(info: &PanicInfo<'_>) -> ! {
//     loop {}
// }
