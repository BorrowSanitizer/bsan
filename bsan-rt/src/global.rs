#![feature(allocator_api)]
#![feature(unsafe_cell_access)]
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::cell::{SyncUnsafeCell, UnsafeCell};
use core::ffi::CStr;
use core::fmt::{self, write, Write};
use core::mem::{self, zeroed, MaybeUninit};
use core::num::NonZeroUsize;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use block::*;
use hashbrown::{DefaultHashBuilder, HashMap};
use libc_print::std_name::*;
use rustc_hash::FxBuildHasher;

use crate::hooks::{BsanAllocHooks, BsanHooks};
use crate::shadow::ShadowHeap;
use crate::stack::Stack;
use crate::utils::Sizes;
use crate::*;

/// Every action that requires a heap allocation must be performed through a globally
/// accessible, singleton instance of `GlobalCtx`. Initializing or obtaining
/// a reference to this instance is unsafe, since it requires having been initialized
/// with a valid set of `BsanHooks`, which is provided from across the FFI.
/// Only shared references (&self) can be obtained, since this object will be accessed concurrently.
/// All of its API endpoints are free from undefined behavior, under
/// that these invariants hold. This design pattern requires us to pass the `GlobalCtx` instance
/// around explicitly, but it prevents us from relying on implicit global state and limits the spread
/// of unsafety throughout the library.
#[derive(Debug)]
pub struct GlobalCtx {
    hooks: BsanHooks,
    next_alloc_id: AtomicUsize,
    next_thread_id: AtomicUsize,
    shadow_heap: ShadowHeap<Provenance>,
    pub sizes: Sizes,
}

impl GlobalCtx {
    /// Creates a new instance of `GlobalCtx` using the given `BsanHooks`.
    /// This function will also initialize our shadow heap
    fn new(hooks: BsanHooks) -> Self {
        Self {
            hooks,
            next_alloc_id: AtomicUsize::new(AllocId::min().get()),
            next_thread_id: AtomicUsize::new(0),
            shadow_heap: ShadowHeap::new(&hooks),
            sizes: Sizes::default(),
        }
    }

    pub fn shadow_heap(&self) -> &ShadowHeap<Provenance> {
        &self.shadow_heap
    }

    pub fn hooks(&self) -> &BsanHooks {
        &self.hooks
    }

    fn allocator(&self) -> BsanAllocHooks {
        self.hooks.alloc
    }

    fn exit(&self) -> ! {
        unsafe { (self.hooks.exit)() }
    }

    pub fn new_thread_id(&self) -> ThreadId {
        let id = self.next_thread_id.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        ThreadId::new(id)
    }

    pub fn new_alloc_id(&self) -> AllocId {
        let id = self.next_alloc_id.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        AllocId::new(id)
    }

    pub fn new_stack<T>(&self) -> Stack<T> {
        Stack::new(self)
    }
}

impl Drop for GlobalCtx {
    fn drop(&mut self) {}
}

// Logging for UI testing, which is enabled by the `ui_test` feature.
macro_rules! ui_test {
    ($($arg:tt)*) => {
        #[cfg(feature = "ui_test")]
        crate::println!($($arg)*);
    };
}
pub(crate) use ui_test;

/// A thin wrapper around `Vec` that uses `GlobalCtx` as its allocator
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BVec<T>(Vec<T, BsanAllocHooks>);

impl<T> Deref for BVec<T> {
    type Target = Vec<T, BsanAllocHooks>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for BVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> BVec<T> {
    fn new(ctx: &GlobalCtx) -> Self {
        unsafe { Self(Vec::new_in(ctx.allocator())) }
    }
}

/// We provide this trait implementation so that we can use `BVec` to
/// store the temporary results of formatting a string in the implementation
/// of `GlobalCtx::print`
impl core::fmt::Write for BVec<u8> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.bytes();
        if self.try_reserve_exact(bytes.len()).is_err() {
            Err(core::fmt::Error)
        } else {
            self.extend(bytes);
            Ok(())
        }
    }
}

/// A thin wrapper around `VecDeque` that uses `GlobalCtx` as its allocator
#[derive(Debug, Clone)]
pub struct BVecDeque<T>(VecDeque<T, BsanAllocHooks>);

impl<T> Deref for BVecDeque<T> {
    type Target = VecDeque<T, BsanAllocHooks>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for BVecDeque<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> BVecDeque<T> {
    fn new(ctx: &GlobalCtx) -> Self {
        unsafe { Self(VecDeque::new_in(ctx.allocator())) }
    }
}

/// The seed for the random state of the hash function for `BHashMap`.
/// Equal to the decimal encoding of the ascii for "BSAN".
static BSAN_HASH_SEED: usize = 1112752462;

/// A thin wrapper around `HashMap` that uses `GlobalCtx` as its allocator
#[derive(Debug, Clone)]
pub struct BHashMap<K, V>(HashMap<K, V, FxBuildHasher, BsanAllocHooks>);

impl<K, V> Deref for BHashMap<K, V> {
    type Target = HashMap<K, V, FxBuildHasher, BsanAllocHooks>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<K, V> DerefMut for BHashMap<K, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<K, V> BHashMap<K, V> {
    fn new(ctx: &GlobalCtx) -> Self {
        unsafe { Self(HashMap::with_hasher_in(FxBuildHasher, ctx.allocator())) }
    }
}

/// We need to declare a global allocator to be able to use `alloc` in a `#[no_std]`
/// crate. Anything other than the `GlobalCtx` object will clash with the interceptors,
/// so we provide a placeholder that panics when it is used.
#[cfg(not(test))]
mod global_alloc {
    use core::alloc::{GlobalAlloc, Layout};

    #[derive(Default)]
    struct DummyAllocator;

    unsafe impl GlobalAlloc for DummyAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            panic!()
        }
        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
            panic!()
        }
    }

    #[global_allocator]
    static GLOBAL_ALLOCATOR: DummyAllocator = DummyAllocator;
}

pub static GLOBAL_CTX: SyncUnsafeCell<MaybeUninit<GlobalCtx>> =
    SyncUnsafeCell::new(MaybeUninit::uninit());

/// Initializes the global context object.
///
/// # Safety
///
/// This function must only be called once: when the program is first initialized.
/// It is marked as `unsafe`, because it relies on the set of function pointers in
/// `BsanHooks` to be valid.
#[inline]
pub unsafe fn init_global_ctx<'a>(hooks: BsanHooks) -> &'a GlobalCtx {
    unsafe {
        (*GLOBAL_CTX.get()).write(GlobalCtx::new(hooks));
        global_ctx()
    }
}

/// Deinitializes the global context object.
/// # Safety
/// This function must only be called once: when the program is terminating.
/// It is marked as `unsafe`, since all other API functions except for `bsan_init` rely
/// on the assumption that this function has not been called yet.
#[inline]
pub unsafe fn deinit_global_ctx() {
    let ctx = unsafe { ptr::replace(GLOBAL_CTX.get(), MaybeUninit::uninit()).assume_init() };
}

/// # Safety
/// The user needs to ensure that the context is initialized, e.g. `bsan_init`
/// has been called and `bsan_deinit` has not yet been called.
#[inline]
pub unsafe fn global_ctx<'a>() -> &'a GlobalCtx {
    let ctx = GLOBAL_CTX.get();
    unsafe { &*mem::transmute::<*mut MaybeUninit<GlobalCtx>, *mut GlobalCtx>(ctx) }
}
