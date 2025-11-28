use core::cell::SyncUnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use bsan_shared::ProtectorKind;
use hashbrown::{DefaultHashBuilder, HashMap};

use crate::errors::ErrorInfo;
use crate::memory::hooks::{BsanAllocHooks, BsanHooks};
use crate::memory::{AllocError, Heap, ShadowHeap};
use crate::*;

// Calls into LLVM's sanitizer framework
// Those are disabled during unit tests to avoid linking issues
#[cfg(not(test))]
unsafe extern "C" {
    ///  to print the error report
    fn __bsan_reportError();
}

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
    /// The set of allocation and deallocation functions.
    hooks: BsanHooks,
    protected_tags: Mutex<BHashMap<BorTag, ProtectorKind>>,
    alloc_metadata_map: Heap<AllocInfo>,
    shadow_heap: ShadowHeap<Provenance>,
}

impl GlobalCtx {
    /// Creates a new instance of `GlobalCtx` using the given `BsanHooks`.
    /// This function will also initialize our shadow heap
    fn new(hooks: BsanHooks) -> Result<Self, AllocError> {
        Ok(Self {
            hooks,
            protected_tags: Mutex::new(BHashMap::new_in(hooks.alloc)),
            alloc_metadata_map: Heap::new(&hooks)?,
            shadow_heap: ShadowHeap::new(&hooks, &raw const __BSAN_WILDCARD_PROVENANCE)?,
        })
    }

    pub fn shadow_heap(&self) -> &ShadowHeap<Provenance> {
        &self.shadow_heap
    }

    pub fn hooks(&self) -> &BsanHooks {
        &self.hooks
    }

    pub(crate) fn create_alloc_info(&self, info: AllocInfo) -> BorsanResult<NonNull<AllocInfo>> {
        Ok(self.alloc_metadata_map.alloc(info)?)
    }

    pub(crate) unsafe fn destroy_alloc_info(&self, ptr: NonNull<AllocInfo>) {
        unsafe { self.alloc_metadata_map.dealloc(ptr) };
    }

    pub fn allocator(&self) -> BsanAllocHooks {
        self.hooks.alloc
    }

    pub fn exit(&self, code: i32) -> ! {
        unsafe {
            (self.hooks.exit)(code);
        }
    }

    pub fn add_protected_tag(&self, bor_tag: BorTag, protector_kind: ProtectorKind) {
        let mut tag_map = self.protected_tags.lock();
        tag_map.insert(bor_tag, protector_kind);
    }

    pub fn remove_protected_tags(&self, bor_tags: &[BorTag]) {
        let mut tag_map = self.protected_tags.lock();
        for tag in bor_tags {
            tag_map.remove(tag);
        }
    }

    pub fn get_protector_kind(&self, bor_tag: BorTag) -> Option<ProtectorKind> {
        let tag_map = self.protected_tags.lock();
        tag_map.get(&bor_tag).copied()
    }

    #[inline(never)] // never inline to have specific break point for debugging with GDB
    pub fn handle_error(&self, info: ErrorInfo) -> ! {
        crate::eprintln!("An error occurred: {info:?}\n\n");
        #[cfg(not(test))]
        if let ErrorInfo::UndefinedBehavior(_ub_info) = info {
            crate::eprintln!("BSAN detected undefined behavior. Printing Error Report\n");
            unsafe {
                __bsan_reportError();
            }
        }
        self.exit(1)
    }
}

/// A thin wrapper around `HashMap` that uses `GlobalCtx` as its allocator
#[derive(Debug, Clone)]
pub struct BHashMap<K, V>(HashMap<K, V, DefaultHashBuilder, BsanAllocHooks>);

impl<K, V> Deref for BHashMap<K, V> {
    type Target = HashMap<K, V, DefaultHashBuilder, BsanAllocHooks>;
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
    fn new_in(hooks: BsanAllocHooks) -> Self {
        Self(HashMap::with_hasher_in(foldhash::fast::RandomState::default(), hooks))
    }
}

/// We need to declare a global allocator to be able to use `alloc` in a `#[no_std]`
/// crate. Anything other than the `GlobalCtx` object will clash with the interceptors,
/// For now, this allocator will defer to libc malloc and free, but in the future, we can
/// set its endpoints to immediately panic with an error message to help with debugging.
mod global_alloc {
    use core::alloc::{GlobalAlloc, Layout};

    #[derive(Default)]
    struct DummyAllocator;

    unsafe impl GlobalAlloc for DummyAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { libc::malloc(layout.size()).cast::<u8>() }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
            unsafe { libc::free(ptr.cast::<libc::c_void>()) }
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
pub unsafe fn init_global_ctx(hooks: BsanHooks) {
    unsafe {
        (*GLOBAL_CTX.get())
            .write(GlobalCtx::new(hooks).expect("failed to allocate global context"));
    }
}

/// Deinitializes the global context object.
/// # Safety
/// This function must only be called once: when the program is terminating.
/// It is marked as `unsafe`, since all other API functions except for `bsan_init` rely
/// on the assumption that this function has not been called yet.
#[inline]
pub unsafe fn deinit_global_ctx() {
    unsafe { drop(ptr::replace(GLOBAL_CTX.get(), MaybeUninit::uninit()).assume_init()) };
}

/// # Safety
/// The user needs to ensure that the context is initialized, e.g. `bsan_init`
/// has been called and `bsan_deinit` has not yet been called.
#[inline]
pub unsafe fn global_ctx<'a>() -> &'a GlobalCtx {
    let ctx = GLOBAL_CTX.get();
    unsafe { &*ctx.cast::<global::GlobalCtx>() }
}
