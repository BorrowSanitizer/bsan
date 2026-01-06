use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::NonNull;

use bsan_shared::ProtectorKind;
use hashbrown::{HashMap, HashSet};
use rustc_hash::FxBuildHasher;
use spin::{MutexGuard, RwLock};

use crate::errors::ErrorInfo;
use crate::local::{deinit_local_ctx, init_local_ctx, local_ctx, local_ctx_mut, LocalCtx};
use crate::memory::hooks::{BsanAllocHooks, BsanHooks};
use crate::memory::{Heap, ShadowHeap};
use crate::*;

pub trait VisitProvenance {
    fn visit_provenance(&self, tags: &mut HashSet<BorTag>);
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
    hooks: BsanHooks,
    protected_tags: Mutex<HashMap<BorTag, ProtectorKind, FxBuildHasher>>,
    shadow_heap: ShadowHeap<Provenance>,
    allocations: Mutex<HashSet<NonNull<AllocInfo>>>,
    alloc_metadata_map: Heap<AllocInfo>,
    threads: RwLock<HashMap<ThreadId, NonNull<LocalCtx>, FxBuildHasher>>,
}

impl GlobalCtx {
    /// Creates a new instance of `GlobalCtx` using the given `BsanHooks`.
    /// This function will also initialize our shadow heap
    fn new(hooks: BsanHooks) -> Self {
        Self {
            hooks,
            protected_tags: Mutex::new(HashMap::with_hasher(FxBuildHasher)),
            alloc_metadata_map: Heap::new(),
            shadow_heap: ShadowHeap::new(&raw const __BSAN_WILDCARD_PROVENANCE),
            threads: RwLock::new(HashMap::with_hasher(FxBuildHasher)),
            allocations: Mutex::new(HashSet::new()),
        }
    }

    pub fn hooks(&self) -> &BsanHooks {
        &self.hooks
    }

    pub(crate) fn create_alloc_info(&self, info: AllocInfo) -> BorsanResult<NonNull<AllocInfo>> {
        let info = self.alloc_metadata_map.alloc(info);
        self.allocations.lock().insert(info);
        Ok(info)
    }

    pub(crate) unsafe fn destroy_alloc_info(&self, ptr: NonNull<AllocInfo>) {
        self.allocations.lock().remove(&ptr);
        unsafe { self.alloc_metadata_map.dealloc(ptr) }
    }

    pub fn shadow_heap(&self) -> &ShadowHeap<Provenance> {
        &self.shadow_heap
    }

    pub fn allocator(&self) -> BsanAllocHooks {
        self.hooks.alloc
    }

    pub fn exit(&self, code: i32) -> ! {
        unsafe {
            (self.hooks.exit)(code);
        }
    }

    pub fn protected_tags(&self) -> MutexGuard<'_, HashMap<BorTag, ProtectorKind, FxBuildHasher>> {
        self.protected_tags.lock()
    }

    pub fn run_gc(&self) {
        /*
        let threads = self.threads.write();
        let mut tags = HashSet::new();
        for local_ctx in threads.values() {
            unsafe {
                (*local_ctx.as_ptr()).visit_tags(&mut tags);
            }
        }
        self.shadow_heap().visit_tags(&mut tags);

        for alloc in self.allocations.lock().iter() {
            unsafe {
                let tree_lock = &raw mut (*alloc.as_ptr()).tree_lock;
                let tree = (*tree_lock).get_mut();
                if let Some(tree) = tree {
                    tree.remove_unreachable_tags(&tags, self.allocator());
                }
            }
        }*/
    }

    pub fn local_ctx_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut LocalCtx) -> R,
    {
        self.threads.read();
        let local_ctx = unsafe { local_ctx_mut() };
        f(local_ctx)
    }

    pub fn local_ctx<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&LocalCtx) -> R,
    {
        self.threads.read();
        let local_ctx = unsafe { local_ctx() };
        f(local_ctx)
    }

    pub fn add_protected_tag(&self, bor_tag: BorTag, protector_kind: ProtectorKind) {
        let mut tag_map = self.protected_tags();
        tag_map.insert(bor_tag, protector_kind);
    }

    pub fn get_protector_kind(&self, bor_tag: BorTag) -> Option<ProtectorKind> {
        let tag_map = self.protected_tags();
        tag_map.get(&bor_tag).copied()
    }

    pub fn init_local_ctx(&self) -> BorsanResult<()> {
        let tid = ThreadId::default();
        unsafe { __BSAN_THREAD_ID = tid };
        let local_ctx = unsafe { init_local_ctx(tid.is_main()) };
        self.threads.write().insert(tid, local_ctx);
        Ok(())
    }

    /// # Safety
    /// This function must only be called once.
    pub unsafe fn deinit_local_ctx(&self) {
        unsafe {
            let tid = __BSAN_THREAD_ID;
            self.threads.write().remove(&tid);
            deinit_local_ctx();
        }
    }

    pub fn handle_error(&self, info: ErrorInfo) -> ! {
        crate::eprintln!("{:?}", backtrace::Backtrace::new());
        crate::eprintln!("An error occurred: {info:?}\n\n");
        self.exit(1)
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

struct GlobalCtxWrapper(UnsafeCell<MaybeUninit<GlobalCtx>>);

unsafe impl Send for GlobalCtxWrapper {}
unsafe impl Sync for GlobalCtxWrapper {}

static GLOBAL_CTX: GlobalCtxWrapper = GlobalCtxWrapper(UnsafeCell::new(MaybeUninit::uninit()));

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
        (*GLOBAL_CTX.0.get()).write(GlobalCtx::new(hooks));
    }
}

/// Deinitializes the global context object.
/// # Safety
/// This function must only be called once: when the program is terminating.
/// It is marked as `unsafe`, since all other API functions except for `bsan_init` rely
/// on the assumption that this function has not been called yet.
#[inline]
pub unsafe fn deinit_global_ctx() {
    unsafe { drop(ptr::replace(GLOBAL_CTX.0.get(), MaybeUninit::uninit()).assume_init()) };
}

/// # Safety
/// The user needs to ensure that the context is initialized, e.g. `bsan_init`
/// has been called and `bsan_deinit` has not yet been called.
#[inline]
pub unsafe fn global_ctx<'a>() -> &'a GlobalCtx {
    let ctx = GLOBAL_CTX.0.get();
    unsafe { &*ctx.cast::<global::GlobalCtx>() }
}
