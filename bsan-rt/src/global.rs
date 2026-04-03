use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use borrow_tracker::ProtectorKind;
use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::errors::{ErrorFormatContext, UBInfo};
use crate::helpers::FxHashMap;
use crate::memory::{Heap, ShadowHeap};
use crate::*;

unsafe extern "C" {
    fn __bsan_abort() -> !;
}

#[derive(Default)]
pub struct ProtectedTags(FxHashMap<BorTag, ProtectorKind>);

impl ProtectedTags {
    pub fn get_protector_kind(&self, tag: BorTag) -> Option<ProtectorKind> {
        self.0.get(&tag).copied()
    }

    pub fn add_protector(&mut self, tag: BorTag, kind: ProtectorKind) {
        self.0.insert(tag, kind);
    }

    pub fn remove_protector(&mut self, tag: BorTag) {
        self.0.remove(&tag);
    }
}

pub struct ProtectedTagsRefMut<'a>(RwLockWriteGuard<'a, ProtectedTags>);

impl<'a> Deref for ProtectedTagsRefMut<'a> {
    type Target = ProtectedTags;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> DerefMut for ProtectedTagsRefMut<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub struct ProtectedTagsRef<'a>(RwLockReadGuard<'a, ProtectedTags>);

impl<'a> Deref for ProtectedTagsRef<'a> {
    type Target = ProtectedTags;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
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
pub struct GlobalCtx {
    protected_tags: RwLock<ProtectedTags>,
    shadow_heap: ShadowHeap<Provenance>,
    alloc_metadata_map: Heap<AllocInfo>,
    snapshots: RwLock<FxHashMap<AllocId, Tree>>,
}

impl GlobalCtx {
    fn new() -> Self {
        Self {
            protected_tags: RwLock::new(ProtectedTags::default()),
            alloc_metadata_map: Heap::new(),
            shadow_heap: ShadowHeap::new(&raw const __BSAN_WILDCARD_PROVENANCE),
            snapshots: RwLock::new(FxHashMap::default()),
        }
    }

    pub(crate) fn create_alloc_info(&self, info: AllocInfo) -> NonNull<AllocInfo> {
        self.alloc_metadata_map.alloc(info)
    }

    pub(crate) unsafe fn destroy_alloc_info(&self, ptr: NonNull<AllocInfo>) {
        unsafe { self.alloc_metadata_map.dealloc(ptr) }
    }

    pub fn shadow_heap(&self) -> &ShadowHeap<Provenance> {
        &self.shadow_heap
    }

    pub fn protected_tags<'a>(&'a self) -> ProtectedTagsRef<'a> {
        ProtectedTagsRef(self.protected_tags.read())
    }

    pub fn protected_tags_mut<'a>(&'a self) -> ProtectedTagsRefMut<'a> {
        ProtectedTagsRefMut(self.protected_tags.write())
    }

    pub fn handle_error(&self, ub_info: UBInfo, pc: Span) {
        let mut ctx = ErrorFormatContext::default();
        crate::eprint!("error: {}", ctx.display_ub(ub_info, pc));
        unsafe {
            __BSAN_HAD_ERROR = 1;
        }
    }

    pub fn take_snapshot(&self, alloc_id: AllocId, tree: Tree) {
        self.snapshots.write().insert(alloc_id, tree);
    }

    pub fn with_snapshot<F>(&self, alloc_id: AllocId, f: F)
    where
        F: FnOnce(&Tree),
    {
        self.snapshots.read().get(&alloc_id).map(f);
    }
}

/// We need to declare a global allocator to be able to use `alloc` in a `#[no_std]`
/// crate. Anything other than the `GlobalCtx` object will clash with the interceptors,
/// For now, this allocator will defer to libc malloc and free, but in the future, we can
/// set its endpoints to immediately panic with an error message to help with debugging.
mod global_alloc {
    use core::ffi::c_void;

    #[cfg(not(test))]
    unsafe extern "C" {
        fn __crt_malloc(size: usize) -> *mut core::ffi::c_void;
        fn __crt_free(ptr: *mut core::ffi::c_void);
    }

    use core::alloc::{GlobalAlloc, Layout};

    #[derive(Default)]
    struct Alloc;

    unsafe impl GlobalAlloc for Alloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            #[cfg(test)]
            unsafe {
                libc::malloc(layout.size()).cast::<u8>()
            }
            #[cfg(not(test))]
            unsafe {
                __crt_malloc(layout.size()).cast::<u8>()
            }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
            #[cfg(test)]
            unsafe {
                libc::free(ptr.cast::<c_void>());
            }
            #[cfg(not(test))]
            unsafe {
                __crt_free(ptr.cast::<c_void>());
            }
        }
    }

    #[global_allocator]
    static GLOBAL_ALLOCATOR: Alloc = Alloc;
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
pub unsafe fn init_global_ctx() {
    unsafe {
        (*GLOBAL_CTX.0.get()).write(GlobalCtx::new());
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
