use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard, mutex::SpinMutex};

use crate::errors::{ErrorFormatContext, UBInfo};
use crate::helpers::FxHashMap;
use crate::local::LocalCtx;
use crate::memory::ShadowHeap;
#[cfg(feature = "alloc-bsan-metadata")]
use crate::memory::Heap;
use crate::tree_borrows::data_structures::RangeObjectMap;
use crate::tree_borrows::{LazyTree, ProtectorKind};
use crate::*;

pub static DISABLE_NODE_DEBUG_INFO: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    fn __bsan_abort() -> !;
    fn __bsan_disable_node_debug_info() -> bool;
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

pub struct ExposedProvenanceRef<'a>(RwLockReadGuard<'a, RangeObjectMap<NonNull<AllocInfo>>>);

impl<'a> Deref for ExposedProvenanceRef<'a> {
    type Target = RangeObjectMap<NonNull<AllocInfo>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct ExposedProvenanceRefMut<'a>(RwLockWriteGuard<'a, RangeObjectMap<NonNull<AllocInfo>>>);

impl<'a> Deref for ExposedProvenanceRefMut<'a> {
    type Target = RangeObjectMap<NonNull<AllocInfo>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> DerefMut for ExposedProvenanceRefMut<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
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
    #[cfg(feature = "alloc-bsan-metadata")]
    alloc_metadata_heap: crate::memory::Heap<AllocInfo>,
    #[cfg(not(feature = "alloc-bsan-metadata"))]
    alloc_info_free_list: SpinMutex<Option<NonNull<AllocInfo>>>,
    snapshots: RwLock<FxHashMap<AllocId, LazyTree>>,
    threads: RwLock<FxHashMap<ThreadId, NonNull<LocalCtx>>>,
    exposed_provenance: RwLock<RangeObjectMap<NonNull<AllocInfo>>>,
}

impl GlobalCtx {
    fn new() -> Self {
        Self {
            protected_tags: RwLock::new(ProtectedTags::default()),
            #[cfg(feature = "alloc-bsan-metadata")]
            alloc_metadata_heap: crate::memory::Heap::new(),
            #[cfg(not(feature = "alloc-bsan-metadata"))]
            alloc_info_free_list: SpinMutex::new(None),
            shadow_heap: ShadowHeap::new(),
            snapshots: RwLock::new(FxHashMap::default()),
            threads: RwLock::new(FxHashMap::default()),
            exposed_provenance: RwLock::new(RangeObjectMap::new()),
        }
    }

    pub(crate) fn create_alloc_info(&self, info: AllocInfo) -> NonNull<AllocInfo> {
        #[cfg(feature = "alloc-bsan-metadata")]
        let ptr = self.alloc_metadata_heap.alloc(info);

        #[cfg(not(feature = "alloc-bsan-metadata"))]
        let ptr = {
            // Try the free list first to recycle previously freed AllocInfo slots.
            // This avoids allocating new memory and ensures that freed slots
            // (whose addresses may still be referenced by the shadow heap)
            // are never returned to the OS.
            if let Some(mut free_list) = self.alloc_info_free_list.try_lock()
                && let Some(head) = *free_list
            {
                let next = unsafe { (*head.as_ptr()).base_addr.free_list_next };
                *free_list = next;
                unsafe { head.as_ptr().write(info) };
                head
            } else {
                // Fallback: allocate from the global allocator
                unsafe {
                    let ptr = alloc::alloc::alloc(core::alloc::Layout::new::<AllocInfo>()).cast::<AllocInfo>();
                    if ptr.is_null() {
                        alloc::alloc::handle_alloc_error(core::alloc::Layout::new::<AllocInfo>());
                    }
                    ptr.write(info);
                    NonNull::new_unchecked(ptr)
                }
            }
        };

        ptr
    }

    pub(crate) unsafe fn destroy_alloc_info(&self, ptr: NonNull<AllocInfo>) {
        unsafe {
            let _ = (*ptr.as_ptr()).tree_lock.lock().take();
        }
        #[cfg(feature = "alloc-bsan-metadata")]
        {
            unsafe { self.alloc_metadata_heap.dealloc(ptr) }
        }
        #[cfg(not(feature = "alloc-bsan-metadata"))]
        {
            // Do NOT return the AllocInfo slot itself to the OS.
            // Instead, push it onto the free list for reuse.
            let mut free_list = self.alloc_info_free_list.lock();
            unsafe {
                (*ptr.as_ptr()).base_addr.free_list_next = *free_list;
            }
            *free_list = Some(ptr);
        }
    }

    pub(crate) fn register_thread(&self, thread_id: ThreadId, local_ctx_ptr: NonNull<LocalCtx>) {
        self.threads.write().insert(thread_id, local_ctx_ptr);
    }

    pub(crate) fn deregister_thread(&self, thread: ThreadId) {
        self.threads.write().remove(&thread);
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

    #[allow(unused)]
    pub fn exposed_provenance<'a>(&'a self) -> ExposedProvenanceRef<'a> {
        ExposedProvenanceRef(self.exposed_provenance.read())
    }

    pub fn exposed_provenance_mut<'a>(&'a self) -> ExposedProvenanceRefMut<'a> {
        ExposedProvenanceRefMut(self.exposed_provenance.write())
    }

    pub fn handle_error(&self, ub_info: UBInfo, pc: Span) {
        let mut ctx = ErrorFormatContext::default();
        crate::eprint!("error: {}", ctx.display_ub(ub_info, pc));
        unsafe {
            crate::sanitizer_common::__bsan_had_error = 1;
        }
    }

    pub fn take_snapshot(&self, alloc_id: AllocId, tree: LazyTree) {
        self.snapshots.write().insert(alloc_id, tree);
    }

    pub fn with_snapshot<F>(&self, alloc_id: AllocId, f: F)
    where
        F: FnOnce(&LazyTree),
    {
        self.snapshots.read().get(&alloc_id).map(f);
    }

    pub fn clear_nodes(&self, ptr: *mut core::ffi::c_void) {
        let prov = unsafe { self.shadow_heap.get(ptr.addr()).as_ref() };
        let alloc_info_ptr = prov.alloc_info;
        if alloc_info_ptr.is_null() {
            return;
        }

        let alloc_info_ref = unsafe { &mut *alloc_info_ptr };
        let mut tree_guard = alloc_info_ref.tree_lock.lock();
        if let Some(ref mut lazy_tree) = *tree_guard {
            if let LazyTree::Init(tree) = lazy_tree {
                let mut live_tags: crate::helpers::FxHashSet<BorTag> =
                    tree.tag_mapping.keys().copied().collect();
                live_tags.remove(&prov.bor_tag);

                // Protected tags are always considered live.
                let protected_guard = self.protected_tags.read();
                for &tag in protected_guard.0.keys() {
                    if tag.is_valid() {
                        live_tags.insert(tag);
                    }
                }
                drop(protected_guard);

                tree.remove_unreachable_tags(&live_tags);
            }
        }
    }
}

/// We need to declare a global allocator to be able to use `alloc` in a `#[no_std]`
/// crate. Anything other than the `GlobalCtx` object will clash with the interceptors,
/// For now, this allocator will defer to libc malloc and free, but in the future, we can
/// set its endpoints to immediately panic with an error message to help with debugging.
mod global_alloc {

    #[cfg(all(not(test), feature = "alloc-system"))]
    unsafe extern "C" {
        fn __bsan_crt_malloc(size: usize) -> *mut core::ffi::c_void;
        fn __bsan_crt_free(ptr: *mut core::ffi::c_void);
    }

    use core::alloc::{GlobalAlloc, Layout};

    #[derive(Default)]
    struct Alloc;

    unsafe impl GlobalAlloc for Alloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            #[cfg(feature = "alloc-mimalloc")]
            {
                return unsafe { libmimalloc_sys::mi_malloc_aligned(layout.size(), layout.align()) as *mut u8 };
            }
            #[cfg(feature = "alloc-dlmalloc")]
            {
                return unsafe { <dlmalloc::GlobalDlmalloc as core::alloc::GlobalAlloc>::alloc(&dlmalloc::GlobalDlmalloc, layout) };
            }
            #[cfg(feature = "alloc-system")]
            {
            #[cfg(test)]
            unsafe {
                    return libc::malloc(layout.size()).cast::<u8>();
            }
            #[cfg(not(test))]
            unsafe {
                    return __bsan_crt_malloc(layout.size()).cast::<u8>();
                }
            }
            #[cfg(not(any(feature = "alloc-mimalloc", feature = "alloc-dlmalloc", feature = "alloc-system")))]
            {
                panic!("No allocator backend enabled");
            }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
            #[cfg(feature = "alloc-mimalloc")]
            {
                unsafe { libmimalloc_sys::mi_free(ptr as *mut core::ffi::c_void) }
                return;
            }
            #[cfg(feature = "alloc-dlmalloc")]
            {
                unsafe { <dlmalloc::GlobalDlmalloc as core::alloc::GlobalAlloc>::dealloc(&dlmalloc::GlobalDlmalloc, ptr, _layout) }
                return;
            }
            #[cfg(feature = "alloc-system")]
            {
            #[cfg(test)]
                unsafe { libc::free(ptr as *mut core::ffi::c_void) }
            #[cfg(not(test))]
                unsafe { __bsan_crt_free(ptr as *mut core::ffi::c_void) }
                return;
            }
            #[cfg(not(any(feature = "alloc-mimalloc", feature = "alloc-dlmalloc", feature = "alloc-system")))]
            {
                panic!("No allocator backend enabled");
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
        DISABLE_NODE_DEBUG_INFO.store(__bsan_disable_node_debug_info(), Ordering::Relaxed);
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
