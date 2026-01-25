use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use bsan_shared::ProtectorKind;
use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[cfg(not(test))]
use crate::diagnostics::History;
use crate::errors::UBInfo;
use crate::helpers::FxHashMap;
use crate::local::{deinit_local_ctx, init_local_ctx, local_ctx, local_ctx_mut, LocalCtx};
use crate::memory::hooks::{BsanAllocHooks, BsanHooks};
use crate::memory::{Heap, ShadowHeap};
#[cfg(not(test))]
use crate::sanitizer_common_interface::StackTraceDepot;
use crate::*;

#[derive(Default)]
pub struct ProtectedTags(FxHashMap<BorTag, ProtectorKind>);

impl ProtectedTags {
    pub fn get_protector_kind(&self, tag: BorTag) -> Option<ProtectorKind> {
        self.0.get(&tag).copied()
    }

    pub fn is_protected(&self, tag: BorTag) -> bool {
        self.0.contains_key(&tag)
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
    hooks: BsanHooks,
    protected_tags: RwLock<ProtectedTags>,
    shadow_heap: ShadowHeap<Provenance>,
    alloc_metadata_map: Heap<AllocInfo>,
    threads: RwLock<FxHashMap<ThreadId, NonNull<LocalCtx>>>,
    #[cfg(not(test))]
    allocation_stack_depot: Mutex<crate::sanitizer_common_interface::StackTraceDepot>,
}

impl GlobalCtx {
    /// Creates a new instance of `GlobalCtx` using the given `BsanHooks`.
    /// This function will also initialize our shadow heap
    fn new(hooks: BsanHooks) -> Self {
        Self {
            hooks,
            protected_tags: RwLock::new(ProtectedTags::default()),
            alloc_metadata_map: Heap::new(),
            shadow_heap: ShadowHeap::new(&raw const __BSAN_WILDCARD_PROVENANCE),
            threads: RwLock::new(FxHashMap::default()),
            #[cfg(not(test))]
            allocation_stack_depot: Mutex::new(StackTraceDepot::default()),
        }
    }

    pub fn hooks(&self) -> &BsanHooks {
        &self.hooks
    }

    pub(crate) fn create_alloc_info(&self, info: AllocInfo) -> BorsanResult<NonNull<AllocInfo>> {
        let info = self.alloc_metadata_map.alloc(info);
        Ok(info)
    }

    pub(crate) unsafe fn destroy_alloc_info(&self, ptr: NonNull<AllocInfo>) {
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

    #[allow(unused)]
    pub fn local_ctx_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut LocalCtx) -> R,
    {
        self.threads.read();
        let local_ctx = unsafe { local_ctx_mut() };
        f(local_ctx)
    }

    #[allow(unused)]
    pub fn local_ctx<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&LocalCtx) -> R,
    {
        let local_ctx = unsafe { local_ctx() };
        f(local_ctx)
    }

    pub fn protected_tags<'a>(&'a self) -> ProtectedTagsRef<'a> {
        ProtectedTagsRef(self.protected_tags.read())
    }

    pub fn protected_tags_mut<'a>(&'a self) -> ProtectedTagsRefMut<'a> {
        ProtectedTagsRefMut(self.protected_tags.write())
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

    #[cfg(not(test))]
    pub fn store_stacktrace_for_allocation(&self, alloc_id: AllocId, span_data: Span) {
        match self.allocation_stack_depot.lock().capture_stack(alloc_id, None, span_data) {
            Ok(()) => {}
            Err(e) => {
                self.handle_error(e);
            }
        }
    }

    #[inline(never)] // never inline to have specific break point for debugging with GDB
    #[allow(clippy::collapsible_if)]
    pub fn handle_error(&self, ub_info: UBInfo) -> ! {
        crate::eprintln!("An error occurred: {ub_info:?}");

        #[cfg(not(test))]
        {
            if let Some(alloc_id) = ub_info.get_alloc_id()
                && let Ok(stack_id) = self.allocation_stack_depot.lock().print_trace(&alloc_id)
            {
                crate::eprintln!("{:?} previously allocated here:", alloc_id);
                sanitizer_common_interface::print_stack_trace(Some(stack_id));
            }

            match ub_info {
                errors::UBInfo::AliasingViolation(tree_error) => {
                    let print_traces = |history: &History| {
                        history.created_at().0.print_stack_trace();
                        history.events_iter().for_each(|event| {
                            event.span.print_stack_trace();
                        });
                    };

                    print_traces(&tree_error.accessed_info.history);
                    print_traces(&tree_error.conflicting_info.history);
                }
                errors::UBInfo::AccessOutOfBounds(prov, _, _) => {
                    if let Some(alloc_info) = unsafe { prov.alloc_info.as_ref() } {
                        if let Some((span, _)) = alloc_info.created_at() {
                            span.print_stack_trace();
                        }
                        if let Some((span, _)) = alloc_info.conflict_at() {
                            span.print_stack_trace();
                        }
                    }
                }
                _ => (),
            }
        }

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
