use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use bsan_shared::ProtectorKind;
use hashbrown::{DefaultHashBuilder, HashMap};
use rustc_hash::FxBuildHasher;
use spin::MutexGuard;

#[cfg(not(test))]
use crate::diagnostics::History;
use crate::errors::ErrorInfo;
use crate::memory::hooks::{BsanAllocHooks, BsanHooks};
use crate::memory::{AllocError, Heap, ShadowHeap};
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
    protected_tags: Mutex<HashMap<BorTag, ProtectorKind, FxBuildHasher>>,
    shadow_heap: ShadowHeap<Provenance>,
    alloc_metadata_map: Heap<AllocInfo>,
    #[cfg(not(test))]
    allocation_stack_depot: Mutex<crate::sanitizer_common_interface::StackTraceDepot>,
}

impl GlobalCtx {
    /// Creates a new instance of `GlobalCtx` using the given `BsanHooks`.
    /// This function will also initialize our shadow heap
    fn new(hooks: BsanHooks) -> Result<Self, AllocError> {
        Ok(Self {
            hooks,
            protected_tags: Mutex::new(HashMap::with_hasher(FxBuildHasher)),
            alloc_metadata_map: Heap::new(&hooks)?,
            shadow_heap: ShadowHeap::new(&hooks, &raw const __BSAN_WILDCARD_PROVENANCE)?,
            #[cfg(not(test))]
            allocation_stack_depot: Mutex::new(
                crate::sanitizer_common_interface::StackTraceDepot::new_in(hooks.alloc),
            ),
        })
    }

    pub fn hooks(&self) -> &BsanHooks {
        &self.hooks
    }

    pub(crate) fn create_alloc_info(&self, info: AllocInfo) -> BorsanResult<NonNull<AllocInfo>> {
        Ok(self.alloc_metadata_map.alloc(info)?)
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

    pub fn protected_tags(&self) -> MutexGuard<'_, HashMap<BorTag, ProtectorKind, FxBuildHasher>> {
        self.protected_tags.lock()
    }

    pub fn add_protected_tag(&self, bor_tag: BorTag, protector_kind: ProtectorKind) {
        let mut tag_map = self.protected_tags();
        tag_map.insert(bor_tag, protector_kind);
    }

    pub fn get_protector_kind(&self, bor_tag: BorTag) -> Option<ProtectorKind> {
        let tag_map = self.protected_tags();
        tag_map.get(&bor_tag).copied()
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
    pub fn handle_error(&self, info: ErrorInfo) -> ! {
        crate::eprintln!("An error occurred: {info:?}");

        // code below uses sanitizer common interface to print stack traces and detailed error info
        #[cfg(not(test))]
        if let ErrorInfo::UndefinedBehavior(ub_info) = info {
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

                    // #[cfg(feature = "debug")]
                    // crate::eprintln!("[DEBUG] Full TreeError: {:#?}", tree_error);
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

#[cfg(not(test))]
impl<K, V> BHashMap<K, V> {
    pub(crate) fn new_in(hooks: BsanAllocHooks) -> Self {
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
        (*GLOBAL_CTX.0.get())
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
