use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::errors::{ErrorFormatContext, UBInfo};
use crate::helpers::FxHashMap;
use crate::memory::Heap;
use crate::sanitizer_common::Span;
use crate::tree_borrows::data_structures::{AccessType, RangeObjectMap};
use crate::tree_borrows::{AllocStateImpl, ProtectorKind};
use crate::*;

pub static DISABLE_NODE_DEBUG_INFO: AtomicBool = AtomicBool::new(false);

/// Only prune borrow trees with more than this many nodes; this initial value is only
/// the pre-init default and is replaced by the flag's default (64) in `bsan_flags.inc`.
pub static TREE_GC_MIN_NODES: AtomicUsize = AtomicUsize::new(0);

/// Upper bound on how many children can be resulted from compaction of a single node.
/// The pre-init default and is replaced by the flag's default (16) in `bsan_flags.inc`.
pub static MAX_COMPACTED_CHILDREN: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Thread-local slot for a boxed `(UBInfo, Span)` set by `handle_error` and
/// consumed by `__bsan_format_pending_ub` once the C++ side has captured the
/// stack and located the first user-code frame.
#[thread_local]
static PENDING_ERROR: UnsafeCell<*mut (UBInfo, Span)> = UnsafeCell::new(core::ptr::null_mut());

unsafe extern "C" {
    fn __bsan_abort() -> !;
    fn __bsan_disable_node_debug_info() -> bool;
    fn __bsan_tree_gc_min_nodes() -> usize;
    fn __bsan_max_compacted_children() -> usize;
}

/// Called from the `HANDLE_ERROR` C++ macro after the stack trace has been
/// captured and the first user-code frame PC has been located.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __bsan_format_pending_ub(user_frame_pc: usize) {
    let ptr = unsafe { *PENDING_ERROR.get() };
    if ptr.is_null() {
        return;
    }
    unsafe { *PENDING_ERROR.get() = core::ptr::null_mut() };
    let (ub_info, original_pc) = unsafe { *alloc::boxed::Box::from_raw(ptr) };
    let (primary, origin) = crate::sanitizer_common::SanitizerCommon::resolve_error_location(
        user_frame_pc,
        original_pc,
    );
    let mut ctx = ErrorFormatContext::default();
    crate::eprint!("error: {}", ctx.display_ub(ub_info, primary, origin));
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

pub struct ExposedProvenanceRef<'a>(RwLockReadGuard<'a, RangeObjectMap<AllocInfoPtr>>);

impl<'a> Deref for ExposedProvenanceRef<'a> {
    type Target = RangeObjectMap<AllocInfoPtr>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct ExposedProvenanceRefMut<'a>(RwLockWriteGuard<'a, RangeObjectMap<AllocInfoPtr>>);

impl<'a> Deref for ExposedProvenanceRefMut<'a> {
    type Target = RangeObjectMap<AllocInfoPtr>;

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
    alloc_metadata_map: Heap<AllocInfo>,
    snapshots: RwLock<FxHashMap<AllocId, AllocStateImpl>>,
    exposed_provenance: RwLock<RangeObjectMap<AllocInfoPtr>>,
}

impl GlobalCtx {
    fn new() -> Self {
        Self {
            protected_tags: RwLock::new(ProtectedTags::default()),
            alloc_metadata_map: Heap::new(),
            snapshots: RwLock::new(FxHashMap::default()),
            exposed_provenance: RwLock::new(RangeObjectMap::new()),
        }
    }

    pub(crate) fn create_alloc_info(&self, info: AllocInfo) -> NonNull<AllocInfo> {
        self.alloc_metadata_map.alloc(info)
    }

    pub(crate) unsafe fn destroy_alloc_info(&self, ptr: NonNull<AllocInfo>) {
        unsafe { self.alloc_metadata_map.dealloc(ptr) }
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

    pub fn get_exposed_provenance(&self, range: AllocRange) -> Option<AllocInfoPtr> {
        // A zero-sized lookup (e.g. a deallocation, where the size of the access
        // is determined by the allocation) still needs to resolve the allocation
        // containing its start address, so we widen it to a single byte.
        let size = core::cmp::max(range.size, Size::from_bytes(1));
        let range = AllocRange { start: range.start, size };
        let exposed = self.exposed_provenance.read();
        match exposed.access_type(range) {
            AccessType::PerfectlyOverlapping(ix) => Some(exposed[ix]),
            AccessType::Empty(_) => None,
            AccessType::ImperfectlyOverlapping(range) => {
                (range.len() == 1).then(|| exposed[range.start])
            }
        }
    }

    pub fn remove_exposed_provenance(&self, range: AllocRange, strict: bool) {
        self.removing_exposed_provenance(range, strict, || {});
    }
    /// Removes a provenance value that has been exposed for the given range.
    /// If `strict`, then exposed provenance will only be removed if is matches
    /// Otherwise, all exposed provenance values will be removed within the given
    /// range. Calls the provided closure while the lock is held, which is useful
    /// for ensuring that certain events happen "atomically" along with clearing
    /// exposed provenance from the given range.
    pub fn removing_exposed_provenance<T, F>(&self, range: AllocRange, strict: bool, f: F) -> T
    where
        F: Fn() -> T,
    {
        // Zero-sized allocations are never inserted into the mapping.
        if range.size == Size::ZERO {
            return f();
        }

        let read = self.exposed_provenance.upgradeable_read();
        // Most programs never expose any provenance, so we check with a read
        // lock first to keep deallocation cheap in the common case.
        if matches!(read.access_type(range), AccessType::Empty(_)) {
            return f();
        }

        let mut write = read.upgrade();
        match write.access_type(range) {
            AccessType::PerfectlyOverlapping(pos) => {
                write.remove_from_pos(pos);
            }
            AccessType::ImperfectlyOverlapping(range) if !strict => {
                write.remove_pos_range(range);
            }
            AccessType::Empty(_) | AccessType::ImperfectlyOverlapping(_) => {}
        }

        let res = f();
        drop(write);
        res
    }

    pub fn handle_error(&self, ub_info: UBInfo, pc: Span) {
        unsafe {
            let old_ptr = *PENDING_ERROR.get();
            if !old_ptr.is_null() {
                drop(alloc::boxed::Box::from_raw(old_ptr));
            }
            let ptr = alloc::boxed::Box::into_raw(alloc::boxed::Box::new((ub_info, pc)));
            *PENDING_ERROR.get() = ptr;
            crate::sanitizer_common::__bsan_had_error = 1;
        }
    }

    pub fn take_snapshot(&self, alloc_id: AllocId, tree: AllocStateImpl) {
        self.snapshots.write().insert(alloc_id, tree);
    }

    pub fn with_snapshot<F>(&self, alloc_id: AllocId, f: F)
    where
        F: FnOnce(&AllocStateImpl),
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
        fn __bsan_crt_malloc(size: usize) -> *mut core::ffi::c_void;
        fn __bsan_crt_free(ptr: *mut core::ffi::c_void);
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
                __bsan_crt_malloc(layout.size()).cast::<u8>()
            }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
            #[cfg(test)]
            unsafe {
                libc::free(ptr.cast::<c_void>());
            }
            #[cfg(not(test))]
            unsafe {
                __bsan_crt_free(ptr.cast::<c_void>());
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
        TREE_GC_MIN_NODES.store(__bsan_tree_gc_min_nodes(), Ordering::Relaxed);
        MAX_COMPACTED_CHILDREN.store(__bsan_max_compacted_children(), Ordering::Relaxed);
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
