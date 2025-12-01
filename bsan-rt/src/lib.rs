#![cfg_attr(not(test), no_std)]
#![feature(thread_local)]
#![feature(allocator_api)]
#![feature(sync_unsafe_cell)]
#![feature(yeet_expr)]
#[macro_use]
extern crate alloc;
use core::ffi::c_void;
use core::fmt::Debug;
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr::NonNull;
use core::sync::atomic::AtomicUsize;
use core::{fmt, ptr, slice};

use bsan_shared::{AccessKind, RetagInfo, Size};
use libc_print::std_name::*;
use spin::Mutex;

mod global;
pub use global::*;

mod local;
pub use local::*;

pub mod borrow_tracker;
use borrow_tracker::*;

mod diagnostics;

mod span;
use span::Span;

mod memory;

mod errors;

use crate::borrow_tracker::tree::Tree;
use crate::errors::BorsanResult;
use crate::memory::hooks;
use crate::span::FramePointer;

macro_rules! println {
    ($($arg:tt)*) => {
        libc_print::std_name::println!($($arg)*)
    };
}

pub(crate) use println;

macro_rules! handle_err {
    ($err:expr, $gtx:expr) => {{
        #[cfg(test)]
        {
            panic!("Error in test mode: {:?}", $err);
        }
        #[cfg(not(test))]
        {
            $gtx.handle_error($err);
        }
    }};
}

/// A struct for summarizing debug information about memory operations
#[cfg(feature = "debug")]
struct DebugSummary {
    op: &'static str,
    ptr: usize,
    alloc_id: AllocId,
    bor_tag: BorTag,
    info: AllocInfoSummary,
}

#[cfg(feature = "debug")]
impl fmt::Display for DebugSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.info {
            AllocInfoSummary::WildCard => write!(
                f,
                "[{}] 0x{:x} @({:?}, {:?}) -> (wildcard)",
                self.op, self.ptr, self.alloc_id, self.bor_tag
            ),
            AllocInfoSummary::Null => write!(
                f,
                "[{}] 0x{:x} @({:?}, {:?}) -> (null)",
                self.op, self.ptr, self.alloc_id, self.bor_tag
            ),
            AllocInfoSummary::Valid { alloc_id, base_addr, size } => write!(
                f,
                "[{}] 0x{:x} @({:?}, {:?}) -> ({:?}, {:?}, {:?})",
                self.op, self.ptr, self.alloc_id, self.bor_tag, alloc_id, base_addr, size
            ),
        }
    }
}

#[cfg(feature = "debug")]
macro_rules! debug_bsan {
    ($op:literal, $ptr:ident, $alloc_id:ident, $bor_tag:ident, $alloc_info:expr) => {{
        #[allow(unused_unsafe)]
        let info = match $alloc_id.0 {
            0 => AllocInfoSummary::WildCard,
            1 => AllocInfoSummary::Null,
            _ => unsafe { &*$alloc_info }.summarize(),
        };
        let summary = DebugSummary {
            op: $op,
            ptr: $ptr.addr(),
            alloc_id: $alloc_id,
            bor_tag: $bor_tag,
            info,
        };
        println!("{}", summary);
    }};
}

/// No-op macro when debug feature is disabled
#[cfg(not(feature = "debug"))]
macro_rules! debug_bsan {
    ($op:literal, $ptr:ident, $alloc_id:ident, $bor_tag:ident, $info:expr) => {{}};
}
#[unsafe(no_mangle)]
pub static __BSAN_ALLOC_ID_CTR: AtomicUsize = AtomicUsize::new(3);

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
    /// Represents any valid allocation
    pub const fn wildcard() -> Self {
        AllocId(0)
    }

    /// An invalid allocation
    pub const fn invalid() -> Self {
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

#[unsafe(no_mangle)]
pub static __BSAN_BOR_TAG_CTR: AtomicUsize = AtomicUsize::new(0);

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
        let global = unsafe { global_ctx() };
        let protector = match global.get_protector_kind(*self) {
            Some(kind) => &format!("{:?}", kind),
            None => "unprotected",
        };
        write!(f, "<{}>({})", self.0, protector)
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

unsafe impl Sync for Provenance {}
unsafe impl Send for Provenance {}

impl Default for Provenance {
    fn default() -> Self {
        Provenance::wildcard()
    }
}

impl Provenance {
    /// The default provenance value, which is assigned to dangling or invalid
    /// pointers.
    const fn null() -> Self {
        Provenance {
            alloc_id: AllocId::invalid(),
            bor_tag: BorTag::new(1),
            alloc_info: core::ptr::null_mut(),
        }
    }

    /// Pointers cast from integers receive a "wildcard" provenance value,
    /// which permits any access.
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
#[derive(Copy, Clone)]
pub union FreeListAddrUnion {
    free_list_next: Option<NonNull<AllocInfo>>,
    // Must be a raw pointer for union field access safety
    base_addr: *mut c_void,
}

impl fmt::Debug for FreeListAddrUnion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe { write!(f, "{:?}", self.base_addr) }
    }
}

impl Default for FreeListAddrUnion {
    fn default() -> Self {
        Self { base_addr: core::ptr::null_mut() }
    }
}

#[derive(Debug)]
struct ProvenanceVecView {
    len: usize,
    curr: usize,
    id_buffer: *mut AllocId,
    tag_buffer: *mut BorTag,
    info_buffer: *mut *mut AllocInfo,
}

impl ProvenanceVecView {
    fn new(
        len: usize,
        id_buffer: *mut AllocId,
        tag_buffer: *mut BorTag,
        info_buffer: *mut *mut AllocInfo,
    ) -> Self {
        Self { len, curr: 0, id_buffer, tag_buffer, info_buffer }
    }
}

impl Extend<Provenance> for ProvenanceVecView {
    fn extend<T: IntoIterator<Item = Provenance>>(&mut self, iter: T) {
        for elem in iter {
            if self.curr < self.len {
                let Provenance { alloc_id, bor_tag, alloc_info } = elem;
                unsafe {
                    *self.id_buffer.add(self.curr) = alloc_id;
                    *self.tag_buffer.add(self.curr) = bor_tag;
                    *self.info_buffer.add(self.curr) = alloc_info;
                    self.curr += 1;
                }
            }
        }
    }
}

impl Iterator for ProvenanceVecView {
    type Item = Provenance;

    fn next(&mut self) -> Option<Self::Item> {
        if self.curr == self.len {
            None
        } else {
            unsafe {
                let alloc_id = *self.id_buffer.add(self.curr);
                let bor_tag = *self.tag_buffer.add(self.curr);
                let alloc_info = *self.info_buffer.add(self.curr);
                self.curr += 1;
                Some(Provenance { alloc_id, bor_tag, alloc_info })
            }
        }
    }
}

#[unsafe(no_mangle)]
static __BSAN_WILDCARD_PROVENANCE: Provenance = Provenance::wildcard();

#[unsafe(no_mangle)]
static __BSAN_NULL_PROVENANCE: Provenance = Provenance::null();

/// Every allocation is associated with a "lock" object, which is an instance of `AllocInfo`.
/// Provenance is the "key" to this lock. To validate a memory access, we compare the allocation ID
/// of a pointer's provenance with the value stored in its corresponding `AllocInfo` object. If the values
/// do not match, then the access is invalid. If they do match, then we proceed to validate the access against
/// the tree for the allocation.
#[derive(Debug)]
#[repr(C)]
pub struct AllocInfo {
    pub alloc_id: AllocId,
    pub base_addr: FreeListAddrUnion,
    pub size: usize,
    pub tree_lock: Mutex<Option<tree::Tree<hooks::BsanAllocHooks>>>,
}

impl AllocInfo {
    fn invalid() -> Self {
        AllocInfo {
            alloc_id: AllocId::invalid(),
            base_addr: FreeListAddrUnion { base_addr: ptr::null_mut() },
            size: 0,
            tree_lock: Mutex::new(None),
        }
    }

    fn new(
        ctx: &GlobalCtx,
        base_addr: *mut c_void,
        size: usize,
        alloc_id: AllocId,
        bor_tag: BorTag,
    ) -> Self {
        Self {
            alloc_id,
            base_addr: FreeListAddrUnion { base_addr },
            size,
            tree_lock: Mutex::new(Some(Tree::new_in(
                bor_tag,
                Size::from_bytes(size),
                Span::new(),
                ctx.allocator(),
            ))),
        }
    }

    #[cfg(feature = "debug")]
    fn summarize(&self) -> AllocInfoSummary {
        AllocInfoSummary::Valid {
            alloc_id: self.alloc_id,
            base_addr: self.base_addr,
            size: self.size,
        }
    }
}

/// A shallow version of `AllocInfo`, for use in debug logging.
#[cfg(feature = "debug")]
#[derive(Debug)]
pub enum AllocInfoSummary {
    /// When Prov is wildcard, AllocInfo is invalid
    WildCard,
    /// When Prov is null, AllocInfo is invalid
    Null,
    /// When Prov is valid, only drop the tree_lock field
    Valid { alloc_id: AllocId, base_addr: FreeListAddrUnion, size: usize },
}

/// Initializes the global state of the runtime library.
/// The safety of this library is entirely dependent on this
/// function having been executed. We assume the global invariant that
/// no other API functions will be called prior to that point.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_internal_init() {
    unsafe {
        init_global_ctx(hooks::DEFAULT_HOOKS);
    }
}

/// Deinitializes the global state of the runtime library.
/// We assume the global invariant that no other API functions
/// will be called after this function has executed.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_internal_deinit() {
    unsafe {
        deinit_global_ctx();
    }
}

/// Creates a new borrow tag for the given provenance object.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_retag(
    object_addr: *mut c_void,
    access_size: usize,
    perm: u64,
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    new_tag: BorTag,
    im_data: *const [usize; 2],
    im_len: usize,
) {
    debug_bsan!("retag", object_addr, alloc_id, bor_tag, alloc_info);
    let global_ctx = unsafe { global_ctx() };
    let prov = Provenance { alloc_id, bor_tag, alloc_info };
    let retag_info = unsafe { RetagInfo::from_raw(access_size, perm, im_data, im_len) };

    BorrowTracker::new(prov, object_addr, Some(access_size))
        .and_then(|opt| {
            opt.map(|bt| bt.retag(global_ctx, retag_info, new_tag, Span::new())).transpose()
        })
        .unwrap_or_else(|err| handle_err!(err, global_ctx));
}

/// Records a read access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_read(
    ptr: *mut c_void,
    access_size: usize,
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
) {
    debug_bsan!("read", ptr, alloc_id, bor_tag, alloc_info);
    let global_ctx = unsafe { global_ctx() };
    let prov = Provenance { alloc_id, bor_tag, alloc_info };

    BorrowTracker::new(prov, ptr, Some(access_size))
        .and_then(|bt| {
            bt.iter().try_for_each(|t| t.access(global_ctx, AccessKind::Read, Span::new()))
        })
        .unwrap_or_else(|err| handle_err!(err, global_ctx));
}

/// Records a write access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_write(
    ptr: *mut c_void,
    access_size: usize,
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
) {
    debug_bsan!("write", ptr, alloc_id, bor_tag, alloc_info);
    let global_ctx = unsafe { global_ctx() };
    let prov = Provenance { alloc_id, bor_tag, alloc_info };
    BorrowTracker::new(prov, ptr, Some(access_size))
        .and_then(|bt| {
            bt.iter().try_for_each(|t| t.access(global_ctx, AccessKind::Write, Span::new()))
        })
        .unwrap_or_else(|err| handle_err!(err, global_ctx));
}

/// Deregisters a heap allocation
#[unsafe(no_mangle)]
extern "C" fn __bsan_dealloc(
    ptr: *mut c_void,
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
    weak: bool,
) {
    debug_bsan!("dealloc", ptr, alloc_id, bor_tag, alloc_info);
    let global_ctx = unsafe { global_ctx() };
    let prov: Provenance = Provenance { alloc_id, bor_tag, alloc_info };

    if weak {
        if alloc_info.is_null() {
            return;
        }

        if alloc_id != unsafe { (*alloc_info).alloc_id } {
            return;
        }
    }
    BorrowTracker::new(prov, ptr, None)
        .and_then(|mut bt| bt.iter_mut().try_for_each(|t| t.dealloc(global_ctx, Span::new())))
        .unwrap_or_else(|err| handle_err!(err, global_ctx));

    if !weak && let Some(alloc_info) = NonNull::new(alloc_info) {
        unsafe { global_ctx.destroy_alloc_info(alloc_info) };
    }
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_remove_protected_tags(data: *mut BorTag, len: usize) {
    let global_ctx = unsafe { global_ctx() };
    let tags = unsafe { slice::from_raw_parts(data, len) };
    global_ctx.remove_protected_tags(tags);
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_mark_tls() -> FramePointer {
    unsafe { ptr::replace(&raw mut __BSAN_TLS_MARKER, FramePointer::current().prev().prev()) }
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_validate_param_tls(len: usize) {
    let grandparent = FramePointer::current().prev().prev().prev();
    unsafe {
        if grandparent == __BSAN_TLS_MARKER {
            __BSAN_TLS_MARKER = FramePointer::null();
        } else {
            __BSAN_PARAM_TLS[0..len].fill(Provenance::wildcard());
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_validate_retval_tls(len: usize, prev_marker: FramePointer) {
    unsafe {
        if __BSAN_TLS_MARKER != FramePointer::null() {
            __BSAN_RETVAL_TLS[0..len].fill(Provenance::wildcard());
            __BSAN_TLS_MARKER = prev_marker;
        }
    }
}

// Registers a heap allocation of size `size`, storing its provenance in the return pointer.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_alloc(
    base_addr: *mut c_void,
    size: usize,
    alloc_id: AllocId,
    bor_tag: BorTag,
) -> NonNull<AllocInfo> {
    let ctx = unsafe { global_ctx() };
    let alloc_info = ctx
        .create_alloc_info(AllocInfo::new(ctx, base_addr, size, alloc_id, bor_tag))
        .unwrap_or_else(|info| ctx.handle_error(info));
    debug_bsan!("alloc", base_addr, alloc_id, bor_tag, alloc_info.as_ptr());
    alloc_info
}

/// Copies the provenance stored in the range `[src_addr, src_addr + access_size)` within the shadow heap
/// to the address `dst_addr`. This function will silently fail, so it should only be called in conjunction with
/// `bsan_read` and `bsan_write` or as part of an interceptor.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_shadow_copy(src: *mut u8, dst: *mut u8, access_size: usize) {
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();
    heap.memcpy(ctx.hooks(), src.addr(), dst.addr(), access_size)
        .unwrap_or_else(|info| ctx.handle_error(info.into()))
}

/// Clears the provenance stored in the range `[dst_addr, dst_addr + access_size)` within the
/// shadow heap.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_shadow_clear(dst: *mut u8, access_size: usize) {
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();
    heap.clear(ctx.hooks(), dst.addr(), access_size, __BSAN_NULL_PROVENANCE)
        .unwrap_or_else(|info| ctx.handle_error(info.into()))
}

/// Loads the provenance of a given address from shadow memory and stores
/// the result in the return pointer.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_shadow_src(addr: *mut u8) -> *const Provenance {
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();
    heap.get_src(addr.addr())
}

/// Stores the given provenance value into shadow memory at the location for the given address.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_shadow_dest(addr: *mut u8) -> *mut Provenance {
    let ctx = unsafe { global_ctx() };
    bsan_shadow_dest(ctx, addr).unwrap_or_else(|info| ctx.handle_error(info))
}

#[inline]
fn bsan_shadow_dest(ctx: &GlobalCtx, addr: *mut u8) -> BorsanResult<*mut Provenance> {
    let heap = ctx.shadow_heap();
    Ok(heap.get_dest(ctx.hooks(), addr.addr())?)
}

/// Copy provenance values from split arrays into the shadow heap.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_shadow_load_vector(
    src: *mut u8,
    len: usize,
    id_buffer: *mut AllocId,
    tag_buffer: *mut BorTag,
    info_buffer: *mut *mut AllocInfo,
) {
    let ctx = unsafe { global_ctx() };
    let heap = ctx.shadow_heap();

    let prov_vec = ProvenanceVecView::new(len, id_buffer, tag_buffer, info_buffer);
    heap.load_consecutive(src.addr(), len, prov_vec);
}

/// Load provenance values from the shadow heap into split arrays.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_shadow_store_vector(
    dst: *mut u8,
    len: usize,
    id_buffer: *mut AllocId,
    tag_buffer: *mut BorTag,
    info_buffer: *mut *mut AllocInfo,
) {
    let ctx = unsafe { global_ctx() };
    let view = ProvenanceVecView::new(len, id_buffer, tag_buffer, info_buffer);
    ctx.shadow_heap()
        .store_consecutive(ctx.hooks(), dst.addr(), view)
        .unwrap_or_else(|info| ctx.handle_error(info.into()));
}

/// Reserves a stack slot for allocation metadata.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_reserve_stack_slot() -> NonNull<AllocInfo> {
    let ctx = unsafe { global_ctx() };
    ctx.create_alloc_info(AllocInfo::invalid()).unwrap_or_else(|info| ctx.handle_error(info))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_destroy_stack_slot(slot: NonNull<AllocInfo>) {
    let global_ctx = unsafe { global_ctx() };
    unsafe {
        global_ctx.destroy_alloc_info(slot);
    }
}

/// Initializes stack allocation metadata in-place.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_alloc_stack(
    base_addr: *mut c_void,
    size: usize,
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: NonNull<c_void>,
) {
    debug_bsan!(
        "alloc_stack",
        base_addr,
        alloc_id,
        bor_tag,
        alloc_info.as_ptr().cast::<AllocInfo>()
    );
    unsafe {
        alloc_info.cast::<AllocInfo>().write(AllocInfo::new(
            global_ctx(),
            base_addr,
            size,
            alloc_id,
            bor_tag,
        ));
    }
}

/// Marks the borrow tag for `prov` as "exposed," allowing it to be resolved to
/// validate accesses through "wildcard" pointers.
#[allow(unused)]
#[unsafe(no_mangle)]
extern "C" fn __bsan_expose_tag(alloc_id: AllocId, bor_tag: BorTag, alloc_info: *mut AllocInfo) {}

// Code is more readable with explicit return
#[allow(clippy::needless_return)]
#[unsafe(no_mangle)]
extern "C" fn __bsan_debug_assert_null(
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
) {
    let global_ctx = unsafe { global_ctx() };
    let prov = Provenance { alloc_id, bor_tag, alloc_info };
    if prov != Provenance::null() {
        crate::eprintln!("Expected null provenance, got {prov:?}");
        global_ctx.exit(1);
    }
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_debug_assert_wildcard(
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
) {
    let global_ctx = unsafe { global_ctx() };
    let prov = Provenance { alloc_id, bor_tag, alloc_info };
    if prov != Provenance::wildcard() {
        crate::eprintln!("Expected wildcard provenance, got {prov:?}");
        global_ctx.exit(1);
    }
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_debug_assert_valid(
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
) {
    let prov = Provenance { alloc_id, bor_tag, alloc_info };
    assert_ne!(prov, Provenance::null());
    assert_ne!(prov, Provenance::wildcard());
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_debug_assert_invalid(
    alloc_id: AllocId,
    bor_tag: BorTag,
    alloc_info: *mut AllocInfo,
) {
    let global_ctx = unsafe { global_ctx() };
    let prov = Provenance { alloc_id, bor_tag, alloc_info };

    if !(prov == Provenance::null() || prov == Provenance::wildcard()) {
        global_ctx.exit(1);
    }
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_debug_print(alloc_id: AllocId, bor_tag: BorTag, alloc_info: *mut AllocInfo) {
    let prov = Provenance { alloc_id, bor_tag, alloc_info };
    crate::println!("{prov:?}");
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::Ordering;

    use crate::*;

    fn with_init(unit_test: fn()) {
        unsafe { __bsan_internal_init() };
        unit_test();
        unsafe { __bsan_internal_deinit() };
    }

    fn with_heap_object(unit_test: fn(obj: *mut c_void, size: usize)) {
        let obj = unsafe { libc::malloc(64) };
        unit_test(obj, 64);
        unsafe { libc::free(obj) };
    }

    fn create_metadata(base_addr: *mut c_void, size: usize) -> Provenance {
        unsafe {
            let alloc_id = AllocId(__BSAN_ALLOC_ID_CTR.fetch_add(1, Ordering::Relaxed));
            let bor_tag = BorTag(__BSAN_BOR_TAG_CTR.fetch_add(1, Ordering::Relaxed));
            let alloc_info = __bsan_alloc(base_addr, size, alloc_id, bor_tag).as_ptr();
            Provenance { alloc_id, bor_tag, alloc_info }
        }
    }

    fn destroy_metadata(ptr: *mut c_void, prov: Provenance) {
        __bsan_dealloc(ptr, prov.alloc_id, prov.bor_tag, prov.alloc_info, false);
    }

    #[test]
    fn bsan_alloc_increasing_alloc_id() {
        with_init(|| {
            with_heap_object(|obj1, size1| {
                let prov1 = create_metadata(obj1, size1);
                assert_eq!(prov1.alloc_id, AllocId::min());
                with_heap_object(|obj2, size2| {
                    let prov2 = create_metadata(obj2, size2);
                    assert_eq!(prov2.alloc_id, AllocId(AllocId::min().get() + 1));
                    destroy_metadata(obj2, prov2);
                });
                destroy_metadata(obj1, prov1);
            });
        });
    }

    #[test]
    fn bsan_alloc_and_dealloc() {
        with_init(|| {
            with_heap_object(|obj, size| unsafe {
                let prov = create_metadata(obj, size);
                destroy_metadata(obj, prov);
                let alloc_metadata = &*prov.alloc_info;
                assert_eq!(alloc_metadata.alloc_id, AllocId::invalid());
            });
        })
    }

    #[test]
    #[should_panic]
    #[cfg(not(miri))]
    fn bsan_dealloc_detect_double_free() {
        with_init(|| {
            with_heap_object(|obj, size| {
                let prov = create_metadata(obj, size);
                destroy_metadata(obj, prov);
                destroy_metadata(obj, prov);
            })
        });
    }

    #[test]
    #[should_panic]
    #[cfg(not(miri))]
    fn bsan_dealloc_detect_invalid_free() {
        with_init(|| {
            with_heap_object(|obj, size| {
                let prov = create_metadata(obj, size);
                let mut modified_prov = prov;
                modified_prov.alloc_id = AllocId::new(99);
                destroy_metadata(obj, modified_prov);
            });
        })
    }

    #[test]
    fn bsan_read() {
        with_init(|| {
            with_heap_object(|obj: *mut c_void, size: usize| unsafe {
                let prov = create_metadata(obj, size);
                __bsan_read(obj, size, prov.alloc_id, prov.bor_tag, prov.alloc_info);
                destroy_metadata(obj, prov);
            });
        });
    }

    #[test]
    fn bsan_write() {
        with_init(|| {
            with_heap_object(|obj, size| unsafe {
                let prov = create_metadata(obj, size);
                __bsan_write(obj, size, prov.alloc_id, prov.bor_tag, prov.alloc_info);
                destroy_metadata(obj, prov);
            });
        });
    }
}
