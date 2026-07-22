#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), feature(core_intrinsics))]
#![feature(thread_local)]
#![feature(allocator_api)]
#![feature(never_type)]
#![allow(internal_features)]

#[macro_use]
extern crate alloc;
use core::ffi::c_void;
use core::fmt::Debug;
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::{fmt, ptr, slice};

mod borrow_tracker;
use libc_print::std_name::*;
mod tree_borrows;

mod global;
use global::*;
mod helpers;
mod sanitizer_common;
use borrow_tracker::*;

mod errors;
mod memory;

use crate::helpers::{AllocRange, Size};
use crate::sanitizer_common::Span;
use crate::tree_borrows::perms::AccessKind;
use crate::tree_borrows::tree::Node;

#[thread_local]
#[unsafe(no_mangle)]
pub static mut __BSAN_HAD_ERROR: usize = 0;

/// A struct for summarizing debug information about memory operations
#[cfg(feature = "debug")]
struct DebugSummary {
    op: &'static str,
    ptr: usize,
    bor_tag: BorTag,
    info: NodeSummary,
}

#[cfg(feature = "debug")]
impl fmt::Display for DebugSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.info {
            NodeSummary::Omnivalid => {
                write!(f, "[{}] 0x{:x} @{:?} -> (omnivalid)", self.op, self.ptr, self.bor_tag)
            }
            NodeSummary::Wildcard => {
                write!(f, "[{}] 0x{:x} @{:?} -> (wildcard)", self.op, self.ptr, self.bor_tag)
            }
            NodeSummary::Null => {
                write!(f, "[{}] 0x{:x} @{:?} -> (null)", self.op, self.ptr, self.bor_tag)
            }
            NodeSummary::Valid { alloc_id, base_addr, size } => write!(
                f,
                "[{}] 0x{:x} @{:?} -> ({:?}, {:?}, {:?})",
                self.op, self.ptr, self.bor_tag, alloc_id, base_addr, size
            ),
        }
    }
}

macro_rules! debug_bsan {
    ($op:literal, $p:ident, $prov:expr) => {
        #[cfg(feature = "debug")]
        {
            #[allow(unused_unsafe)]
            let prov: Provenance = $prov;
            let bor_tag = prov.tag();
            let info = if prov.is_omnivalid() {
                NodeSummary::Omnivalid
            } else if prov.is_invalid() {
                NodeSummary::Null
            } else if prov.is_wildcard() {
                NodeSummary::Wildcard
            } else {
                unsafe {
                    let root = RootNode::from_node(NonNull::new_unchecked(prov.node()));
                    root.as_ref().summarize()
                }
            };
            let summary = DebugSummary { op: $op, ptr: 0, bor_tag, info };
            libc_print::std_name::println!("{}", summary);
        }
    };
}

#[unsafe(no_mangle)]
pub static __BSAN_ALLOC_ID_CTR: AtomicUsize = AtomicUsize::new(3);

/// Unique identifier for an allocation
#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct AllocId(usize);

impl AllocId {
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

impl Default for AllocId {
    fn default() -> Self {
        AllocId(__BSAN_ALLOC_ID_CTR.fetch_add(1, Ordering::Relaxed))
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

impl fmt::Display for AllocId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

unsafe extern "C" {
    #[link_name = "__bsan_bor_tag_ctr"]
    unsafe static __BSAN_BOR_TAG_CTR: AtomicUsize;
}

/// Unique identifier for a node within the tree
#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BorTag(usize);

impl BorTag {
    #[inline]
    pub fn is_wildcard(self) -> bool {
        self == Self::wildcard()
    }

    #[inline]
    pub fn is_invalid(self) -> bool {
        self == Self::invalid()
    }

    #[inline]
    pub fn is_omnivalid(self) -> bool {
        self == Self::omnivalid()
    }

    #[inline]
    pub fn is_concrete(&self) -> bool {
        self.0 > Self::wildcard().0
    }

    #[inline]
    pub const fn omnivalid() -> Self {
        BorTag(0)
    }

    #[inline]
    pub const fn invalid() -> Self {
        BorTag(1)
    }

    #[inline]
    pub const fn wildcard() -> Self {
        BorTag(2)
    }

    #[inline]
    pub fn get(&self) -> usize {
        self.0
    }
}

impl Default for BorTag {
    fn default() -> Self {
        BorTag(unsafe { __BSAN_BOR_TAG_CTR.fetch_add(1, Ordering::Relaxed) })
    }
}

impl fmt::Debug for BorTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let global = unsafe { global_ctx() };
        let protector = match global.protected_tags().get_protector_kind(*self) {
            Some(kind) => &format!("{:?}", kind),
            None => "unprotected",
        };
        write!(f, "<{}>({})", self.0, protector)
    }
}

/// One-word provenance: a single [`Node`] pointer.
///
/// Sentinel scheme (do not dereference):
/// - null / address 0 = empty / omnivalid
/// - address 1 = invalid
/// - address 2 = wildcard
///
/// Concrete values are real `Node*` (child or root). Tag lives on [`Node`].
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Provenance(*mut Node);

unsafe impl Sync for Provenance {}
unsafe impl Send for Provenance {}

impl Provenance {
    #[inline]
    pub const fn omnivalid() -> Self {
        Self(ptr::null_mut())
    }

    #[inline]
    #[allow(clippy::manual_dangling_ptr)] // intentional sentinel addr 1, not a dangling tip
    pub const fn invalid() -> Self {
        Self(1 as *mut Node)
    }

    #[inline]
    #[allow(clippy::manual_dangling_ptr)] // intentional sentinel addr 2, not a dangling tip
    pub const fn wildcard() -> Self {
        Self(2 as *mut Node)
    }

    #[inline]
    pub fn from_node(node: *mut Node) -> Self {
        Self(node)
    }

    #[inline]
    pub fn node(self) -> *mut Node {
        self.0
    }

    #[inline]
    pub fn is_omnivalid(self) -> bool {
        self.0.is_null()
    }

    #[inline]
    pub fn is_invalid(self) -> bool {
        self.0 as usize == 1
    }

    #[inline]
    pub fn is_wildcard(self) -> bool {
        self.0 as usize == 2
    }

    /// Concrete heap `Node*` are 8-byte aligned (same as CRT `kMinProvAlignment`).
    /// Unaligned addresses above the sentinel range are not concrete.
    #[inline]
    pub fn is_concrete(self) -> bool {
        let addr = self.0 as usize;
        addr > 2 && addr.is_multiple_of(8)
    }

    /// Tag for this provenance: sentinel tags for 0/1/2, else `node.tag`.
    #[inline]
    pub fn tag(self) -> BorTag {
        if self.is_omnivalid() {
            BorTag::omnivalid()
        } else if self.is_invalid() {
            BorTag::invalid()
        } else if self.is_wildcard() {
            BorTag::wildcard()
        } else if !self.is_concrete() {
            BorTag::omnivalid()
        } else {
            unsafe { (*self.0).tag }
        }
    }
}

/// A shallow version of root-node metadata, for use in debug logging.
#[cfg(feature = "debug")]
#[derive(Debug)]
pub(crate) enum NodeSummary {
    Omnivalid,
    Wildcard,
    Null,
    Valid { alloc_id: AllocId, base_addr: Size, size: Size },
}

/// Initializes the global state of the runtime library.
/// The safety of this library is entirely dependent on this
/// function having been executed. We assume the global invariant that
/// no other API functions will be called prior to that point.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_internal_init() {
    unsafe {
        init_global_ctx();
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

bitflags::bitflags! {
    #[repr(C)]
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
    pub struct RetagFlags: u8 {
        /// If this is a function-entry retag.
        const IS_PROTECTED = 1 << 0;
        /// If this is a mutable reference or a `Box`.
        const IS_MUTABLE = 1 << 1;
        /// If this is a `Box`.
        const IS_BOX = 1 << 2;
        /// If the pointee type is `Freeze`
        const IS_FREEZE = 1 << 3;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RetagInfo<'a> {
    pub size: Size,
    pub flags: RetagFlags,
    pub im_layout: Option<&'a [[Size; 2]]>,
    pub pin_layout: Option<&'a [[Size; 2]]>,
}

/// Creates a new borrow tag for the given provenance object.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_retag_impl(
    ptr: *mut c_void,
    size: Size,
    flags: RetagFlags,
    im_data: Option<NonNull<[Size; 2]>>,
    im_len: usize,
    pin_data: Option<NonNull<[Size; 2]>>,
    pin_len: usize,
    node: *mut Node,
    dest: NonNull<Provenance>,
    pc: Span,
    checked: bool,
) {
    let prov = Provenance::from_node(node);
    debug_bsan!("retag", ptr, prov);
    let ctx = unsafe { global_ctx() };

    // Sentinels and unaligned shadow noise must not go through
    // `for_access_unchecked` (derefs Node*). Omnivalid/invalid: pass through.
    // Unaligned garbage: treat as omnivalid. Wildcard still resolves below.
    if !prov.is_concrete() && !prov.is_wildcard() {
        let out =
            if prov.is_omnivalid() || prov.is_invalid() { prov } else { Provenance::omnivalid() };
        unsafe { dest.write(out) };
        return;
    }

    let opt_slice = |opt_ptr: Option<NonNull<[Size; 2]>>, len| -> Option<_> {
        opt_ptr.map(|ptr| unsafe { slice::from_raw_parts(ptr.as_ptr(), len) })
    };

    let retag_info = RetagInfo {
        size,
        flags,
        im_layout: opt_slice(im_data, im_len),
        pin_layout: opt_slice(pin_data, pin_len),
    };

    let prov = if checked && prov.is_concrete() {
        unsafe {
            BorrowTracker::for_access_unchecked(
                ctx,
                prov,
                Size::from_addr(ptr),
                Some(size),
                |mut bt| bt.retag(ctx, retag_info, pc).map(Some),
            )
        }
    } else {
        BorrowTracker::for_access(ctx, prov, Size::from_addr(ptr), Some(size), |mut bt| {
            bt.retag(ctx, retag_info, pc).map(Some)
        })
    }
    .map(|opt| opt.unwrap_or(prov))
    .unwrap_or_else(|err| {
        ctx.handle_error(err, pc);
        prov
    });

    unsafe { dest.write(prov) };
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_protector_end_impl(node: *mut Node, pc: Span) {
    let ctx = unsafe { global_ctx() };
    let prov = Provenance::from_node(node);
    let bor_tag = prov.tag();
    BorrowTracker::for_alloc_weak(prov, |mut bt| {
        let _ = bt.protector_end(ctx, pc);
    });
    // We need to remove the protector as a separate action from deallocation,
    // because you can deallocate something through a protected tag.
    ctx.protected_tags_mut().remove_protector(bor_tag);
}

/// Records a read access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_read_impl(
    ptr: *mut c_void,
    access_size: Size,
    node: *mut Node,
    pc: Span,
    checked: bool,
) {
    let prov = Provenance::from_node(node);
    debug_bsan!("read", ptr, prov);
    let ctx = unsafe { global_ctx() };
    if checked {
        unsafe {
            BorrowTracker::for_access_unchecked(
                ctx,
                prov,
                Size::from_addr(ptr),
                Some(access_size),
                |mut bt| bt.access(ctx, AccessKind::Read, pc),
            )
        }
    } else {
        BorrowTracker::for_access(ctx, prov, Size::from_addr(ptr), Some(access_size), |mut bt| {
            bt.access(ctx, AccessKind::Read, pc)
        })
    }
    .unwrap_or_else(|err| ctx.handle_error(err, pc));
}

/// Records a write access of size `access_size` at the given address `addr` using the provenance `prov`.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_write_impl(
    ptr: *mut c_void,
    access_size: Size,
    node: *mut Node,
    pc: Span,
    checked: bool,
) {
    let prov = Provenance::from_node(node);
    debug_bsan!("write", ptr, prov);
    let ctx = unsafe { global_ctx() };
    if checked {
        unsafe {
            BorrowTracker::for_access_unchecked(
                ctx,
                prov,
                Size::from_addr(ptr),
                Some(access_size),
                |mut bt| bt.access(ctx, AccessKind::Write, pc),
            )
        }
    } else {
        BorrowTracker::for_access(ctx, prov, Size::from_addr(ptr), Some(access_size), |mut bt| {
            bt.access(ctx, AccessKind::Write, pc)
        })
    }
    .unwrap_or_else(|err| ctx.handle_error(err, pc));
}

// Registers a heap allocation of size `size`, returning a pointer to the inline root node.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_alloc_impl(
    base_addr: *mut c_void,
    size: Size,
    bor_tag: BorTag,
    pc: Span,
) -> NonNull<Node> {
    let ctx = unsafe { global_ctx() };
    let range = AllocRange { start: Size::from_addr(base_addr), size };
    ctx.removing_exposed_provenance(range, false, || {
        #[allow(clippy::let_and_return)]
        let node =
            ctx.create_root_node(RootNode::new(Size::from_addr(base_addr), size, bor_tag, pc));
        debug_bsan!("alloc", base_addr, Provenance::from_node(node.as_ptr()));
        node
    })
}

/// Deregisters a heap allocation
#[unsafe(no_mangle)]
extern "C" fn __bsan_dealloc(ptr: *mut c_void, node: *mut Node, pc: Span, checked: bool) {
    let prov = Provenance::from_node(node);
    debug_bsan!("dealloc", ptr, prov);
    let ctx = unsafe { global_ctx() };

    if checked {
        unsafe {
            BorrowTracker::for_access_unchecked(ctx, prov, Size::from_addr(ptr), None, |bt| {
                bt.dealloc(ctx, pc)
            })
        }
    } else {
        BorrowTracker::for_access(ctx, prov, Size::from_addr(ptr), None, |bt| bt.dealloc(ctx, pc))
    }
    .unwrap_or_else(|err| ctx.handle_error(err, pc));
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_dealloc_stack_impl(node: *mut Node, span: Span) {
    let prov = Provenance::from_node(node);
    debug_bsan!("dealloc", node, prov);
    let ctx = unsafe { global_ctx() };
    BorrowTracker::for_alloc_weak(prov, |bt| {
        let _ = bt.dealloc(ctx, span);
    });
}

/// Increments the reference count on a concrete `Node*`.
///
/// Returns `true` if the count transitioned from zero to one.
/// Atomic on the named node; does not take the allocation mutex.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_rc_inc_impl(node: *mut Node) -> bool {
    let prov = Provenance::from_node(node);
    if !prov.is_concrete() {
        return false;
    }
    unsafe { (*node).refcount.increment() }
}

/// Decrements the reference count on a concrete `Node*`.
///
/// Returns `true` if the count reached zero.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn __bsan_rc_dec_impl(node: *mut Node) -> bool {
    let prov = Provenance::from_node(node);
    if !prov.is_concrete() {
        return false;
    }
    unsafe { (*node).refcount.decrement() }
}

/// Tag of a concrete [`Node`]. Must not be called on provenance sentinels.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_node_tag_impl(node: *mut Node) -> BorTag {
    unsafe { (*node).tag }
}

/// Reserves a stack slot for a [`RootNode`].
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_reserve_stack_slot_impl() -> NonNull<Node> {
    unsafe { global_ctx().create_root_node(RootNode::invalid_stack()) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_destroy_stack_slot_impl(slot: NonNull<Node>) {
    let ctx = unsafe { global_ctx() };
    unsafe {
        let root = RootNode::from_node(slot);
        debug_assert!((*root.as_ptr()).on_stack);
        // Clear borrow state, then return the slot to the free list.
        drop(root.replace(RootNode::invalid_stack()));
        RootNode::wire_state(root);
        ctx.destroy_root_node(slot);
    }
}

/// Initializes stack allocation metadata in-place.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_alloc_stack_impl(
    base_addr: *mut c_void,
    size: Size,
    bor_tag: BorTag,
    node: NonNull<Node>,
    pc: Span,
) {
    debug_bsan!("alloc_stack", base_addr, Provenance::from_node(node.as_ptr()));
    let global_ctx = unsafe { global_ctx() };
    let start = Size::from_addr(base_addr);
    let range = AllocRange { start, size };
    global_ctx.removing_exposed_provenance(range, false, || unsafe {
        let root = RootNode::from_node(node);
        let on_stack = (*root.as_ptr()).on_stack;
        let mut fresh = RootNode::new(start, size, bor_tag, pc);
        fresh.on_stack = on_stack;
        root.write(fresh);
        RootNode::wire_state(root);
    });
}

/// Records that a pointer's provenance has been exposed (e.g. via a
/// pointer-to-integer cast), so that it can later be recovered when an
/// integer is cast back to a pointer with wildcard provenance.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_expose_prov_impl(node: *mut Node) {
    let ctx = unsafe { global_ctx() };
    let prov = Provenance::from_node(node);
    BorrowTracker::for_alloc_weak(prov, |mut bt| {
        let _ = bt.expose_tag(ctx);
    });
}

/// Prunes a series of nodes that are identified by the list of borrow tags.
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_prune(node: NonNull<Node>, bor_tags: *mut BorTag, len: usize) -> bool {
    let dead_tags = unsafe { slice::from_raw_parts_mut(bor_tags, len) };
    NodePtr::from(node).prune_dead_tags(dead_tags)
}


/// Frees a [`RootNode`] recovered from any node in the allocation.
/// Must be unreachable from shadow. Stack roots are ignored (frame owns the slot
/// until [`__bsan_destroy_stack_slot_impl`]).
#[unsafe(no_mangle)]
unsafe extern "C" fn __bsan_eject(node: NonNull<Node>) {
    let ctx = unsafe { global_ctx() };
    unsafe {
        // Unreachable from shadow, so safe until returned to the bump allocator.
        let root = RootNode::from_node(node);
        if (*root.as_ptr()).on_stack {
            return;
        }
        drop(root.replace(RootNode::invalid()));
        // Stale locks must see `BorrowState::None`, not a dangling mutex.
        RootNode::wire_state(root);
        ctx.destroy_root_node(RootNode::node_ptr(root));
    }
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_print(node: *mut Node) {
    let prov = Provenance::from_node(node);
    crate::println!("{prov:?}");
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_print_borrow_state(node: *mut Node) {
    let ctx = unsafe { global_ctx() };
    let prov = Provenance::from_node(node);
    BorrowTracker::for_alloc_weak(prov, |bt| {
        bt.debug_print_tree(ctx, false);
    });
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_tree_size(node: *mut Node) {
    let prov = Provenance::from_node(node);
    BorrowTracker::for_alloc_weak(prov, |bt| {
        crate::println!("Tree size: {}", bt.debug_tree_size());
    });
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_snapshot(node: *mut Node) {
    let ctx = unsafe { global_ctx() };
    let prov = Provenance::from_node(node);
    BorrowTracker::for_alloc_weak(prov, |bt| {
        bt.debug_take_snapshot(ctx);
    });
}

#[unsafe(no_mangle)]
extern "C" fn __bsan_print_diff(node: *mut Node) {
    let ctx = unsafe { global_ctx() };
    let prov = Provenance::from_node(node);
    BorrowTracker::for_alloc_weak(prov, |bt| bt.debug_print_diff(ctx));
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    eprintln!("The BorrowSanitizer runtime panicked! {:?}", info);
    core::intrinsics::abort()
}
