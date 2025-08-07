//! Several types of objects are frequently allocated by our runtime. This crate includes implementations of several
//! custom allocators for these objects. A `Stack<T>` is a bump allocator for instances of `T`. It supports
//! pushing and popping frames containing multiple instances. A `Heap<T>` is also a bump allocator without frames.
//! However, unlike a `Stack`, a `Heap` supports deallocating objects at any point. Both allocators rely internally
//! on a linked list of page-sized "blocks" of memory.
pub mod hooks;
use hooks::*;

mod heap;
pub use heap::Heap;
use heap::Heapable;

mod stack;
pub use stack::Stack;
use stack::Stackable;

mod shadow;
use core::ffi::c_void;
use core::mem;
use core::num::NonZero;
use core::ptr::{self, NonNull};

pub use shadow::ShadowHeap;

use crate::{AllocInfo, BorTag};

/// # Safety
/// Values of type `AllocInfo` can fit within the size of a heap chunk.
unsafe impl Heapable<AllocInfo> for AllocInfo {
    fn next(&mut self) -> *mut Option<NonNull<AllocInfo>> {
        // we are re-using the space of base_addr to store the free list pointer
        // SAFETY: this is safe because both union fields are raw pointers
        unsafe { &raw mut self.base_addr.free_list_next }
    }
}

unsafe impl Stackable for AllocInfo {}

unsafe impl Stackable for BorTag {}

/// All of our custom allocators depend on `mmap` and `munmap`. We propagate
/// any nonzero exit-codes from these functions to the user as errors.
#[derive(Clone, Copy, Debug)]
pub enum AllocError {
    InvalidStackSize,
    InvalidPageSize,
    StackOverflow,
    MMapFailed(InternalAllocKind, i32),
    MUnmapFailed(InternalAllocKind, i32),
    InvalidHeapSize(usize),
}

#[derive(Clone, Copy, Debug)]
pub enum InternalAllocKind {
    Heap,
    Stack,
    ShadowHeap,
}

pub(crate) type AllocResult<T> = Result<T, AllocError>;

/// Credit: bumpalo
#[cold]
#[inline(never)]
pub(crate) fn unmap_failed<T>() -> T {
    panic!("failed to unmap allocation")
}

/// Credit: bumpalo
#[inline]
pub(crate) const fn round_up_to(n: usize, divisor: usize) -> Option<usize> {
    debug_assert!(divisor > 0);
    debug_assert!(divisor.is_power_of_two());
    match n.checked_add(divisor - 1) {
        Some(x) => Some(x & !(divisor - 1)),
        None => None,
    }
}

/// Credit: bumpalo
/// Like `round_up_to` but turns overflow into undefined behavior rather than
/// returning `None`.
#[inline]
pub(crate) unsafe fn round_up_to_unchecked(n: usize, divisor: usize) -> usize {
    match round_up_to(n, divisor) {
        Some(x) => x,
        None => {
            debug_assert!(false, "round_up_to_unchecked failed");
            unsafe { core::hint::unreachable_unchecked() }
        }
    }
}

/// Credit: bumpalo
/// Same as `round_down_to` but preserves pointer provenance.
#[inline]
pub(crate) fn round_mut_ptr_down_to<T>(ptr: *mut T, divisor: usize) -> *mut T {
    debug_assert!(divisor > 0);
    debug_assert!(divisor.is_power_of_two());
    ptr.wrapping_sub(ptr as usize & (divisor - 1))
}

/// Credit: bumpalo
#[inline]
pub(crate) unsafe fn round_mut_ptr_up_to_unchecked(ptr: *mut u8, divisor: usize) -> *mut u8 {
    debug_assert!(divisor > 0);
    debug_assert!(divisor.is_power_of_two());
    let aligned = unsafe { round_up_to_unchecked(ptr as usize, divisor) };
    let delta = aligned - (ptr as usize);
    unsafe { ptr.add(delta) }
}

/// # Safety
/// The pointer must be offset from the beginning of its allocation
/// by at least `mem::size_of::<B>()` bytes.
#[inline]
pub unsafe fn align_down<A, B>(ptr: NonNull<A>) -> NonNull<B> {
    debug_assert!(ptr.as_ptr().is_aligned());
    unsafe {
        let ptr = ptr.cast::<u8>();
        let ptr = round_mut_ptr_down_to(ptr.as_ptr(), mem::align_of::<B>());
        let ptr = ptr.cast::<B>();
        debug_assert!(ptr.is_aligned());
        NonNull::<B>::new_unchecked(ptr)
    }
}

/// # Safety
/// If the parameter is rounded up to the nearest multiple of `mem::align_of::<B>()`, then it must still\
/// be within the allocation.
#[inline]
pub unsafe fn align_up<A, B>(ptr: NonNull<A>) -> NonNull<B> {
    debug_assert!(ptr.as_ptr().is_aligned());
    unsafe {
        let ptr = ptr.cast::<u8>();
        let ptr = round_mut_ptr_up_to_unchecked(ptr.as_ptr(), mem::align_of::<B>());
        let ptr = ptr.cast::<B>();
        debug_assert!(ptr.is_aligned());
        NonNull::<B>::new_unchecked(ptr)
    }
}

/// A wrapper around `mmap` that converts non-zero exit codes into errors.
#[inline]
pub unsafe fn mmap<T>(
    mmap: hooks::MMap,
    kind: InternalAllocKind,
    size_bytes: NonZero<usize>,
) -> AllocResult<NonNull<T>> {
    let size_bytes = size_bytes.get();
    unsafe {
        let ptr = (mmap)(ptr::null_mut(), size_bytes, BSAN_PROT_FLAGS, BSAN_MAP_FLAGS, -1, 0);
        if ptr.is_null() || ptr == libc::MAP_FAILED {
            let errno = *libc::__errno_location();
            Err(AllocError::MMapFailed(kind, errno))
        } else {
            Ok(NonNull::<T>::new_unchecked(ptr.cast::<T>()))
        }
    }
}

/// A wrapper around `munmap` that converts non-zero exit codes into errors.
#[inline]
pub unsafe fn munmap<T>(
    munmap: MUnmap,
    kind: InternalAllocKind,
    ptr: NonNull<T>,
    size_bytes: NonZero<usize>,
) -> AllocResult<()> {
    let size_bytes = size_bytes.get();
    unsafe {
        let ptr = ptr.as_ptr();
        let ptr = ptr.cast::<c_void>();
        let res = (munmap)(ptr, size_bytes);
        if res == -1 {
            let errno = *libc::__errno_location();
            Err(AllocError::MUnmapFailed(kind, errno))
        } else {
            Ok(())
        }
    }
}
