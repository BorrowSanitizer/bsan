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

mod shadow;
use core::ffi::c_void;
use core::mem;
use core::num::NonZero;
use core::ptr::{self, NonNull};

pub use shadow::ShadowHeap;

use crate::{AllocInfo, BorTag};

/// # Safety
/// Values must be aligned to the word size of the current platform.
pub(crate) unsafe trait WordAligned: Sized {
    fn is_word_aligned() -> bool {
        mem::align_of::<Self>() == mem::align_of::<usize>()
    }
}
unsafe impl WordAligned for AllocInfo {}
unsafe impl WordAligned for BorTag {}

/// # Safety
/// Values of type `AllocInfo` can fit within the size of a heap chunk.
unsafe impl Heapable for AllocInfo {
    fn next(&mut self) -> *mut Option<NonNull<AllocInfo>> {
        // we are re-using the space of base_addr to store the free list pointer
        // SAFETY: this is safe because both union fields are raw pointers
        unsafe { &raw mut self.base_addr.free_list_next }
    }
}

/// All of our custom allocators depend on `mmap` and `munmap`. We propagate
/// any nonzero exit-codes from these functions to the user as errors.
#[derive(Clone, Copy, Debug)]
pub enum AllocError {
    InvalidStackSize,
    InvalidPageSize,
    StackOverflow,
    MMapFailed(InternalAllocKind, i32),
    MUnmapFailed(InternalAllocKind, i32),
}

#[derive(Clone, Copy, Debug)]
pub enum InternalAllocKind {
    Heap,
    Stack,
    ShadowHeap,
}

pub(crate) type AllocResult<T> = Result<T, AllocError>;

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
#[inline]
pub(crate) unsafe fn round_mut_ptr_up_to_unchecked(ptr: *mut u8, divisor: usize) -> *mut u8 {
    debug_assert!(divisor > 0);
    debug_assert!(divisor.is_power_of_two());
    let aligned = unsafe { round_up_to_unchecked(ptr as usize, divisor) };
    let delta = aligned - (ptr as usize);
    unsafe { ptr.add(delta) }
}

/// A wrapper around `mmap` that converts non-zero exit codes into errors.
#[inline]
pub unsafe fn mmap(
    mmap: hooks::MMap,
    kind: InternalAllocKind,
    size_bytes: NonZero<usize>,
) -> AllocResult<NonNull<u8>> {
    let size_bytes = size_bytes.get();
    unsafe {
        let ptr = (mmap)(ptr::null_mut(), size_bytes, BSAN_PROT_FLAGS, BSAN_MAP_FLAGS, -1, 0);
        if ptr.is_null() || ptr == libc::MAP_FAILED {
            let errno = *libc::__errno_location();
            Err(AllocError::MMapFailed(kind, errno))
        } else {
            Ok(NonNull::new_unchecked(ptr.cast()))
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
