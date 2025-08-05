//! Several types of objects are frequently allocated by our runtime. This crate includes implementations of several
//! custom allocators for these objects. A `Stack<T>` is a bump allocator for instances of `T`. It supports
//! pushing and popping frames containing multiple instances. A `Heap<T>` is also a bump allocator without frames.
//! However, unlike a `Stack`, a `Heap` supports deallocating objects at any point. Both allocators rely internally
//! on a linked list of page-sized "blocks" of memory.
pub mod hooks;
use hooks::*;

mod heap;
pub use heap::{Heap, Heapable};

mod stack;
pub use stack::Stack;

mod shadow;
use core::ffi::c_void;
use core::mem;
use core::num::NonZero;
use core::ptr::{self, NonNull};

pub use shadow::ShadowHeap;

/// All of our custom allocators depend on `mmap` and `munmap`. We propagate
/// any nonzero exit-codes from these functions to the user as errors.
#[derive(Clone, Copy, Debug)]
pub enum AllocError {
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

static TYPICAL_PAGE_SIZE: NonZero<usize> = NonZero::new(0x1000).unwrap();

/// A contiguous chunk of memory
#[derive(Debug, Clone, Copy)]
pub(crate) struct Chunk {
    /// A pointer to the start of the allocation
    base_address: NonNull<u8>,
    /// The size of the allocation
    size: NonZero<usize>,
}

impl Chunk {
    pub(crate) fn new(
        mmap_ptr: hooks::MMap,
        size: NonZero<usize>,
        kind: InternalAllocKind,
    ) -> AllocResult<Chunk> {
        let base_address =
            unsafe { mmap(mmap_ptr, kind, size, hooks::BSAN_PROT_FLAGS, hooks::BSAN_MAP_FLAGS)? };
        Ok(Chunk { base_address, size })
    }
    pub(crate) fn dispose(
        self,
        munmap_ptr: hooks::MUnmap,
        kind: InternalAllocKind,
    ) -> AllocResult<()> {
        unsafe { munmap(munmap_ptr, kind, self.base_address, self.size)? };
        Ok(())
    }
}

/// Credit: bumpalo
#[cold]
#[inline(never)]
pub(crate) fn allocation_size_overflow<T>() -> T {
    panic!("requested allocation size overflowed")
}

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
    prot: i32,
    flags: i32,
) -> AllocResult<NonNull<T>> {
    let size_bytes = size_bytes.get();
    unsafe {
        let ptr = (mmap)(ptr::null_mut(), size_bytes, prot, flags, -1, 0);
        if ptr.is_null() || ptr.addr() as isize == -1 {
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
