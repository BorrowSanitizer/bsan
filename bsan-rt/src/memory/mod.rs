//! Several types of objects are frequently allocated by our runtime. This crate includes implementations of several
//! custom allocators for these objects. A `Stack<T>` is a bump allocator for instances of `T`. It supports
//! pushing and popping frames containing multiple instances. A `Heap<T>` is also a bump allocator without frames.
//! However, unlike a `Stack`, a `Heap` supports deallocating objects at any point. Both allocators rely internally
//! on a linked list of page-sized "blocks" of memory.

mod heap;
use core::ffi::c_void;
use core::mem;
use core::num::NonZero;
use core::ptr::{self, NonNull};

pub use heap::*;
use libc::_SC_PAGESIZE;

use crate::{AllocInfo, BorTag};

pub const BSAN_PROT_FLAGS: i32 = libc::PROT_READ | libc::PROT_WRITE;
#[cfg(not(miri))]
pub const BSAN_MAP_FLAGS: i32 =
    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_ANON | libc::MAP_NORESERVE;
#[cfg(miri)]
pub const BSAN_MAP_FLAGS: i32 = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_ANON;

static mut PAGE_SIZE_CACHED: Option<NonZero<usize>> = None;

#[derive(Debug, Copy, Clone)]
struct PageSize;

impl PageSize {
    fn get_cached() -> NonZero<usize> {
        let cached_size = unsafe { PAGE_SIZE_CACHED };
        cached_size.unwrap_or_else(|| {
            let size = Self::get();
            unsafe { PAGE_SIZE_CACHED = Some(size) };
            size
        })
    }

    fn get() -> NonZero<usize> {
        let page_size = unsafe { libc::sysconf(_SC_PAGESIZE) };
        debug_assert!(page_size > 0);
        let size = unsafe { NonZero::new_unchecked(page_size as usize) };
        unsafe { PAGE_SIZE_CACHED = Some(size) };
        size
    }
}

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
    fn next(ptr: *mut AllocInfo) -> *mut Option<NonNull<AllocInfo>> {
        unsafe { (&raw mut (*((*ptr).free_or_addr).as_ptr()).free_list_next) }
    }
}

/// Credit: bumpalo
/// Like `round_up_to` but turns overflow into undefined behavior rather than
/// returning `None`.
#[inline]
pub(crate) unsafe fn next_greater_multiple_unchecked(n: usize, divisor: usize) -> usize {
    debug_assert!(divisor > 0);
    debug_assert!(divisor.is_power_of_two());
    debug_assert!(usize::MAX - n >= divisor);
    unsafe { n.unchecked_add(divisor) & !(divisor - 1) }
}

/// Credit: bumpalo
#[inline]
pub(crate) unsafe fn round_mut_ptr_up_to_unchecked(ptr: *mut u8, divisor: usize) -> *mut u8 {
    let aligned = unsafe { next_greater_multiple_unchecked(ptr as usize, divisor) };
    let delta = aligned - (ptr as usize);
    unsafe { ptr.add(delta) }
}

/// A wrapper around `mmap` that converts non-zero exit codes into errors.
#[inline]
pub fn mmap(size_bytes: NonZero<usize>) -> NonNull<u8> {
    let size_bytes = size_bytes.get();
    unsafe {
        let ptr = libc::mmap(ptr::null_mut(), size_bytes, BSAN_PROT_FLAGS, BSAN_MAP_FLAGS, -1, 0);
        if ptr.is_null() || ptr == libc::MAP_FAILED {
            let errno = *libc::__errno_location();
            libc_failed("mmap", errno);
        }
        NonNull::new_unchecked(ptr.cast())
    }
}

#[cold]
#[inline(never)]
pub(crate) fn libc_failed(name: &str, exit_code: libc::c_int) -> ! {
    panic!("`{name}` failed with exit code: {exit_code}")
}

/// A wrapper around `munmap` that converts non-zero exit codes into errors.
#[inline]
pub unsafe fn munmap<T>(ptr: NonNull<T>, size_bytes: impl Into<NonZero<usize>>) {
    let size_bytes = size_bytes.into().get();
    unsafe {
        let ptr = ptr.as_ptr();
        let ptr = ptr.cast::<c_void>();
        let res = libc::munmap(ptr, size_bytes);
        if res == -1 {
            let errno = *libc::__errno_location();
            libc_failed("munmap", errno)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::memory::next_greater_multiple_unchecked;

    #[test]
    fn rounding() {
        unsafe { assert_eq!(next_greater_multiple_unchecked(4, 4), 8) }
        unsafe { assert_eq!(next_greater_multiple_unchecked(4, 8), 8) }
    }
}
