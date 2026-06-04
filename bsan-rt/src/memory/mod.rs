//! Several types of objects are frequently allocated by our runtime. This crate includes implementations of several
//! custom allocators for these objects. A `Stack<T>` is a bump allocator for instances of `T`. It supports
//! pushing and popping frames containing multiple instances. A `Heap<T>` is also a bump allocator without frames.
//! However, unlike a `Stack`, a `Heap` supports deallocating objects at any point. Both allocators rely internally
//! on a linked list of page-sized "blocks" of memory.

mod heap;
pub use heap::Heap;
use heap::Heapable;
use libc::{pthread_attr_destroy, pthread_attr_init, pthread_attr_t, rlimit, _SC_PAGESIZE};

mod shadow;
use core::ffi::c_void;
use core::mem::{self, MaybeUninit};
use core::num::NonZero;
use core::ptr::{self, NonNull};

pub use shadow::ShadowHeap;

use crate::{AllocInfo, BorTag};

pub const BSAN_PROT_FLAGS: i32 = libc::PROT_READ | libc::PROT_WRITE;
#[cfg(not(miri))]
pub const BSAN_MAP_FLAGS: i32 =
    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_ANON | libc::MAP_NORESERVE;
#[cfg(miri)]
pub const BSAN_MAP_FLAGS: i32 = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_ANON;

#[derive(Debug, Copy, Clone)]
pub struct StackSize(NonZero<usize>);

#[allow(clippy::from_over_into)]
impl Into<NonZero<usize>> for StackSize {
    fn into(self) -> NonZero<usize> {
        self.0
    }
}

#[allow(unused)]
impl StackSize {
    pub fn from_rlimit() -> Self {
        let mut limits = MaybeUninit::<rlimit>::uninit();

        let exit_code = unsafe { libc::getrlimit(libc::RLIMIT_STACK, limits.as_mut_ptr()) };
        assert!(exit_code == 0, "`getrlimit` with `RLIMIT_STACK failed: {exit_code}");

        let size = unsafe { limits.assume_init() }.rlim_cur as usize;
        unsafe { StackSize(NonZero::new_unchecked(size)) }
    }

    pub fn from_pthread() -> Self {
        let mut attr = MaybeUninit::<pthread_attr_t>::uninit();

        let attr_init = unsafe { pthread_attr_init(attr.as_mut_ptr()) };
        assert!(attr_init == 0, "`pthread_attr_init` failed: {attr_init}");

        let mut size = MaybeUninit::<libc::size_t>::uninit();
        let size_init =
            unsafe { libc::pthread_attr_getstacksize(attr.as_mut_ptr(), size.as_mut_ptr()) };
        assert!(size_init == 0, "`pthread_attr_getstacksize` failed: {size_init}");

        let attr_destroy = unsafe { pthread_attr_destroy(attr.as_mut_ptr()) };
        assert!(attr_destroy == 0, "`pthread_attr_destroy` failed: {attr_destroy}");

        let size = unsafe { NonZero::new_unchecked(size.assume_init()) };
        StackSize(size)
    }
}

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
    fn next(&mut self) -> *mut Option<NonNull<AllocInfo>> {
        // we are re-using the space of base_addr to store the free list pointer
        // SAFETY: this is safe because both union fields are raw pointers
        #[allow(unused_unsafe)]
        unsafe {
            &raw mut (*self.base_addr.as_ptr()).free_list_next
        }
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
    use crate::memory::{next_greater_multiple_unchecked, StackSize};

    #[test]
    fn stack_size() {
        StackSize::from_rlimit();
        std::thread::spawn(move || {
            StackSize::from_pthread();
        })
        .join()
        .unwrap();
    }

    #[test]
    fn rounding() {
        unsafe { assert_eq!(next_greater_multiple_unchecked(4, 4), 8) }
        unsafe { assert_eq!(next_greater_multiple_unchecked(4, 8), 8) }
    }
}
