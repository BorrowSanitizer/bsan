use core::ffi::c_void;
use core::mem::{self, MaybeUninit};
use core::num::{NonZero, NonZeroUsize};
use core::ptr::{self, NonNull};

use cfg_if::cfg_if;
use libc::{rlimit, RLIMIT_STACK, _SC_PAGESIZE};

use crate::hooks::{MMap, MUnmap};
use crate::{BorTag, Provenance};

#[derive(Debug)]
pub struct Sizes {
    pub page: NonZero<usize>,
    pub stack: NonZero<usize>,
}

impl Default for Sizes {
    fn default() -> Self {
        let page = get_page_size().expect("Page size set to 0.");
        let stack = get_stack_size().expect("Stack size set to 0.");
        Self { page, stack }
    }
}

#[allow(unused)]
pub fn get_page_size() -> Option<NonZero<usize>> {
    unsafe {
        let page_size = libc::sysconf(_SC_PAGESIZE) as usize;
        NonZero::new(page_size)
    }
}

#[allow(unused)]
pub fn get_stack_size() -> Option<NonZero<usize>> {
    let mut limits = MaybeUninit::<rlimit>::uninit();
    #[cfg(not(miri))]
    let exit_code = unsafe { libc::getrlimit(RLIMIT_STACK, limits.as_mut_ptr()) };

    #[cfg(miri)]
    let exit_code = unsafe {
        (*limits.as_mut_ptr()).rlim_cur = 1024;
        (*limits.as_mut_ptr()).rlim_max = 1024;
        0
    };

    let stack_size_bytes = if (exit_code != 0) {
        panic!("Failed to obtain stack size limit.");
    } else {
        let limits = unsafe { MaybeUninit::assume_init(limits) };
        limits.rlim_cur as usize
    };

    NonZero::new(stack_size_bytes)
}

/// # Safety
/// The pointer must be offset from the beginning of its allocation
/// by at least `mem::size_of::<B>()` bytes.
#[inline]
pub unsafe fn align_down<A, B>(ptr: NonNull<A>) -> NonNull<B> {
    debug_assert!(ptr.as_ptr().is_aligned());
    unsafe {
        let ptr = ptr.cast::<u8>();

        // round down to nearest aligned address
        let addr = ptr.expose_provenance();
        let addr = (addr.get() & !(mem::align_of::<B>() - 1));
        let ptr: *mut u8 = ptr::with_exposed_provenance_mut(addr);

        let ptr = ptr.cast::<B>();
        let ptr = ptr.sub(1);

        debug_assert!(ptr.is_aligned());
        NonNull::<B>::new_unchecked(ptr)
    }
}

/// # Safety
/// If the parameter is rounded up to the nearest multiple of `mem::align_of::<B>()` and
/// then offset by `mem::size_of::<B>()`, it must still be within the allocation.
#[inline]
pub unsafe fn align_up<A, B>(ptr: NonNull<A>) -> NonNull<B> {
    debug_assert!(ptr.as_ptr().is_aligned());
    unsafe {
        let ptr = ptr.cast::<u8>();

        // round up to nearest aligned address
        let addr = ptr.expose_provenance();
        let align = mem::align_of::<B>();
        let addr = (addr.get() + align - 1) & !(align - 1);
        let ptr: *mut u8 = ptr::with_exposed_provenance_mut(addr);
        let ptr = ptr.cast::<B>();

        debug_assert!(ptr.is_aligned());
        NonNull::<B>::new_unchecked(ptr)
    }
}

#[inline]
pub unsafe fn mmap<T>(mmap: MMap, size_bytes: NonZero<usize>, prot: i32, flags: i32) -> NonNull<T> {
    let size_bytes = size_bytes.get();
    unsafe {
        let ptr = (mmap)(ptr::null_mut(), size_bytes, prot, flags, -1, 0);
        let ptr = ptr.cast::<T>();
        if ptr.is_null() || ptr.addr() as isize == -1 {
            panic!("Failed to allocate page of size {size_bytes:?}.");
        } else {
            NonNull::<T>::new_unchecked(ptr)
        }
    }
}

#[inline]
pub unsafe fn munmap<T>(munmap: MUnmap, ptr: NonNull<T>, size_bytes: NonZero<usize>) {
    let size_bytes = size_bytes.get();
    unsafe {
        let ptr = ptr.as_ptr();
        let ptr = ptr.cast::<c_void>();
        (munmap)(ptr, size_bytes);
    }
}
