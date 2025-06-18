use core::mem::{self, MaybeUninit};
use core::num::NonZeroUsize;
use core::ptr::{self, NonNull};

use cfg_if::cfg_if;
use libc::{rlimit, RLIMIT_STACK};

use crate::{BorTag, Provenance};

#[derive(Debug)]
pub struct StackElementCounts {
    pub provenance: NonZeroUsize,
    pub borrow_tag: NonZeroUsize,
}

macro_rules! nonzero_size {
    ($s:expr, $p:ty) => {{
        let expr: usize = ($s / core::mem::size_of::<$p>()) as usize;
        cfg_if! {
            if #[cfg(debug_assertions)] {
                NonZeroUsize::new(expr).expect("Zero size in stack element count.")
            }else{
                unsafe {
                    NonZeroUsize::new_unchecked(expr)
                }
            }
        }
    }};
}

impl Default for StackElementCounts {
    fn default() -> Self {
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
        let provenance = nonzero_size!(stack_size_bytes, Provenance);
        let borrow_tag = nonzero_size!(stack_size_bytes, BorTag);
        Self { provenance, borrow_tag }
    }
}

/// # Safety
/// The pointer must be offset from the beginning of its allocation
/// by at least `mem::size_of::<B>()` bytes.
#[inline(always)]
pub unsafe fn align_down<A, B>(ptr: NonNull<A>) -> NonNull<B> {
    debug_assert!(ptr.as_ptr().is_aligned());
    unsafe {
        let ptr = mem::transmute::<*mut A, *mut u8>(ptr.as_ptr());

        // round down to nearest aligned address
        let addr = ptr.expose_provenance();
        let addr = (addr & !(mem::align_of::<B>() - 1));
        let ptr = ptr::with_exposed_provenance_mut(addr);

        let ptr = mem::transmute::<*mut u8, *mut B>(ptr);
        let ptr = ptr.sub(1);

        debug_assert!(ptr.is_aligned());
        NonNull::<B>::new_unchecked(ptr)
    }
}

/// # Safety
/// If the parameter is rounded up to the nearest multiple of `mem::align_of::<B>()` and
/// then offset by `mem::size_of::<B>()`, it must still be within the allocation.
#[inline(always)]
pub unsafe fn align_up<A, B>(ptr: NonNull<A>) -> NonNull<B> {
    debug_assert!(ptr.as_ptr().is_aligned());
    unsafe {
        let ptr = mem::transmute::<*mut A, *mut u8>(ptr.as_ptr());

        // round up to nearest aligned address
        let addr = ptr.expose_provenance();
        let align = mem::align_of::<B>();
        let addr = (addr + align - 1) & !(align - 1);
        let ptr = ptr::with_exposed_provenance_mut(addr);

        let ptr = mem::transmute::<*mut u8, *mut B>(ptr);

        debug_assert!(ptr.is_aligned());
        NonNull::<B>::new_unchecked(ptr)
    }
}
