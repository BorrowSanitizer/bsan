use core::mem::{self, MaybeUninit};
use core::num::NonZeroUsize;

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
