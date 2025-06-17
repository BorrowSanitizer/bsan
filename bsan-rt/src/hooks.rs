use alloc::alloc::{AllocError, Allocator, Layout};
use core::ffi::c_void;
use core::mem;
use core::num::NonZeroUsize;
use core::ptr::{self, NonNull};

use libc::off_t;

use crate::block::Block;

pub static BSAN_PROT_FLAGS: i32 = libc::PROT_READ | libc::PROT_WRITE;
#[cfg(not(miri))]
pub static BSAN_MAP_FLAGS: i32 = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE;
#[cfg(miri)]
pub static BSAN_MAP_FLAGS: i32 = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

pub type MMap = unsafe extern "C" fn(*mut c_void, usize, i32, i32, i32, off_t) -> *mut c_void;
pub type MUnmap = unsafe extern "C" fn(*mut c_void, usize) -> i32;
pub type Malloc = unsafe extern "C" fn(usize) -> *mut c_void;
pub type Free = unsafe extern "C" fn(*mut c_void);
pub type Exit = unsafe extern "C" fn() -> !;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct BsanHooks {
    pub alloc: BsanAllocHooks,
    pub mmap: MMap,
    pub munmap: MUnmap,
    pub exit: Exit,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BsanAllocHooks {
    malloc: Malloc,
    free: Free,
}

impl BsanHooks {
    pub fn new_block<T>(&self, num_elements: NonZeroUsize) -> Block<T> {
        let layout = Layout::array::<T>(num_elements.into()).unwrap();
        let base = unsafe {
            (self.mmap)(ptr::null_mut(), layout.size(), BSAN_PROT_FLAGS, BSAN_MAP_FLAGS, -1, 0)
        };

        assert!(!base.is_null());
        assert!(base.addr() as isize != -1isize);

        let base = unsafe { mem::transmute::<*mut c_void, *mut T>(base) };
        let base = unsafe { NonNull::new_unchecked(base) };
        let munmap = self.munmap;
        Block { num_elements, base, munmap }
    }
}

unsafe impl Allocator for BsanAllocHooks {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        unsafe {
            match layout.size() {
                0 => Ok(NonNull::slice_from_raw_parts(layout.dangling(), 0)),
                size => {
                    let ptr = (self.malloc)(layout.size());
                    if ptr.is_null() {
                        return Err(AllocError);
                    }
                    let ptr = NonNull::new_unchecked(ptr as *mut u8);
                    Ok(NonNull::slice_from_raw_parts(ptr, size))
                }
            }
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        unsafe {
            let ptr = mem::transmute::<*mut u8, *mut libc::c_void>(ptr.as_ptr());
            (self.free)(ptr);
        }
    }
}

unsafe extern "C" fn default_exit() -> ! {
    unsafe { libc::exit(0) }
}

pub static DEFAULT_HOOKS: BsanHooks = BsanHooks {
    alloc: BsanAllocHooks { malloc: libc::malloc, free: libc::free },
    mmap: libc::mmap,
    munmap: libc::munmap,
    exit: default_exit,
};
