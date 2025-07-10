use alloc::alloc::{AllocError, Allocator, Layout};
use core::ffi::c_void;
use core::ptr::NonNull;

use libc::off_t;

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
    pub mmap_ptr: MMap,
    pub munmap_ptr: MUnmap,
    pub exit: Exit,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BsanAllocHooks {
    malloc: Malloc,
    free: Free,
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
                    let ptr = NonNull::new_unchecked(ptr.cast::<u8>());
                    Ok(NonNull::slice_from_raw_parts(ptr, size))
                }
            }
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        unsafe {
            let ptr = ptr.cast::<libc::c_void>();
            (self.free)(ptr.as_ptr());
        }
    }
}

unsafe extern "C" fn default_exit() -> ! {
    unsafe { libc::exit(0) }
}

pub static DEFAULT_HOOKS: BsanHooks = BsanHooks {
    alloc: BsanAllocHooks { malloc: libc::malloc, free: libc::free },
    mmap_ptr: libc::mmap,
    munmap_ptr: libc::munmap,
    exit: default_exit,
};
