//! Several types of objects are allocated frequently. This crate includes implementations of several
//! custom allocators for these objects. A `Stack<T>` is a bump allocator for instances of `T`. It supports
//! pushing and popping frames containing multiple instances. A `Heap<T>` is also a bump allocator without frames.
//! However, unlike a `Stack`, a `Heap` supports deallocating objects at any point. Both allocators rely internally
//! on a linked list of pages.
pub mod hooks;
use hooks::*;

mod heap;
pub use heap::{Bumpable, Heap};

mod stack;
pub use stack::Stack;

mod shadow;
use core::ffi::c_void;
use core::marker::PhantomData;
use core::mem::{self, MaybeUninit};
use core::num::NonZero;
use core::ops::Deref;
use core::ptr::{self, NonNull};

use libc::_SC_PAGESIZE;
pub use shadow::ShadowHeap;

/// All of our custom allocators depend on `mmap` and `munmap`. We propagate
/// any nonzero exit-codes from these functions to the user as errors.
#[derive(Clone, Copy, Debug)]
pub enum AllocError {
    MMapFailed(i32),
    MUnmapFailed(i32),
}

pub(crate) type AllocResult<T> = Result<T, AllocError>;

#[derive(Debug, Copy, Clone)]
pub struct PageSize(NonZero<usize>);

impl Deref for PageSize {
    type Target = NonZero<usize>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for PageSize {
    fn default() -> Self {
        let page_size = unsafe { libc::sysconf(_SC_PAGESIZE) } as usize;
        Self(NonZero::new(page_size).expect("Received 0 for page size."))
    }
}

static PAGE_SIZE: PageSize = PageSize(NonZero::new(0x1000).expect("Page size should be nonzero"));

#[derive(Debug)]
pub(crate) struct BlockSize<T> {
    size: NonZero<usize>,
    data: PhantomData<*const T>,
}

impl<T> Deref for BlockSize<T> {
    type Target = NonZero<usize>;

    fn deref(&self) -> &Self::Target {
        &self.size
    }
}

impl<T: HasMinBlockSize<T>> From<PageSize> for BlockSize<T> {
    fn from(val: PageSize) -> BlockSize<T> {
        unsafe { T::get_unchecked(val.0) }
    }
}

/// # Safety
/// Each block should store values of type `Value`. Blocks can
/// also have a header of type `Header`. A minimum, a block for a given
/// allocator should be able to store the `Header` and at least one `Value`.
pub(crate) unsafe trait HasMinBlockSize<T> {
    type Header: Sized;
    type Values: Sized;

    fn valid(size: NonZero<usize>) -> bool {
        size.get() >= (mem::size_of::<Self::Header>() + mem::size_of::<Self::Values>())
    }

    unsafe fn get_unchecked(size: NonZero<usize>) -> BlockSize<T> {
        debug_assert!(Self::valid(size));
        BlockSize { size, data: PhantomData }
    }
}

impl<T> Clone for BlockSize<T> {
    fn clone(&self) -> BlockSize<T> {
        *self
    }
}

impl<T> Copy for BlockSize<T> {}

#[derive(Clone, Debug)]
pub(crate) struct Block<T: HasMinBlockSize<T>> {
    /// A pointer to the header.
    header: NonNull<MaybeUninit<T::Header>>,
    /// A pointer to the end of the block, aligned up so that
    /// `cursor` will eventually be equal to `limit` when the
    /// block is full.
    limit: NonNull<MaybeUninit<u8>>,
}

impl<T: HasMinBlockSize<T>> Block<T> {
    pub(crate) fn new(mmap_ptr: hooks::MMap, size: BlockSize<T>) -> AllocResult<Block<T>> {
        let limit =
            unsafe { mmap(mmap_ptr, *size, hooks::BSAN_PROT_FLAGS, hooks::BSAN_MAP_FLAGS)? };

        let high_end = unsafe { limit.add(size.get()) };

        let header: NonNull<MaybeUninit<T::Header>> =
            unsafe { align_down::<MaybeUninit<u8>, MaybeUninit<T::Header>>(high_end).sub(1) };

        Ok(Block { header, limit })
    }
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

/// Like `round_up_to` but turns overflow into undefined behavior rather than
/// returning `None`.
/// Credit: bumpalo
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

/// Same as `round_down_to` but preserves pointer provenance.
/// Credit: bumpalo
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
    size_bytes: NonZero<usize>,
    prot: i32,
    flags: i32,
) -> AllocResult<NonNull<MaybeUninit<T>>> {
    let size_bytes = size_bytes.get();
    unsafe {
        let ptr = (mmap)(ptr::null_mut(), size_bytes, prot, flags, -1, 0);
        let ptr = ptr.cast::<MaybeUninit<T>>();
        if ptr.is_null() || ptr.addr() as isize == -1 {
            let errno = *libc::__errno_location();
            Err(AllocError::MMapFailed(errno))
        } else {
            Ok(NonNull::<MaybeUninit<T>>::new_unchecked(ptr))
        }
    }
}

/// A wrapper around `munmap` that converts non-zero exit codes into errors.
#[inline]
pub unsafe fn munmap<T>(
    munmap: MUnmap,
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
            Err(AllocError::MUnmapFailed(errno))
        } else {
            Ok(())
        }
    }
}
