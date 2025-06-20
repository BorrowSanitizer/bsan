use core::cell::UnsafeCell;
use core::hint;
use core::mem::MaybeUninit;
use core::num::NonZeroUsize;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use crate::hooks::{BsanHooks, MUnmap, BSAN_MAP_FLAGS, BSAN_PROT_FLAGS};
use crate::*;

/// Types that implement this trait can act as elements
/// of a singly-linked list.
///
/// # Safety
///
/// The pointer that is returned by `next` must not be mutated concurrently.
pub unsafe trait Linkable<T: Sized> {
    fn next(&self) -> *mut *mut T;
}

/// An mmap-ed chunk of memory that will munmap the chunk on drop.
#[derive(Debug)]
pub struct Block<T: Sized> {
    num_elements: NonZero<usize>,
    base: NonNull<T>,
    munmap: MUnmap,
}

impl<T: Sized> Block<T> {
    pub fn new(hooks: &BsanHooks, num_elements: NonZero<usize>) -> Block<T> {
        // Only sized types are allowed.
        let ty_size = unsafe { NonZero::new_unchecked(mem::size_of::<T>()) };

        #[cfg(debug_assertions)]
        let num_bytes =
            num_elements.checked_mul(ty_size).expect("Overflow when computing size of block.");

        #[cfg(not(debug_assertions))]
        let num_bytes = unsafe { NonZero::new_unchecked(num_elements.get() * ty_size.get()) };

        let base =
            unsafe { utils::mmap(hooks.mmap_ptr, num_bytes, BSAN_PROT_FLAGS, BSAN_MAP_FLAGS) };

        Block { num_elements, base, munmap: hooks.munmap_ptr }
    }

    // The last valid, addressable element in the block.
    #[inline]
    pub fn last(&self) -> NonNull<T> {
        unsafe { self.end().sub(mem::size_of::<T>()) }
    }

    // The upper end of the block; an invalid address.
    #[inline]
    pub fn end(&self) -> NonNull<T> {
        unsafe { NonNull::new_unchecked(self.base.as_ptr().add(self.num_elements.get())) }
    }

    /// The first valid, addressable location within the block (at its low-end)
    #[inline]
    pub fn start(&self) -> NonNull<T> {
        self.base
    }
}

impl<T> Drop for Block<T> {
    fn drop(&mut self) {
        // SAFETY: our munmap pointer will be valid by construction of the GlobalCtx.
        // We can safely transmute it to c_void since that's what it was originally when
        // it was allocated by mmap
        let success = unsafe {
            let ptr = mem::transmute::<*mut T, *mut libc::c_void>(self.base.as_ptr());
            (self.munmap)(ptr, self.num_elements.get())
        };
        if success != 0 {
            panic!("Failed to unmap block!");
        }
    }
}

/// A fixed-capacity, semi-lock-free, thread-safe bump-allocator.
#[derive(Debug)]
pub struct BlockAllocator<T: Linkable<T>> {
    /// The next valid element, which will be uninitialized.
    cursor: AtomicPtr<MaybeUninit<T>>,
    /// A list of freed elements, which can be anywhere in the block.
    /// This needs to be interior mutable since both alloc and dealloc
    /// need to modify the free list through &self
    free_list: UnsafeCell<*mut T>,
    /// A mutex for the free list
    free_lock: AtomicBool,
    /// The block of memory where instances are allocated from.
    block: Block<T>,
}

// SAFETY: Whenever we mutate the allocator, we either lock on `free_lock`
// or we're executing an atomic operation.
unsafe impl<T: Linkable<T>> Send for BlockAllocator<T> {}
unsafe impl<T: Linkable<T>> Sync for BlockAllocator<T> {}

impl<T: Linkable<T>> BlockAllocator<T> {
    /// Initializes a BlockAllocator for the given block.
    fn new(block: Block<T>) -> Self {
        BlockAllocator {
            // we begin at the high-end of the block and decrement downward
            cursor: AtomicPtr::new(block.last().as_ptr() as *mut MaybeUninit<T>),
            free_list: UnsafeCell::new(core::ptr::null::<T>() as *mut T),
            free_lock: AtomicBool::new(false),
            block,
        }
    }

    /// Allocates a new instance from the block.
    /// If a prior allocation has been freed, it will be reused instead of
    /// incrementing the internal cursor.
    fn alloc(&self) -> Option<NonNull<MaybeUninit<T>>> {
        if !self.free_lock.swap(true, Ordering::Acquire) {
            let curr = unsafe { *self.free_list.get() };
            let curr = if !curr.is_null() {
                unsafe {
                    let next = (*curr).next();
                    *self.free_list.get() = *next;
                    Some(NonNull::new_unchecked(curr as *mut MaybeUninit<T>))
                }
            } else {
                None
            };
            self.free_lock.store(false, Ordering::Release);
            if curr.is_some() {
                return curr;
            }
        };
        self.cursor
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |val| {
                if val.is_null() {
                    // We have reached the end of the block
                    None
                } else if val.addr() == self.block.start().addr().get() {
                    // We are handing out the last element of the block
                    Some(core::ptr::null_mut())
                } else {
                    // There's more than one element remaining in the block
                    unsafe { Some(val.sub(1)) }
                }
            })
            .map(NonNull::new)
            .ok()?
    }

    /// Deallocates a pointer that has been allocated from the block.
    /// Passing a pointer to a different block will result in undefined behavior,
    /// since "freed" allocations are added to a list and reused for subsequent
    /// calls to alloc. The allocation does not need to be initialized; you can pass
    /// the result of `BlockAllocator::alloc` directly to this function.
    unsafe fn dealloc(&self, ptr: NonNull<MaybeUninit<T>>) {
        while self.free_lock.swap(true, Ordering::Acquire) {
            hint::spin_loop();
        }
        let curr = self.free_list.get();
        unsafe {
            let ptr = (*ptr.as_ptr()).as_mut_ptr();
            let ptr_next = (*ptr).next();
            *ptr_next = *curr;
            *self.free_list.get() = ptr;
        }
        self.free_lock.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;
    use std::thread;

    use super::*;
    use crate::hooks::DEFAULT_HOOKS;
    use crate::*;

    struct Link {
        link: UnsafeCell<*mut u8>,
    }

    unsafe impl Linkable<Link> for Link {
        fn next(&self) -> *mut *mut Link {
            unsafe { mem::transmute(self.link.get()) }
        }
    }

    #[test]
    fn allocate_from_page_in_parallel() {
        let ctx = unsafe { init_global_ctx(DEFAULT_HOOKS) };
        let block = Block::new(ctx.hooks(), unsafe { NonZero::new_unchecked(200) });

        let page = Arc::new(BlockAllocator::<Link>::new(block));
        let mut threads = Vec::new();

        for id in 0..10 {
            let page = page.clone();
            // Create 10 threads, which will each allocate and deallocate from the page
            threads.push(thread::spawn(move || {
                // Allocate 10 elements per thread.
                let mut allocs: Vec<_> = (0..10).map(|_| page.alloc().unwrap()).collect();
                if id % 2 == 0 {
                    // Even-numbered threads will immediately free the elements, adding them to the
                    // free list for odd-numbered threads to pick up.
                    for alloc in allocs.drain(..) {
                        unsafe {
                            page.dealloc(alloc);
                        }
                    }
                } else {
                    // Odd-numbered threads will continue to allocate elements,
                    // hopefully picking the allocations freed by even-numbered threads.
                    for _ in 0..10 {
                        if let Some(alloc) = page.alloc() {
                            unsafe {
                                (*alloc.as_ptr())
                                    .write(Link { link: UnsafeCell::new(core::ptr::null_mut()) });
                            }
                            allocs.push(alloc);
                        }
                        allocs.push(page.alloc().unwrap());
                    }
                    allocs.drain(..).for_each(|alloc| unsafe {
                        page.dealloc(alloc);
                    });
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }

        unsafe {
            deinit_global_ctx();
        }
    }
}
