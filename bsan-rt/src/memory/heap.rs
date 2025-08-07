use core::mem;
use core::num::NonZero;
use core::ops::DerefMut;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicUsize, Ordering};

use libc::_SC_PAGESIZE;
use spin::mutex::SpinMutex;
use spin::rwlock::RwLock;

use super::hooks::{BsanHooks, MMap, MUnmap};
use crate::memory::{
    mmap, munmap, round_mut_ptr_up_to_unchecked, unmap_failed, AllocError, AllocResult,
    InternalAllocKind, WordAligned,
};

#[allow(unused)]
#[derive(Debug, Copy, Clone)]
struct PageSize;

#[allow(unused)]
impl PageSize {
    fn try_new() -> AllocResult<NonZero<usize>> {
        let page_size = unsafe { libc::sysconf(_SC_PAGESIZE) };
        NonZero::new(page_size as usize).ok_or(AllocError::InvalidPageSize)
    }
}

/// An object that can be allocated by a `Heap`.
///
/// # Safety
/// A `Heapable` type must be `Sized` and smaller
/// than the `PAGE_SIZE` minus the size of a `HeapBlockHeader<T>`,
/// but large enough to store a pointer to another `Heapable` instance.
/// This allows values to act as nodes in a free list.
pub(crate) unsafe trait Heapable: WordAligned {
    fn next(&mut self) -> *mut Option<NonNull<Self>>;

    #[allow(unused)]
    fn is_heapable() -> AllocResult<bool> {
        let block_size = PageSize::try_new()?;
        let overhead = mem::size_of::<HeapBlockHeader<Self>>();
        let within_capacity = block_size
            .get()
            .checked_sub(overhead)
            .map(|capacity| capacity - mem::size_of::<Self>() > 0)
            .unwrap_or(false);

        Ok(within_capacity)
    }
}

#[derive(Debug)]
pub struct Heap<T: Heapable> {
    head: RwLock<HeapBlock<T>>,
    free_list: SpinMutex<Option<NonNull<T>>>,
    #[allow(unused)]
    grow_lock: AtomicU8,
    block_size: NonZero<usize>,
    mmap: MMap,
    munmap: MUnmap,
}

unsafe impl<T: Heapable> Send for Heap<T> {}
unsafe impl<T: Heapable> Sync for Heap<T> {}

impl<T: Heapable> Heap<T> {
    pub fn new(hooks: &BsanHooks) -> AllocResult<Self> {
        let mmap = hooks.mmap_ptr;
        let munmap = hooks.munmap_ptr;

        let block_size = PageSize::try_new()?;

        let head = unsafe { HeapBlock::<T>::new(mmap, block_size)? };
        let head = RwLock::new(head);

        Ok(Self {
            head,
            free_list: SpinMutex::new(None),
            grow_lock: AtomicU8::new(0),
            block_size,
            mmap,
            munmap,
        })
    }

    pub fn alloc(&self, elem: T) -> AllocResult<NonNull<T>> {
        if let Some(mut free_list) = self.free_list.try_lock()
            && let Some(head) = *free_list
        {
            let header = self.parent_header(head);
            header.increment_used();

            let next = unsafe { (*head.as_ptr()).next() };
            *free_list = unsafe { *next };

            let head = head.cast::<T>();
            unsafe { head.write(elem) };
            return Ok(head);
        }
        loop {
            let bump_reader = self.head.upgradeable_read();
            if let Some(alloc) = bump_reader.next() {
                let alloc = alloc.cast::<T>();
                unsafe { alloc.write(elem) };
                return Ok(alloc);
            }
            if let Ok(mut bump_writer) = bump_reader.try_upgrade() {
                let writer = bump_writer.deref_mut();
                let mut replacement = unsafe { HeapBlock::new(self.mmap, self.block_size)? };
                let replacement_header = unsafe { replacement.header.as_mut() };
                replacement_header.next = Some(writer.header);
                *writer = replacement;
            }
        }
    }

    pub unsafe fn dealloc(&self, ptr: NonNull<T>) {
        let mut free_list = self.free_list.lock();
        let header = self.parent_header(ptr);
        header.decrement_used();
        unsafe {
            let ptr_next = (*ptr.as_ptr()).next();
            *ptr_next = *free_list;
            *free_list = Some(ptr);
        }
    }

    fn parent_header(&self, ptr: NonNull<T>) -> &HeapBlockHeader<T> {
        let high_end = unsafe {
            round_mut_ptr_up_to_unchecked(ptr.cast::<u8>().as_ptr(), self.block_size.get())
        };
        let header = unsafe { high_end.cast::<HeapBlockHeader<T>>().sub(1) };
        debug_assert!(!header.is_null() && header.is_aligned());
        unsafe { &*header }
    }
}

impl<T: Heapable> Drop for Heap<T> {
    fn drop(&mut self) {
        let mut curr = Some(self.head.write().header);
        while let Some(header) = curr {
            let header = unsafe { &*header.as_ptr() };
            curr = header.next;
            unsafe {
                munmap(
                    self.munmap,
                    InternalAllocKind::Heap,
                    header.base_address(),
                    header.block_size,
                )
                .unwrap_or_else(|_| unmap_failed())
            };
        }
    }
}

#[derive(Debug)]
pub struct HeapBlock<T: Sized> {
    header: NonNull<HeapBlockHeader<T>>,
}

unsafe impl<T> Send for HeapBlock<T> {}
unsafe impl<T> Sync for HeapBlock<T> {}

impl<T: Heapable> HeapBlock<T> {
    unsafe fn new(mmap_ptr: MMap, block_size: NonZero<usize>) -> AllocResult<Self> {
        let limit = unsafe { mmap(mmap_ptr, InternalAllocKind::Heap, block_size)? };

        let header = unsafe {
            let high_end = limit.byte_add(block_size.get());
            high_end.cast::<HeapBlockHeader<T>>().sub(1)
        };

        let cursor = unsafe { header.cast::<T>().sub(1) };
        let cursor = AtomicPtr::new(cursor.as_ptr());

        unsafe {
            header.write(HeapBlockHeader {
                cursor,
                limit,
                block_size,
                in_use: 0.into(),
                next: None,
            });
        }
        Ok(Self { header })
    }

    fn next(&self) -> Option<NonNull<T>> {
        let header = unsafe { self.header.as_ref() };
        header
            .cursor
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |val| {
                if val.addr() > header.limit.addr().into() {
                    header.increment_used();
                    // There's more than one element remaining in the block
                    unsafe { Some(val.sub(1)) }
                } else {
                    None
                }
            })
            .ok()
            .map(|val| unsafe { NonNull::new_unchecked(val) })
    }
}

#[repr(align(8))]
#[derive(Debug)]
pub(crate) struct HeapBlockHeader<T> {
    cursor: AtomicPtr<T>,
    limit: NonNull<u8>,
    in_use: AtomicUsize,
    block_size: NonZero<usize>,
    next: Option<NonNull<HeapBlockHeader<T>>>,
}

impl<T> HeapBlockHeader<T> {
    fn increment_used(&self) {
        self.in_use.fetch_add(1, Ordering::Relaxed);
    }

    fn decrement_used(&self) {
        self.in_use.fetch_sub(1, Ordering::Relaxed);
    }

    fn base_address(&self) -> NonNull<u8> {
        self.limit
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;
    use std::thread;

    use super::*;
    use crate::memory::hooks::DEFAULT_HOOKS;
    use crate::memory::{AllocError, AllocResult};
    use crate::AllocInfo;

    #[repr(align(8))]
    #[derive(Default)]
    struct Link {
        next: usize,
    }

    unsafe impl WordAligned for Link {}

    unsafe impl Heapable for Link {
        fn next(&mut self) -> *mut Option<NonNull<Link>> {
            (&raw mut self.next).cast::<Option<NonNull<Link>>>()
        }
    }

    #[test]
    fn alloc_roundtrip() -> AllocResult<()> {
        let allocator = Heap::<Link>::new(&DEFAULT_HOOKS)?;
        unsafe { allocator.dealloc(allocator.alloc(Link { next: 0 })?) }
        Ok(())
    }

    #[test]
    fn allocate_from_page_in_parallel() -> AllocResult<()> {
        let allocator = Arc::new(Heap::<Link>::new(&DEFAULT_HOOKS)?);
        let mut threads: Vec<thread::JoinHandle<Result<(), _>>> = Vec::new();

        for id in 0..10 {
            let page = allocator.clone();
            // Create 10 threads, which will each allocate and deallocate from the page
            threads.push(thread::spawn(move || {
                // Allocate 10 elements per thread.
                let mut allocs: Vec<NonNull<Link>> = (0..10)
                    .map(|_| page.alloc(Link { next: 0 }))
                    .collect::<AllocResult<Vec<_>>>()?;

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
                        allocs.push(page.alloc(Link { next: 0 })?);
                    }
                    allocs.drain(..).for_each(|alloc| unsafe {
                        page.dealloc(alloc);
                    });
                }
                Ok::<(), AllocError>(())
            }));
        }

        for thread in threads {
            let _ = thread.join().unwrap();
        }
        Ok(())
    }

    #[test]
    fn heapable_alloc_info() -> AllocResult<()> {
        assert!(AllocInfo::is_heapable()?);
        Ok(())
    }
}
