use core::mem;
use core::num::NonZero;
use core::ops::DerefMut;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicUsize, Ordering};

use spin::mutex::SpinMutex;
use spin::rwlock::RwLock;

use super::hooks::{BsanHooks, MMap, MUnmap};
use super::{align_down, align_up, Chunk};
use crate::memory::{
    munmap, round_mut_ptr_up_to_unchecked, unmap_failed, AllocResult, InternalAllocKind,
    TYPICAL_PAGE_SIZE,
};

/// # Safety
/// To be used in a `Heap<T>`, values of type `T` need to be smaller
/// than the `HEAP_CHUNK_SIZE` minus the size of a `HeapBlockHeader<T>`,
/// but large enough to store a pointer to another instance of `T`.
pub unsafe trait Heapable<T>: Sized {
    fn next(&mut self) -> *mut Option<NonNull<T>>;
}

const HEAP_CHUNK_SIZE: NonZero<usize> = TYPICAL_PAGE_SIZE;

#[derive(Debug)]
pub struct Heap<T: Heapable<T>> {
    head: RwLock<HeapBlock<T>>,
    free_list: SpinMutex<Option<NonNull<T>>>,
    #[allow(unused)]
    grow_lock: AtomicU8,
    mmap: MMap,
    munmap: MUnmap,
}

unsafe impl<T: Heapable<T>> Send for Heap<T> {}
unsafe impl<T: Heapable<T>> Sync for Heap<T> {}

impl<T: Heapable<T>> Heap<T> {
    pub fn new(hooks: &BsanHooks) -> AllocResult<Self> {
        let mmap = hooks.mmap_ptr;
        let munmap = hooks.munmap_ptr;

        let head = unsafe { HeapBlock::<T>::new(mmap)? };
        let head = RwLock::new(head);

        Ok(Self {
            head,
            free_list: SpinMutex::new(None),
            grow_lock: AtomicU8::new(0),
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
                let mut replacement = unsafe { HeapBlock::new(self.mmap)? };
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
            round_mut_ptr_up_to_unchecked(ptr.as_ptr().cast::<u8>(), HEAP_CHUNK_SIZE.get())
        };
        let header = unsafe { high_end.cast::<HeapBlockHeader<T>>().sub(1) };
        debug_assert!(!header.is_null() && header.is_aligned());
        unsafe { &*header }
    }
}

impl<T: Heapable<T>> Drop for Heap<T> {
    fn drop(&mut self) {
        let mut curr = Some(self.head.write().header);
        while let Some(header) = curr {
            let header = unsafe { &*header.as_ptr() };
            curr = header.next;

            unsafe {
                munmap(self.munmap, InternalAllocKind::Heap, header.base_address(), header.size)
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

impl<T: Heapable<T>> HeapBlock<T> {
    unsafe fn new(mmap_ptr: MMap) -> AllocResult<Self> {
        debug_assert!(
            mem::size_of::<T>() < (HEAP_CHUNK_SIZE.get() - mem::size_of::<HeapBlockHeader<T>>())
        );

        let Chunk { base_address, size } =
            Chunk::new(mmap_ptr, HEAP_CHUNK_SIZE, InternalAllocKind::Heap)?;

        let header = unsafe {
            let high_end = base_address.add(size.get());
            align_down::<u8, HeapBlockHeader<T>>(high_end).sub(1)
        };

        let cursor = unsafe { align_down::<HeapBlockHeader<T>, T>(header).sub(1) };
        let cursor = AtomicPtr::new(cursor.as_ptr());

        let limit = unsafe { align_up::<u8, T>(base_address) };

        unsafe {
            header.write(HeapBlockHeader { cursor, limit, size, in_use: 0.into(), next: None });
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

#[derive(Debug)]
pub(crate) struct HeapBlockHeader<T> {
    cursor: AtomicPtr<T>,
    limit: NonNull<T>,
    in_use: AtomicUsize,
    size: NonZero<usize>,
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
        unsafe { super::align_down::<_, u8>(self.limit) }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;
    use std::thread;

    use super::*;
    use crate::memory::hooks::DEFAULT_HOOKS;
    use crate::memory::{AllocError, AllocResult};

    #[derive(Default)]
    struct Link {
        next: usize,
    }

    unsafe impl Heapable<Link> for Link {
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
}
