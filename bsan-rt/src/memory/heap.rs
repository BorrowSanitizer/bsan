use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ops::DerefMut;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicUsize, Ordering};

use spin::mutex::SpinMutex;
use spin::rwlock::RwLock;

use super::hooks::{BsanHooks, MMap, MUnmap};
use super::{align_down, align_up, Block};
use crate::memory::{munmap, AllocResult, BlockSize, HasMinBlockSize, PAGE_SIZE};

/// # Safety
/// To be used in a `Heap<T>`, values of type `T` need to be able
/// to act as nodes in a linked list, meaning they need to be large
/// enough to store a pointer to another instance of `T`
pub unsafe trait Bumpable<T>: Sized {
    fn next(&mut self) -> *mut Option<NonNull<T>>;
}

#[derive(Debug)]
pub struct Heap<T: Bumpable<T>> {
    head: RwLock<BumpBlock<T>>,
    free_list: SpinMutex<Option<NonNull<T>>>,
    #[allow(unused)]
    grow_lock: AtomicU8,
    block_size: BlockSize<Heap<T>>,
    mmap: MMap,
    munmap: MUnmap,
}

unsafe impl<T: Bumpable<T>> Send for Heap<T> {}
unsafe impl<T: Bumpable<T>> Sync for Heap<T> {}

unsafe impl<T: Bumpable<T>> HasMinBlockSize<Heap<T>> for Heap<T> {
    type Header = BumpBlockHeader<T>;
    type Values = T;
}

impl<T: Bumpable<T>> Heap<T> {
    pub fn new(hooks: &BsanHooks) -> AllocResult<Self> {
        let mmap = hooks.mmap_ptr;
        let munmap = hooks.munmap_ptr;

        let head = unsafe { BumpBlock::<T>::new(mmap, PAGE_SIZE.into())? };
        let head = RwLock::new(head);

        Ok(Self {
            head,
            free_list: SpinMutex::new(None),
            grow_lock: AtomicU8::new(0),
            block_size: PAGE_SIZE.into(),
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
                let replacement = unsafe { BumpBlock::new(self.mmap, self.block_size)? };
                unsafe { &mut *replacement.header() }.next = Some(writer.header);
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

    fn parent_header(&self, ptr: NonNull<T>) -> &BumpBlockHeader<T> {
        let header = ptr.addr().get() & !(self.block_size.get() - 1);
        let header = header as *mut BumpBlockHeader<T>;
        debug_assert!(!header.is_null() && header.is_aligned());
        unsafe { &*header }
    }
}

impl<T: Bumpable<T>> Drop for Heap<T> {
    fn drop(&mut self) {
        let mut curr = Some(self.head.write().header);
        while let Some(header) = curr {
            let header = unsafe { &*header.as_ptr() };
            curr = header.next;
            unsafe {
                munmap::<u8>(self.munmap, header.base_address(), *self.block_size)
                    .expect("failed to unmap page")
            };
        }
    }
}

#[derive(Debug)]
pub struct BumpBlock<T: Sized> {
    header: NonNull<BumpBlockHeader<T>>,
    data: PhantomData<T>,
}

unsafe impl<T> Send for BumpBlock<T> {}
unsafe impl<T> Sync for BumpBlock<T> {}

impl<T: Bumpable<T>> BumpBlock<T> {
    unsafe fn new(mmap_ptr: MMap, size: BlockSize<Heap<T>>) -> AllocResult<Self> {
        let Block { mut header, limit } = Block::<Heap<T>>::new(mmap_ptr, size)?;
        let cursor = unsafe { align_down::<_, MaybeUninit<T>>(header).sub(1) };
        let cursor = AtomicPtr::new(cursor.as_ptr());
        let limit = unsafe { align_up::<_, MaybeUninit<T>>(limit) };
        unsafe {
            header.as_mut().write(BumpBlockHeader { cursor, limit, in_use: 0.into(), next: None });
        }
        Ok(Self { header: header.cast(), data: PhantomData })
    }

    #[inline]
    fn header(&self) -> *mut BumpBlockHeader<T> {
        self.header.as_ptr()
    }

    fn next(&self) -> Option<NonNull<MaybeUninit<T>>> {
        let header = unsafe { &*self.header() };
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
pub(crate) struct BumpBlockHeader<T> {
    cursor: AtomicPtr<MaybeUninit<T>>,
    limit: NonNull<MaybeUninit<T>>,
    in_use: AtomicUsize,
    next: Option<NonNull<BumpBlockHeader<T>>>,
}

impl<T> BumpBlockHeader<T> {
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

    unsafe impl Bumpable<Link> for Link {
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
