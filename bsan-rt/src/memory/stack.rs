use core::marker::PhantomData;
use core::mem;
use core::num::NonZero;
use core::option::Iter;

use super::{align_down, align_up};
use crate::memory::hooks::{MMap, MUnmap};
use crate::memory::{
    allocation_size_overflow, round_up_to, unmap_failed, AllocResult, Chunk, InternalAllocKind,
    TYPICAL_PAGE_SIZE,
};
use crate::{ptr, Debug, GlobalCtx, NonNull};

static DEFAULT_CHUNK_SIZE: NonZero<usize> = TYPICAL_PAGE_SIZE;

#[derive(Debug)]
pub struct Stack<T: Sized> {
    chunk: StackChunk<T>,
    checkpoint: *mut Checkpoint<T>,
    mmap: MMap,
    munmap: MUnmap,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Checkpoint<T> {
    limit: NonNull<T>,
    prev_checkpoint: *mut Checkpoint<T>,
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct StackHeader {
    raw_chunk: Chunk,
    prev_header: Option<NonNull<StackHeader>>,
}

impl<T: Sized> Stack<T> {
    pub fn new(ctx: &GlobalCtx) -> AllocResult<Self> {
        let mmap = ctx.hooks().mmap_ptr;
        let munmap = ctx.hooks().munmap_ptr;
        let chunk = unsafe { StackChunk::<T>::new(mmap, None) }?;
        Ok(Self { chunk, checkpoint: ptr::null_mut(), mmap, munmap })
    }

    pub fn push_frame(&mut self) -> AllocResult<()> {
        let next_checkpoint = self.chunk.next::<Checkpoint<T>>(self.mmap)?;
        unsafe {
            next_checkpoint
                .write(Checkpoint { limit: self.chunk.limit, prev_checkpoint: self.checkpoint })
        };
        self.checkpoint = next_checkpoint.as_ptr();
        Ok(())
    }

    /// # Safety
    /// A frame needs to have been pushed.
    pub unsafe fn pop_frame(&mut self) {
        debug_assert!(!self.checkpoint.is_null());
        let slot = unsafe { NonNull::new_unchecked(self.checkpoint) };
        self.chunk.cursor = unsafe { align_up::<Checkpoint<T>, T>(slot.add(1)) };
        self.checkpoint = unsafe { slot.as_ref().prev_checkpoint };
        self.chunk.limit = unsafe { slot.as_ref().limit };
    }

    pub fn push(&mut self, elem: T) -> AllocResult<NonNull<T>> {
        let slot = self.chunk.next::<T>(self.mmap)?;
        unsafe { slot.write(elem) };
        Ok(slot)
    }
}

#[derive(Debug)]
struct StackChunk<T> {
    header: NonNull<StackHeader>,
    cursor: NonNull<T>,
    limit: NonNull<T>,
    data: PhantomData<*mut T>,
}

impl<T> StackChunk<T> {
    const OVERHEAD: NonZero<usize> =
        NonZero::new(mem::size_of::<StackHeader>() + mem::size_of::<Checkpoint<T>>()).unwrap();

    unsafe fn new(mmap_ptr: MMap, prev_header: Option<NonNull<StackHeader>>) -> AllocResult<Self> {
        let size = if let Some(prev_header) = prev_header {
            unsafe { prev_header.as_ref().raw_chunk.size }
        } else if mem::size_of::<T>() > DEFAULT_CHUNK_SIZE.get() {
            let minimum_size = Self::OVERHEAD
                .checked_add(mem::size_of::<T>())
                .unwrap_or_else(allocation_size_overflow);

            let next_page_multiple = round_up_to(minimum_size.get(), TYPICAL_PAGE_SIZE.get())
                .unwrap_or_else(allocation_size_overflow);

            // The result of rounding a non-zero number up to the nearest multiple of another non-zero
            // number will also be non-zero, unless we overflow, but that will cause a panic.
            unsafe { NonZero::new_unchecked(next_page_multiple) }
        } else {
            DEFAULT_CHUNK_SIZE
        };

        let raw_chunk = Chunk::new(mmap_ptr, size, InternalAllocKind::Stack)?;

        let header = unsafe {
            let high_end = raw_chunk.base_address.add(size.into());
            align_down::<u8, StackHeader>(high_end).sub(1)
        };

        let cursor = unsafe { align_down::<StackHeader, T>(header) };
        let limit = unsafe { align_up::<u8, T>(raw_chunk.base_address) };

        unsafe {
            header.write(StackHeader { raw_chunk, prev_header });
        }

        Ok(Self { header, cursor, limit, data: PhantomData })
    }

    fn next<B: Sized>(&mut self, mmap: MMap) -> AllocResult<NonNull<B>> {
        let capacity = self.cursor.as_ptr() as usize - self.limit.as_ptr() as usize;
        if size_of::<B>() > capacity {
            *self = unsafe { StackChunk::<T>::new(mmap, Some(self.header))? };
        }
        let next = unsafe { align_down::<T, B>(self.cursor).sub(1) };
        self.cursor = unsafe { align_down::<B, T>(next) };
        Ok(next)
    }
}

impl<T> Drop for Stack<T> {
    fn drop(&mut self) {
        let mut current_header = Some(unsafe { *self.chunk.header.as_ptr() });
        while let Some(header) = current_header {
            current_header = header.prev_header.map(|prev| unsafe { prev.read() });
            header
                .raw_chunk
                .dispose(self.munmap, InternalAllocKind::Stack)
                .unwrap_or_else(|_| unmap_failed());
        }
    }
}

#[cfg(test)]
mod test {
    use super::Stack;
    use crate::memory::hooks::DEFAULT_HOOKS;
    use crate::memory::AllocResult;
    use crate::*;

    fn test_info() -> AllocInfo {
        AllocInfo {
            alloc_id: AllocId::invalid(),
            base_addr: FreeListAddrUnion { base_addr: core::ptr::null_mut() },
            size: 0,
            tree_lock: Mutex::new(None),
        }
    }

    #[test]
    fn create_stack() {
        let global_ctx = unsafe { init_global_ctx(DEFAULT_HOOKS) };
        let _ = Stack::<AllocInfo>::new(global_ctx);
    }

    #[test]
    fn push_then_pop() -> AllocResult<()> {
        let global_ctx = unsafe { init_global_ctx(DEFAULT_HOOKS) };
        let mut prov = Stack::<AllocInfo>::new(global_ctx)?;
        unsafe {
            prov.push_frame()?;
            prov.push(test_info())?;
            prov.pop_frame();
        }
        Ok(())
    }

    #[test]
    fn smoke() -> AllocResult<()> {
        let global_ctx = unsafe { init_global_ctx(DEFAULT_HOOKS) };
        let mut prov = Stack::<AllocInfo>::new(global_ctx)?;
        prov.push_frame()?;
        for _ in 0..1000 {
            prov.push(test_info())?;
        }
        prov.push_frame()?;
        unsafe { prov.pop_frame() };
        prov.push_frame()?;
        for _ in 0..1000 {
            prov.push(test_info())?;
        }
        unsafe {
            prov.pop_frame();
            prov.pop_frame();
        }
        Ok(())
    }
}
