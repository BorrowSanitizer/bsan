use core::mem::MaybeUninit;
use core::option::Iter;

use super::hooks::{MMap, MUnmap};
use super::{align_down, align_up, Block};
use crate::memory::{munmap, AllocResult, BlockSize, HasMinBlockSize, PAGE_SIZE};
use crate::{ptr, Debug, GlobalCtx, NonNull};

#[derive(Debug)]
pub struct Stack<T: Sized> {
    /// A pointer to the last element that was allocated.
    cursor: NonNull<MaybeUninit<T>>,
    /// The last element that can be allocated in the current block.
    limit: NonNull<MaybeUninit<T>>,
    /// The size of a block
    block_size: BlockSize<Stack<T>>,
    /// The pointer to the previous frame, which can span blocks.
    checkpoint: *mut Checkpoint<T>,
    /// The pointer to the previous block
    header: NonNull<StackHeader>,
    mmap: MMap,
    munmap: MUnmap,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Checkpoint<T> {
    limit: NonNull<MaybeUninit<T>>,
    prev_checkpoint: *mut Checkpoint<T>,
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct StackHeader {
    limit: NonNull<MaybeUninit<u8>>,
    prev_header: Option<NonNull<StackHeader>>,
}

unsafe impl<T> HasMinBlockSize<Stack<T>> for Stack<T> {
    type Header = StackHeader;
    type Values = (T, Checkpoint<T>);
}

impl<T: Sized> Stack<T> {
    pub fn new(ctx: &GlobalCtx) -> AllocResult<Self> {
        let mmap = ctx.hooks().mmap_ptr;
        let munmap = ctx.hooks().munmap_ptr;

        let block_size: BlockSize<Stack<T>> = PAGE_SIZE.into();

        let Block { limit, mut header } = Block::<Self>::new(mmap, block_size)?;

        unsafe { header.as_mut().write(StackHeader { limit, prev_header: None }) };
        let header = header.cast::<StackHeader>();

        let cursor = unsafe { align_down::<StackHeader, MaybeUninit<T>>(header) };
        let limit = unsafe { align_up::<MaybeUninit<u8>, MaybeUninit<T>>(limit) };

        Ok(Self { block_size, cursor, limit, header, checkpoint: ptr::null_mut(), mmap, munmap })
    }

    /// Allocates space to push another element onto the stack. Used for both elements and frame pointers.
    fn next<B: Sized>(&mut self) -> AllocResult<NonNull<B>> {
        let capacity = self.cursor.as_ptr() as usize - self.limit.as_ptr() as usize;
        if size_of::<B>() > capacity {
            let Block { limit, mut header } = Block::<Self>::new(self.mmap, self.block_size)?;

            unsafe {
                header.as_mut().write(StackHeader { limit, prev_header: Some(self.header) });
            }
            self.header = header.cast::<StackHeader>();

            self.limit = unsafe { align_up::<MaybeUninit<u8>, MaybeUninit<T>>(limit) };
            self.cursor = unsafe { align_down::<StackHeader, MaybeUninit<T>>(self.header) };
        }
        let next = unsafe { align_down::<MaybeUninit<T>, B>(self.cursor).sub(1) };
        self.cursor = unsafe { align_down::<B, MaybeUninit<T>>(next) };
        Ok(next)
    }

    /// Starts a new stack frame of elements, pushing a pointer to the start of the previous frame.
    pub fn push_frame(&mut self) -> AllocResult<()> {
        let next_checkpoint = self.next::<Checkpoint<T>>()?;
        unsafe {
            next_checkpoint
                .write(Checkpoint { limit: self.limit, prev_checkpoint: self.checkpoint })
        };
        self.checkpoint = next_checkpoint.as_ptr();
        Ok(())
    }

    /// Pushes an element onto the stack.
    pub fn push(&mut self, elem: T) -> AllocResult<()> {
        let mut slot = self.next::<MaybeUninit<T>>()?;
        unsafe { slot.as_mut().write(elem) };
        Ok(())
    }

    /// # Safety
    /// A frame must have been pushed.
    pub unsafe fn pop_frame(&mut self) {
        debug_assert!(!self.checkpoint.is_null());
        let slot = unsafe { NonNull::new_unchecked(self.checkpoint) };
        self.cursor = unsafe { align_up::<Checkpoint<T>, MaybeUninit<T>>(slot.add(1)) };
        self.checkpoint = unsafe { slot.as_ref().prev_checkpoint };
        self.limit = unsafe { slot.as_ref().limit };
    }

    pub fn current_frame<'a>(&'a self) -> Iter<'a, T> {
        todo!()
    }
}

impl<T> Drop for Stack<T> {
    fn drop(&mut self) {
        let mut current_header = Some(unsafe { *self.header.as_ptr() });
        while let Some(header) = current_header {
            unsafe {
                munmap(self.munmap, header.limit, *self.block_size).expect("failed to unmap block")
            }
            current_header = header.prev_header.map(|h| unsafe { *h.as_ptr() })
        }
    }
}

#[cfg(test)]
mod test {
    use super::Stack;
    use crate::memory::hooks::DEFAULT_HOOKS;
    use crate::memory::AllocResult;
    use crate::*;

    #[test]
    fn create_stack() {
        let global_ctx = unsafe { init_global_ctx(DEFAULT_HOOKS) };
        let _ = Stack::<Provenance>::new(global_ctx);
        let _ = Stack::<BorTag>::new(global_ctx);
    }

    #[test]
    fn push_then_pop() -> AllocResult<()> {
        let global_ctx = unsafe { init_global_ctx(DEFAULT_HOOKS) };
        let mut prov = Stack::<Provenance>::new(global_ctx)?;
        unsafe {
            prov.push_frame()?;
            prov.push(__BSAN_NULL_PROVENANCE)?;
            prov.pop_frame();
        }
        Ok(())
    }

    #[test]
    fn smoke() -> AllocResult<()> {
        let global_ctx = unsafe { init_global_ctx(DEFAULT_HOOKS) };
        let mut prov = Stack::<Provenance>::new(global_ctx)?;
        prov.push_frame()?;

        for _ in 0..1000 {
            prov.push(__BSAN_NULL_PROVENANCE)?;
        }
        Ok(())
    }
}
