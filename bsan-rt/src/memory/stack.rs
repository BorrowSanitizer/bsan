use core::marker::PhantomData;
use core::mem::{self, MaybeUninit};
use core::num::NonZero;
use core::ops::Deref;

use libc::rlimit;

use crate::memory::hooks::{BsanHooks, MUnmap};
use crate::memory::{mmap, munmap, unmap_failed, AllocError, AllocResult, InternalAllocKind};
use crate::{ptr, Debug, NonNull};

#[derive(Debug, Copy, Clone)]
struct StackSize(NonZero<usize>);

impl Deref for StackSize {
    type Target = NonZero<usize>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl StackSize {
    fn try_new() -> AllocResult<Self> {
        let mut limits = MaybeUninit::<rlimit>::uninit();
        #[cfg(not(miri))]
        let exit_code = unsafe { libc::getrlimit(libc::RLIMIT_STACK, limits.as_mut_ptr()) };

        #[cfg(miri)]
        let exit_code = unsafe {
            (*limits.as_mut_ptr()).rlim_cur = 1024;
            (*limits.as_mut_ptr()).rlim_max = 1024;
            0
        };

        let stack_size_bytes = if exit_code != 0 {
            panic!("Failed to obtain stack size limit.");
        } else {
            let limits = unsafe { MaybeUninit::assume_init(limits) };
            limits.rlim_cur as usize
        };

        NonZero::try_from(stack_size_bytes).map(Self).map_err(|_| AllocError::InvalidStackSize)
    }
}

/// Types that can be allocated via a `Stack`.
///
/// # Safety
/// `Stackable` types must be word-aligned.
pub unsafe trait Stackable: Sized {
    fn is_stackable() -> bool {
        mem::align_of::<Self>() == mem::align_of::<usize>()
    }
}

#[repr(align(8))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Checkpoint {
    prev_checkpoint: *mut Checkpoint,
}

unsafe impl Stackable for Checkpoint {}

#[derive(Debug)]
pub struct Stack<T: Stackable> {
    cursor: NonNull<usize>,
    limit: NonNull<usize>,
    size: StackSize,
    checkpoint: *mut Checkpoint,
    munmap_ptr: MUnmap,
    data: PhantomData<*mut T>,
}

impl<T: Stackable> Stack<T> {
    pub fn new(hooks: BsanHooks) -> AllocResult<Self> {
        assert!(T::is_stackable());

        let munmap_ptr = hooks.munmap_ptr;

        let size = StackSize::try_new()?;

        let limit = unsafe { mmap(hooks.mmap_ptr, InternalAllocKind::Stack, *size)? };
        debug_assert!(limit.is_aligned());

        let cursor = unsafe { limit.byte_add((*size).into()) };
        debug_assert!(cursor.is_aligned());

        let mut stack = Self {
            cursor,
            limit,
            size,
            munmap_ptr,
            checkpoint: ptr::null_mut(),
            data: PhantomData,
        };
        stack.push_frame()?;
        Ok(stack)
    }

    fn next<B: Stackable>(&mut self) -> AllocResult<NonNull<B>> {
        self.extend(1)
    }

    fn extend<B: Stackable>(&mut self, num_elems: usize) -> AllocResult<NonNull<B>> {
        debug_assert!(B::is_stackable());
        let capacity = self.cursor.as_ptr() as usize - self.limit.as_ptr() as usize;
        if (size_of::<B>() * num_elems) > capacity {
            Err(AllocError::StackOverflow)
        } else {
            let next = unsafe { self.cursor.cast::<B>().sub(num_elems) };
            self.cursor = next.cast::<usize>();
            Ok(next)
        }
    }

    pub fn push_frame(&mut self) -> AllocResult<()> {
        let next_checkpoint = self.next::<Checkpoint>()?;
        unsafe { next_checkpoint.write(Checkpoint { prev_checkpoint: self.checkpoint }) };
        self.checkpoint = next_checkpoint.as_ptr();
        Ok(())
    }

    pub fn push_frame_with(&mut self, num_elems: usize) -> AllocResult<NonNull<T>> {
        self.push_frame()?;
        self.reserve_slots(num_elems)
    }

    /// # Safety
    /// A frame needs to have been pushed.
    pub unsafe fn pop_frame(&mut self) {
        debug_assert!(!self.checkpoint.is_null());
        let slot = unsafe { NonNull::new_unchecked(self.checkpoint) };
        self.cursor = unsafe { slot.add(1).cast::<usize>() };
        self.checkpoint = unsafe { slot.as_ref().prev_checkpoint };
    }

    pub fn push(&mut self, elem: T) -> AllocResult<NonNull<T>> {
        let slot = self.next::<T>()?;
        unsafe { slot.write(elem) };
        Ok(slot)
    }

    pub fn reserve_slots(&mut self, num_elems: usize) -> AllocResult<NonNull<T>> {
        self.extend::<T>(num_elems)
    }

    pub(crate) fn frame_len(&self) -> usize {
        let cursor = self.cursor.cast::<T>().as_ptr();
        let checkpoint = self.checkpoint.cast::<T>();
        unsafe { checkpoint.offset_from_unsigned(cursor) }
    }

    pub fn current_frame(&self) -> &[T] {
        let cursor = self.cursor.cast::<T>();
        unsafe { core::slice::from_raw_parts(cursor.as_ptr(), self.frame_len()) }
    }

    pub fn current_frame_mut(&self) -> &mut [T] {
        let cursor = self.cursor.cast::<T>();
        unsafe { core::slice::from_raw_parts_mut(cursor.as_ptr(), self.frame_len()) }
    }
}

impl<T: Stackable> Drop for Stack<T> {
    fn drop(&mut self) {
        unsafe {
            munmap(self.munmap_ptr, InternalAllocKind::Stack, self.limit, *self.size)
                .unwrap_or_else(|_| unmap_failed())
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Stack, StackSize};
    use crate::memory::hooks::DEFAULT_HOOKS;
    use crate::memory::stack::{Checkpoint, Stackable};
    use crate::memory::AllocResult;
    use crate::*;

    fn test_info(size: usize) -> AllocInfo {
        AllocInfo {
            alloc_id: AllocId::invalid(),
            base_addr: FreeListAddrUnion { base_addr: core::ptr::null_mut() },
            size,
            tree_lock: Mutex::new(None),
        }
    }

    #[test]
    fn create_stack_size() -> AllocResult<()> {
        assert!(StackSize::try_new()?.get() > 0);
        Ok(())
    }

    #[test]
    fn create_stack() -> AllocResult<()> {
        let _ = Stack::<AllocInfo>::new(DEFAULT_HOOKS)?;
        Ok(())
    }

    #[test]
    fn empty_frame() -> AllocResult<()> {
        let stack = Stack::<AllocInfo>::new(DEFAULT_HOOKS)?;
        assert_eq!(stack.frame_len(), 0);
        Ok(())
    }

    #[test]
    fn push_then_pop() -> AllocResult<()> {
        let mut prov = Stack::<AllocInfo>::new(DEFAULT_HOOKS)?;
        unsafe {
            prov.push_frame()?;
            prov.push(test_info(0))?;
            prov.pop_frame();
        }
        Ok(())
    }

    #[test]
    fn push_without_frame() -> AllocResult<()> {
        let mut prov = Stack::<AllocInfo>::new(DEFAULT_HOOKS)?;
        prov.push(test_info(5))?;
        let frame = prov.current_frame();
        assert_eq!(frame.len(), 1);
        assert_eq!(frame[0].size, 5);
        Ok(())
    }

    #[test]
    fn read_frame_contents() -> AllocResult<()> {
        let mut prov = Stack::<AllocInfo>::new(DEFAULT_HOOKS)?;
        prov.push_frame()?;

        for i in 0..10 {
            prov.push(test_info(i))?;
        }

        assert_eq!(prov.frame_len(), 10);

        unsafe { prov.pop_frame() };

        assert_eq!(prov.frame_len(), 0);

        prov.push_frame()?;

        for i in 10..20 {
            prov.push(test_info(i))?;
        }

        let frame = prov.current_frame();
        assert_eq!(frame.len(), 10);
        for (i, info) in frame.iter().enumerate() {
            crate::println!("{i:?}");
            assert_eq!(info.size, 19 - i);
        }

        unsafe { prov.pop_frame() };
        Ok(())
    }

    #[test]
    #[cfg(not(miri))]
    fn smoke() -> AllocResult<()> {
        let mut prov = Stack::<AllocInfo>::new(DEFAULT_HOOKS)?;
        prov.push_frame()?;
        for _ in 0..1000 {
            prov.push(test_info(0))?;
        }
        prov.push_frame()?;
        unsafe { prov.pop_frame() };
        prov.push_frame()?;
        for _ in 0..1000 {
            prov.push(test_info(0))?;
        }
        unsafe {
            prov.pop_frame();
            prov.pop_frame();
        }
        Ok(())
    }

    #[test]
    fn stackable_alloc_info() {
        assert!(AllocInfo::is_stackable());
    }

    #[test]
    fn stackable_bor_tag() {
        assert!(BorTag::is_stackable());
    }

    #[test]
    fn stackable_checkpoint() {
        assert!(Checkpoint::is_stackable());
    }
}
