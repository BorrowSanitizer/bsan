use core::mem::{self, MaybeUninit};

use libc::MAP_GROWSDOWN;

use crate::block::{Block, BlockAllocator};
use crate::hooks::{BsanHooks, BSAN_MAP_FLAGS, BSAN_PROT_FLAGS};
use crate::{ptr, utils, Debug, GlobalCtx, NonNull};

/// The type of the counter tracking the number of elements for each frame.
type C = u32;

/// A bump allocator with support for handling frames of values.
/// When created, an initial empty frame is established. Elements can be pushed or popped from
/// an existing frame, or a new frame can be created with an initial allocation of elements.
/// Each frame contains an integer tracking the number of elements, allowing frames to be popped
/// without specifying a number of elements to pop. This abstraction supports situations where you have
/// a statically known lower bound on the number of allocations associated with a given stack frame, but not
/// an upper bound.
#[derive(Debug)]
pub struct Stack<T: Sized> {
    elems: Block<u8>,
    frame_top: NonNull<MaybeUninit<T>>,
    prev_frame_len_slot: *mut C,
    curr_frame_len: C,
}

impl<T> Stack<T> {
    pub fn new(ctx: &GlobalCtx) -> Self {
        let elems = Block::<u8>::new(ctx.hooks(), ctx.sizes.stack);

        // Safety:
        // We know that T is sized, and we assume that it's smaller than
        // the maximum stack size for a process.
        let frame_top = unsafe { elems.end().sub(mem::size_of::<T>()).cast::<MaybeUninit<T>>() };

        Self { elems, frame_top, prev_frame_len_slot: ptr::null_mut(), curr_frame_len: 0 }
    }

    #[inline]
    pub fn push_elems(&mut self, elems: usize) -> NonNull<MaybeUninit<T>> {
        let frame_top = self.frame_top;
        self.frame_top = unsafe { self.frame_top.sub(elems) };
        self.curr_frame_len += elems as u32;

        debug_assert!(self.frame_top.addr() > self.elems.first().addr());

        frame_top
    }

    /// # Safety
    /// The given number of elements must be present on the stack.
    #[inline]
    pub unsafe fn pop_elems(&mut self, elems: usize) {
        debug_assert!(self.frame_top.addr() < self.elems.end().addr());
        self.frame_top = unsafe { self.frame_top.add(elems) }
    }

    #[inline]
    pub fn push_frame(&mut self) -> NonNull<MaybeUninit<T>> {
        self.prev_frame_len_slot =
            unsafe { utils::align_down::<MaybeUninit<T>, C>(self.frame_top.add(1)) }.as_ptr();

        unsafe {
            *self.prev_frame_len_slot = self.curr_frame_len;
        }

        self.curr_frame_len = 0;

        self.frame_top = unsafe {
            debug_assert!(!self.prev_frame_len_slot.is_null());
            let prev_slot = NonNull::new_unchecked(self.prev_frame_len_slot);
            utils::align_down::<C, MaybeUninit<T>>(prev_slot)
        };

        self.frame_top
    }

    #[inline]
    pub fn push_frame_with(&mut self, elems: usize) -> NonNull<MaybeUninit<T>> {
        unsafe {
            self.push_frame();
            self.push_elems(elems)
        }
    }

    /// # Safety
    /// The given number of elements must be present on the stack, and a frame must have
    /// been pushed.
    #[inline]
    pub unsafe fn pop_frame(&mut self) {
        debug_assert!(!self.prev_frame_len_slot.is_null());
        debug_assert!(self.prev_frame_len_slot.is_aligned());

        let counter = unsafe { NonNull::new_unchecked(self.prev_frame_len_slot) };

        let frame_top = unsafe { utils::align_up::<C, T>(counter) };

        self.prev_frame_len_slot = unsafe {
            let ptr = frame_top.as_ptr();
            let ptr = ptr.add(*self.prev_frame_len_slot as usize);
            let ptr = NonNull::new_unchecked(ptr);
            utils::align_up::<T, C>(ptr).as_ptr()
        };

        self.curr_frame_len = unsafe { *self.prev_frame_len_slot };
    }
}

#[cfg(test)]
mod test {
    use crate::hooks::DEFAULT_HOOKS;
    use crate::stack::Stack;
    use crate::*;

    #[test]
    fn create_stack() {
        let global_ctx = unsafe { init_global_ctx(DEFAULT_HOOKS) };
        let _ = Stack::<Provenance>::new(global_ctx);
        let _ = Stack::<BorTag>::new(global_ctx);
    }

    #[test]
    fn mixed_dynamic_on_initial_frame() {
        let global_ctx = unsafe { init_global_ctx(DEFAULT_HOOKS) };
        let mut prov = Stack::<Provenance>::new(global_ctx);
        unsafe {
            prov.push_frame_with(3);
            prov.push_elems(2);

            prov.pop_elems(1);

            prov.push_frame_with(3);
            prov.push_elems(3);

            prov.pop_elems(3);
            prov.pop_frame();
            prov.pop_elems(1);
            prov.pop_frame();
        }
    }

    #[test]
    fn without_initial_frame() {
        let global_ctx = unsafe { init_global_ctx(DEFAULT_HOOKS) };
        let mut prov = Stack::<Provenance>::new(global_ctx);
        unsafe {
            prov.push_elems(2);

            prov.push_frame_with(3);

            assert!(prov.curr_frame_len == 3);

            prov.pop_frame();
        }
    }

    #[test]
    fn push_pop_frames_sequential() {
        let global_ctx = unsafe { init_global_ctx(DEFAULT_HOOKS) };
        let mut prov = Stack::<Provenance>::new(global_ctx);
        let mut tag = Stack::<BorTag>::new(global_ctx);

        let n_frames = 10;
        let n_elem: u32 = 2;

        for i in 0..n_frames {
            unsafe {
                prov.push_frame_with(n_elem as usize);
                tag.push_frame_with(n_elem as usize);
            }
            assert!(prov.curr_frame_len == n_elem);
            assert!(tag.curr_frame_len == n_elem);

            if i > 0 {
                unsafe {
                    assert!(*prov.prev_frame_len_slot == n_elem);
                    assert!(*tag.prev_frame_len_slot == n_elem);
                }
            }
        }
        for i in 0..n_frames {
            unsafe { prov.pop_frame() }
        }
    }
}
