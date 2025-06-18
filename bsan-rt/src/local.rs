use core::mem::{self, MaybeUninit};

use crate::block::{Block, BlockAllocator};
use crate::*;

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
pub struct Stack<T> {
    elems: Block<T>,
    frame_top: NonNull<T>,
    prev_frame_len_slot: *mut C,
    curr_frame_len: C,
}

impl<T> Stack<T> {
    pub fn new(ctx: &GlobalCtx, element_count: NonZero<usize>) -> Self {
        let elems: Block<T> = ctx.hooks().new_block(element_count);
        let counter_index: usize =
            (mem::size_of::<T>() * elems.num_elements.get()) - (mem::size_of::<C>());

        // Safety:
        // The block must contain at least one element.
        let frame_top: NonNull<T> = unsafe { elems.base.add(elems.num_elements.get() - 1) };

        Self { elems, frame_top, prev_frame_len_slot: ptr::null_mut(), curr_frame_len: 0 }
    }

    /// # Safety
    /// The stack allocation must be large enough to contain the additional elements.
    pub unsafe fn push_elems(&mut self, elems: usize) -> NonNull<T> {
        let frame_top = self.frame_top;
        self.frame_top = unsafe { self.frame_top.sub(elems) };
        self.curr_frame_len += elems as u32;
        debug_assert!(self.frame_top >= self.elems.base);
        frame_top
    }

    /// # Safety
    /// The given number of elements must be present on the stack.
    pub unsafe fn pop_elems(&mut self, elems: usize) {
        self.frame_top = unsafe { self.frame_top.add(elems) }
    }

    /// # Safety
    /// The stack allocation must be large enough to contain the additional elements.
    pub unsafe fn push_frame(&mut self, elems: usize) -> NonNull<T> {
        self.prev_frame_len_slot =
            unsafe { utils::align_down::<T, C>(self.frame_top.add(1)) }.as_ptr();

        unsafe {
            *self.prev_frame_len_slot = self.curr_frame_len;
        }

        self.curr_frame_len = 0;

        self.frame_top = unsafe {
            debug_assert!(!self.prev_frame_len_slot.is_null());
            let prev_slot = NonNull::new_unchecked(self.prev_frame_len_slot);
            utils::align_down::<C, T>(prev_slot)
        };

        unsafe { self.push_elems(elems) }
    }

    /// # Safety
    /// The given number of elements must be present on the stack, and a frame must have
    /// been pushed.
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

#[derive(Debug)]
pub struct LocalCtx {
    pub thread_id: ThreadId,
    provenance: Stack<Provenance>,
    protected_tags: Stack<BorTag>,
}
impl LocalCtx {
    pub fn new(ctx: &GlobalCtx) -> Self {
        let thread_id = ctx.new_thread_id();
        let provenance = Stack::<Provenance>::new(ctx, ctx.counts.provenance);
        let protected_tags = Stack::<BorTag>::new(ctx, ctx.counts.borrow_tag);

        Self { thread_id, provenance, protected_tags }
    }
}

#[thread_local]
pub static LOCAL_CTX: UnsafeCell<MaybeUninit<LocalCtx>> = UnsafeCell::new(MaybeUninit::uninit());

/// Initializes the local context object.
///
/// # Safety
///
/// This function should only be called once, when a thread is initialized.
#[inline]
pub unsafe fn init_local_ctx(ctx: &GlobalCtx) -> &LocalCtx {
    unsafe {
        (*LOCAL_CTX.get()).write(LocalCtx::new(ctx));
        local_ctx_mut()
    }
}

/// Deinitializes the local context object.
///
/// # Safety
///
/// This function must only be called once: when a thread is terminating.
/// It is marked as `unsafe`, since multiple other API functions rely
/// on the assumption that the current thread remains initialized.
#[inline]
pub unsafe fn deinit_local_ctx() {
    let ctx = unsafe { ptr::replace(LOCAL_CTX.get(), MaybeUninit::uninit()).assume_init() };
}

/// # Safety
/// The user needs to ensure that the context is initialized.
#[inline]
pub unsafe fn local_ctx<'a>() -> &'a LocalCtx {
    let ctx = LOCAL_CTX.get();
    unsafe { &*local_ctx_mut() }
}

/// # Safety
/// The user needs to ensure that the context is initialized.
#[inline]
pub unsafe fn local_ctx_mut<'a>() -> &'a mut LocalCtx {
    let ctx = LOCAL_CTX.get();
    unsafe { &mut *mem::transmute::<*mut MaybeUninit<LocalCtx>, *mut LocalCtx>(ctx) }
}

impl Drop for LocalCtx {
    fn drop(&mut self) {}
}

#[cfg(test)]
mod test {
    use crate::hooks::DEFAULT_HOOKS;
    use crate::*;

    #[test]
    fn create_stack() {
        let global_ctx = unsafe { init_global_ctx(DEFAULT_HOOKS) };
        let _ = Stack::<Provenance>::new(global_ctx, global_ctx.counts.provenance);
        let _ = Stack::<BorTag>::new(global_ctx, global_ctx.counts.provenance);
    }

    #[test]
    fn mixed_dynamic_on_initial_frame() {
        let global_ctx = unsafe { init_global_ctx(DEFAULT_HOOKS) };
        let mut prov = Stack::<Provenance>::new(global_ctx, global_ctx.counts.provenance);
        unsafe {
            prov.push_frame(1);
            prov.push_elems(2);

            prov.pop_elems(1);

            prov.push_frame(3);
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
        let mut prov = Stack::<Provenance>::new(global_ctx, global_ctx.counts.provenance);
        unsafe {
            prov.push_elems(2);

            prov.push_frame(3);

            assert!(prov.curr_frame_len == 3);

            prov.pop_frame();
        }
    }

    #[test]
    fn push_pop_frames_sequential() {
        let global_ctx = unsafe { init_global_ctx(DEFAULT_HOOKS) };
        let mut prov = Stack::<Provenance>::new(global_ctx, global_ctx.counts.provenance);
        let mut tag = Stack::<BorTag>::new(global_ctx, global_ctx.counts.provenance);

        let n_frames = 10;
        let n_elem: u32 = 2;

        for i in 0..n_frames {
            unsafe {
                prov.push_frame(n_elem as usize);
                tag.push_frame(n_elem as usize);
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
