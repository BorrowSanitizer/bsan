use core::mem::{self, MaybeUninit};

use crate::block::{Block, BlockAllocator};
use crate::*;

type C = u32;

#[derive(Debug)]
pub struct Stack<T> {
    elems: Block<T>,
    frame_top: NonNull<T>,
    prev_frame_len_slot: *mut u32,
    curr_frame_len: u32,
}

/// # Safety
/// The pointer must be offset from the beginning of its allocation
/// by at least `mem::size_of::<B>()` bytes.
#[inline(always)]
unsafe fn align_down<A, B>(ptr: NonNull<A>) -> NonNull<B> {
    debug_assert!(ptr.as_ptr().is_aligned());
    unsafe {
        let ptr = mem::transmute::<*mut A, *mut u8>(ptr.as_ptr());

        // round down to nearest aligned address
        let addr = ptr.expose_provenance();
        let addr = (addr & !(mem::align_of::<B>() - 1));
        let ptr = ptr::with_exposed_provenance_mut(addr);

        let ptr = mem::transmute::<*mut u8, *mut B>(ptr);
        let ptr = ptr.sub(1);

        debug_assert!(ptr.is_aligned());
        NonNull::<B>::new_unchecked(ptr)
    }
}

/// # Safety
/// If the parameter is rounded up to the nearest multiple of `mem::align_of::<B>()` and
/// then offset by `mem::size_of::<B>()`, it must still be within the allocation.
#[inline(always)]
unsafe fn align_up<A, B>(ptr: NonNull<A>) -> NonNull<B> {
    debug_assert!(ptr.as_ptr().is_aligned());
    unsafe {
        let ptr = mem::transmute::<*mut A, *mut u8>(ptr.as_ptr());

        // round up to nearest aligned address
        let addr = ptr.expose_provenance();
        let align = mem::align_of::<B>();
        let addr = (addr + align - 1) & !(align - 1);
        let ptr = ptr::with_exposed_provenance_mut(addr);

        let ptr = mem::transmute::<*mut u8, *mut B>(ptr);

        debug_assert!(ptr.is_aligned());
        NonNull::<B>::new_unchecked(ptr)
    }
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
        assert!(self.frame_top >= self.elems.base);
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
        self.prev_frame_len_slot = unsafe { align_down::<T, C>(self.frame_top.add(1)) }.as_ptr();

        unsafe {
            *self.prev_frame_len_slot = self.curr_frame_len;
        }
        self.curr_frame_len = 0;

        self.frame_top = unsafe {
            debug_assert!(!self.prev_frame_len_slot.is_null());
            let prev_slot = NonNull::new_unchecked(self.prev_frame_len_slot);
            align_down::<C, T>(prev_slot)
        };

        unsafe { self.push_elems(elems) }
    }

    /// # Safety
    /// The given number of elements must be present on the stack, and a frame must have
    /// been pushed.
    pub unsafe fn pop_frame(&mut self) {
        debug_assert!(!self.prev_frame_len_slot.is_null());
        let counter = unsafe { NonNull::new_unchecked(self.prev_frame_len_slot) };

        let frame_top = unsafe { align_up::<C, T>(counter) };

        self.prev_frame_len_slot = unsafe {
            let ptr = frame_top.as_ptr();
            let ptr = mem::transmute::<*mut T, *mut u8>(ptr);
            let ptr = ptr.add(*self.prev_frame_len_slot as usize);
            mem::transmute::<*mut u8, *mut C>(ptr)
        };

        self.curr_frame_len = unsafe {
            *self.prev_frame_len_slot
        };
    }
}

#[derive(Debug)]
pub struct LocalCtx {
    thread_id: ThreadId,
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
    fn push_frames() {
        let global_ctx = unsafe { init_global_ctx(DEFAULT_HOOKS) };
        let mut prov = Stack::<Provenance>::new(global_ctx, global_ctx.counts.provenance);
        let mut tag = Stack::<BorTag>::new(global_ctx, global_ctx.counts.provenance);

        let n_frames = 10;
        let n_elem: u32 = 2;

        for i in 0..n_frames {
            unsafe {
                prov.push_frame(n_elem as usize);
            }
            assert!(prov.curr_frame_len == n_elem);
            if i > 0 {
                unsafe { assert!(*prov.prev_frame_len_slot == n_elem) }
            }
        }
    }

    #[test]
    fn pop_frames() {
        let global_ctx = unsafe { init_global_ctx(DEFAULT_HOOKS) };
        let _ = Stack::<Provenance>::new(global_ctx, global_ctx.counts.provenance);
        let _ = Stack::<BorTag>::new(global_ctx, global_ctx.counts.provenance);
    }
}
