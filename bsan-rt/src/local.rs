use core::mem::{self, MaybeUninit};

use crate::block::{Block, BlockAllocator};
use crate::stack::Stack;
use crate::*;

#[derive(Debug)]
pub struct LocalCtx {
    pub thread_id: ThreadId,
    pub provenance: Stack<Provenance>,
    pub protected_tags: Stack<BorTag>,
}

impl LocalCtx {
    pub fn new(ctx: &GlobalCtx) -> Self {
        let thread_id = ctx.new_thread_id();
        let provenance = ctx.new_stack::<Provenance>();
        let protected_tags = ctx.new_stack::<BorTag>();
        Self { thread_id, provenance, protected_tags }
    }

    /// # Safety
    #[inline]
    pub unsafe fn push_frame(&mut self, elems: usize) -> NonNull<MaybeUninit<Provenance>> {
        unsafe {
            self.protected_tags.push_frame();
            self.provenance.push_frame_with(elems)
        }
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
