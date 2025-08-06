use core::mem::MaybeUninit;

use crate::errors::BorsanResult;
use crate::memory::Stack;
use crate::*;

#[thread_local]
pub static LOCAL_CTX: UnsafeCell<MaybeUninit<LocalCtx>> = UnsafeCell::new(MaybeUninit::uninit());

static TLS_SIZE: usize = 100;

#[thread_local]
#[unsafe(no_mangle)]
pub static mut __BSAN_RETVAL_TLS: [Provenance; TLS_SIZE] = [Provenance::wildcard(); TLS_SIZE];

#[thread_local]
#[unsafe(no_mangle)]
pub static mut __BSAN_PARAM_TLS: [Provenance; TLS_SIZE] = [Provenance::wildcard(); TLS_SIZE];

#[derive(Debug)]
pub struct LocalCtx {
    pub thread_id: ThreadId,
    pub stack: Stack<AllocInfo>,
    pub protected_tags: Stack<BorTag>,
}

impl LocalCtx {
    pub fn new(ctx: &GlobalCtx) -> BorsanResult<Self> {
        let thread_id = ctx.new_thread_id();
        let stack = Stack::<AllocInfo>::new(ctx)?;
        let protected_tags = Stack::<BorTag>::new(ctx)?;
        Ok(Self { thread_id, stack, protected_tags })
    }

    #[inline]
    pub fn push_frame(&mut self) -> BorsanResult<()> {
        Ok(self.stack.push_frame()?)
    }

    /// # Safety
    /// A frame must have been pushed.
    #[inline]
    pub unsafe fn pop_frame(&mut self) {
        unsafe { self.stack.pop_frame() }
    }

    #[inline]
    pub fn allocate_stack_slot(&mut self, elem: AllocInfo) -> BorsanResult<NonNull<AllocInfo>> {
        Ok(self.stack.push(elem)?)
    }

    #[inline]
    pub fn add_protected_tag(&mut self, tag: BorTag) -> BorsanResult<()> {
        let _ = self.protected_tags.push(tag)?;
        Ok(())
    }
}

/// Initializes the local context object.
///
/// # Safety
/// This function should only be called once, when a thread is initialized.
#[inline]
pub unsafe fn init_local_ctx(ctx: &GlobalCtx) -> BorsanResult<&LocalCtx> {
    let local_ctx = LocalCtx::new(ctx)?;
    unsafe {
        (*LOCAL_CTX.get()).write(local_ctx);
        Ok(local_ctx_mut())
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
    unsafe { ptr::replace(LOCAL_CTX.get(), MaybeUninit::uninit()).assume_init() };
}

/// # Safety
/// The user needs to ensure that the context is initialized.
#[inline]
pub unsafe fn local_ctx<'a>() -> &'a LocalCtx {
    unsafe { &*local_ctx_mut() }
}

/// # Safety
/// The user needs to ensure that the context is initialized.
#[inline]
pub unsafe fn local_ctx_mut<'a>() -> &'a mut LocalCtx {
    let ctx = LOCAL_CTX.get();
    unsafe { &mut *ctx.cast::<local::LocalCtx>() }
}

impl Drop for LocalCtx {
    fn drop(&mut self) {}
}
