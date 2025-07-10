use core::mem::MaybeUninit;

use crate::stack::Stack;
use crate::*;

static TLS_SIZE: usize = 100;

#[thread_local]
#[unsafe(no_mangle)]
pub static mut __BSAN_RETVAL_TLS: [Provenance; TLS_SIZE] = [Provenance::null(); TLS_SIZE];

#[thread_local]
#[unsafe(no_mangle)]
pub static mut __BSAN_PARAM_TLS: [Provenance; TLS_SIZE] = [Provenance::null(); TLS_SIZE];

#[derive(Debug)]
pub struct LocalCtx {
    pub thread_id: ThreadId,
    pub provenance: Stack<Provenance>,
    pub protected_tags: Stack<(AllocId, BorTag)>,
}

impl LocalCtx {
    pub fn new(ctx: &GlobalCtx) -> Self {
        let thread_id = ctx.new_thread_id();
        let provenance = Stack::<Provenance>::new(ctx);
        let protected_tags = Stack::<(AllocId, BorTag)>::new(ctx);
        Self { thread_id, provenance, protected_tags }
    }

    #[inline]
    pub fn push_frame(&mut self, elems: usize) -> NonNull<MaybeUninit<Provenance>> {
        self.protected_tags.push_frame();
        self.provenance.push_frame_with(elems)
    }

    #[inline]
    pub fn add_protected_tag(&mut self, alloc_id: AllocId, tag: BorTag) {
        self.protected_tags.push((alloc_id, tag));
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
