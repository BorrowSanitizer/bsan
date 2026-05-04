use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr;
use core::ptr::NonNull;

use crate::{GlobalCtx, Provenance, ThreadId};

pub(crate) struct LocalCtxWrapper(UnsafeCell<MaybeUninit<LocalCtx>>);

unsafe impl Send for LocalCtxWrapper {}
unsafe impl Sync for LocalCtxWrapper {}

#[thread_local]
pub(crate) static LOCAL_CTX: LocalCtxWrapper =
    LocalCtxWrapper(UnsafeCell::new(MaybeUninit::uninit()));

/// The LocalCtx should contain a pointer to the shadow stack,
/// the length of the shadow stack allocation,
/// and a pointer to where the thread's __BSAN_PROV_STACK is stored.
#[derive(Debug)]
pub struct LocalCtx {
    thread_id: ThreadId,
    stack_top: NonNull<Provenance>,
    stack_ptr: *mut NonNull<Provenance>,
}

impl LocalCtx {
    pub unsafe fn new(thread_id: ThreadId, stack_ptr: *mut NonNull<Provenance>) -> Self {
        unsafe { LocalCtx { thread_id, stack_top: stack_ptr.read(), stack_ptr } }
    }

    pub fn thread_id(&self) -> ThreadId {
        self.thread_id
    }
}

/// Initializes the local context object.
///
/// # Safety
/// This function should only be called once, when a thread is initialized.
#[inline]
pub unsafe fn init_local_ctx(global_ctx: &GlobalCtx, stack_ptr: *mut NonNull<Provenance>) {
    let local_ctx_ptr = LOCAL_CTX.0.get().cast::<LocalCtx>();
    let thread_id = ThreadId::default();
    unsafe {
        let local_ctx = LocalCtx::new(thread_id, stack_ptr);
        local_ctx_ptr.write(local_ctx);
        global_ctx.register_thread(thread_id, NonNull::new_unchecked(local_ctx_ptr));
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
pub unsafe fn deinit_local_ctx(global_ctx: &GlobalCtx) {
    let thread_id = unsafe { (*LOCAL_CTX.0.get()).assume_init_ref().thread_id() };
    unsafe { ptr::replace(LOCAL_CTX.0.get(), MaybeUninit::uninit()).assume_init() };
    global_ctx.deregister_thread(thread_id);
}

// /// # Safety
// /// The user needs to ensure that the context is initialized.
// #[inline]
// pub unsafe fn local_ctx<'a>() -> &'a LocalCtx {
//     unsafe { &*local_ctx_mut() }
// }

// /// # Safety
// /// The user needs to ensure that the context is initialized.
// #[inline]
// pub unsafe fn local_ctx_mut<'a>() -> &'a mut LocalCtx {
//     let ctx = LOCAL_CTX.0.get();
//     unsafe { &mut *ctx.cast::<LocalCtx>() }
// }
