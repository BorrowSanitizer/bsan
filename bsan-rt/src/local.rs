use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::num::NonZero;
use core::ops::Deref;
use core::ptr;
use core::ptr::NonNull;

use crate::{GlobalCtx, Provenance};

struct LocalCtxWrapper(UnsafeCell<MaybeUninit<LocalCtx>>);

unsafe impl Send for LocalCtxWrapper {}
unsafe impl Sync for LocalCtxWrapper {}

#[thread_local]
pub static LOCAL_CTX: LocalCtxWrapper = LocalCtxWrapper(UnsafeCell::new(MaybeUninit::uninit()));

/// The LocalCtx should contain a pointer to the shadow stack,
/// the length of the shadow stack allocation,
/// and a pointer to where the thread's __BSAN_PROV_STACK is stored.
#[derive(Debug)]
pub struct LocalCtx {
    stack_top: NonNull<Provenance>,
    stack_ptr: *mut NonNull<Provenance>,
}

impl LocalCtx {
    pub unsafe fn new(stack_ptr: *mut NonNull<Provenance>) -> Self {
        unsafe { LocalCtx { stack_top: stack_ptr.read(), stack_ptr } }
    }
}

/// Initializes the local context object.
///
/// # Safety
/// This function should only be called once, when a thread is initialized.
#[inline]
pub unsafe fn init_local_ctx(global_ctx: &GlobalCtx, stack_ptr: *mut NonNull<Provenance>) {
    unsafe {
        let local_ctx_ptr = LOCAL_CTX.0.get().cast::<LocalCtx>();
        local_ctx_ptr.write(LocalCtx::new(stack_ptr));
        global_ctx.register_thread(NonNull::new_unchecked(local_ctx_ptr));
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
    unsafe { drop(ptr::replace(LOCAL_CTX.0.get(), MaybeUninit::uninit()).assume_init()) };
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
