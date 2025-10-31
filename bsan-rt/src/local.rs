use core::mem::MaybeUninit;

use crate::errors::BorsanResult;
use crate::memory::{mmap, InternalAllocKind, StackSize};
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

#[thread_local]
#[unsafe(no_mangle)]
pub static mut __BSAN_PROT_TAG_STACK: *mut BorTag = core::ptr::null_mut();

#[thread_local]
#[unsafe(no_mangle)]
pub static mut __BSAN_PROT_TAG_STACK_TOP: *mut BorTag = core::ptr::null_mut();

#[derive(Debug)]
pub struct LocalCtx;
impl LocalCtx {
    pub fn new(ctx: &GlobalCtx) -> BorsanResult<Self> {
        let size = StackSize::try_new()?;
        unsafe {
            let limit = mmap(ctx.hooks().mmap_ptr, InternalAllocKind::Stack, *size)?;
            debug_assert!(limit.is_aligned());
            let cursor = limit.byte_add((*size).into());
            debug_assert!(cursor.is_aligned());
            __BSAN_PROT_TAG_STACK = cursor.cast::<BorTag>().as_ptr();
            __BSAN_PROT_TAG_STACK_TOP = __BSAN_PROT_TAG_STACK;
        }
        Ok(LocalCtx)
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
    unsafe { drop(ptr::replace(LOCAL_CTX.get(), MaybeUninit::uninit()).assume_init()) };
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
