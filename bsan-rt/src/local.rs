use core::cmp::min;
use core::mem::MaybeUninit;
use core::ops::Deref;
use core::ptr::NonNull;
use core::{ptr, slice};

use crate::memory::{mmap, munmap, StackSize};
use crate::Provenance;

#[thread_local]
static mut LOCAL_CTX: MaybeUninit<LocalCtx> = MaybeUninit::uninit();

/// A stack-sized chunk of memory for containing provenance values.
/// Each thread has its own provenance stack. This variable
/// stores the current value of the tag stack pointer, which is
/// updated by our instrumentation.
#[thread_local]
#[unsafe(no_mangle)]
pub static mut __BSAN_PROV_STACK: *mut Provenance = core::ptr::null_mut();

/// # Safety
/// `LOCAL_CTX` must be initialialied. This should not be used, since
/// accessing the local context requires locking the global context.
/// Instead, see `GlobalCtx::local_ctx`.
#[inline]
pub unsafe fn local_ctx<'a>() -> &'a LocalCtx {
    unsafe { local_ctx_mut() }
}

/// # Safety
/// `LOCAL_CTX` must be initialialied. This should not be used directly,
/// since accessing the local context requires locking the global context.
/// Instead, see `GlobalCtx::local_ctx_mut`.
#[inline]
pub unsafe fn local_ctx_mut<'a>() -> &'a mut LocalCtx {
    let ctx = &raw mut LOCAL_CTX;
    unsafe { &mut *ctx.cast::<LocalCtx>() }
}

/// # Safety
/// `LOCAL_CTX` must be uninitialized.
#[inline]
pub unsafe fn init_local_ctx(is_main: bool) -> NonNull<LocalCtx> {
    unsafe {
        let ptr = (&raw mut LOCAL_CTX).cast::<LocalCtx>();
        // Pointers to thread-local storage are always valid.
        let ptr = NonNull::new_unchecked(ptr);
        ptr.write(LocalCtx::new(is_main));
        ptr
    }
}

/// Deinitializes the global context object.
/// # Safety
/// This function must only be called once: when the program is terminating.
/// It is marked as `unsafe`, since all other API functions except for `bsan_init` rely
/// on the assumption that this function has not been called yet.
#[inline]
pub unsafe fn deinit_local_ctx() {
    unsafe { drop(ptr::replace(&raw mut LOCAL_CTX, MaybeUninit::uninit()).assume_init()) };
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProvenanceSlot(NonNull<Provenance>);

impl Deref for ProvenanceSlot {
    type Target = Provenance;

    fn deref(&self) -> &Self::Target {
        unsafe { self.0.as_ref() }
    }
}

pub struct LocalCtx {
    stack_bottom: NonNull<u8>,
    stack_size: StackSize,
}

impl LocalCtx {
    pub fn new(main: bool) -> Self {
        let stack_size = if main { StackSize::from_rlimit() } else { StackSize::from_pthread() };
        let stack_bottom = mmap(stack_size.bytes());

        let stack_top = unsafe { stack_bottom.add(stack_size.bytes_usize()) };
        let stack_top = stack_top.cast::<Provenance>();
        unsafe { __BSAN_PROV_STACK = stack_top.as_ptr() };
        Self { stack_bottom, stack_size }
    }

    /// # Safety
    /// A frame must have been pushed before being popped.
    pub unsafe fn pop_frame(&mut self, slot: ProvenanceSlot) {
        unsafe {
            __BSAN_PROV_STACK = slot.0.as_ptr();
        }
    }

    pub fn store_provenance(&mut self, value: Provenance, slot: ProvenanceSlot) {
        unsafe {
            slot.0.write(value);
            __BSAN_PROV_STACK = min(__BSAN_PROV_STACK, slot.0.as_ptr())
        }
    }

    pub fn provenance(&self) -> &[Provenance] {
        self.provenance_from(ProvenanceSlot(self.stack_bottom.cast::<Provenance>()))
    }

    pub fn provenance_from(&self, slot: ProvenanceSlot) -> &[Provenance] {
        unsafe {
            let data = __BSAN_PROV_STACK;
            let len = slot.0.as_ptr().offset_from_unsigned(data);
            slice::from_raw_parts(data, len)
        }
    }
}

impl Drop for LocalCtx {
    fn drop(&mut self) {
        unsafe { munmap(self.stack_bottom, self.stack_size) }
    }
}
