use core::cmp::min;
use core::mem::{self, MaybeUninit};
use core::ops::Deref;
use core::ptr::NonNull;
use core::{ptr, slice};

use crate::memory::{mmap, munmap, StackSize};
use crate::Provenance;

#[thread_local]
static mut LOCAL_CTX: MaybeUninit<LocalCtx> = MaybeUninit::uninit();

#[thread_local]
static mut __BSAN_PROV_STACK: *mut Provenance = core::ptr::null_mut();

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
    fp: NonNull<usize>,
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
        Self { fp: Self::next_frame(None), stack_bottom, stack_size }
    }

    pub fn push_frame(&mut self) -> NonNull<Provenance> {
        self.fp = Self::next_frame(Some(self.fp));
        unsafe { NonNull::new_unchecked(__BSAN_PROV_STACK) }
    }

    /// # Safety
    /// A frame must have been pushed before being popped.
    pub unsafe fn pop_frame(&mut self) {
        unsafe {
            __BSAN_PROV_STACK = self.fp.add(1).cast::<Provenance>().as_ptr();
            self.fp = mem::transmute::<usize, NonNull<usize>>(self.fp.read())
        }
    }

    #[inline]
    fn next_frame(fp: Option<NonNull<usize>>) -> NonNull<usize> {
        unsafe {
            let next_fp = __BSAN_PROV_STACK.cast::<Option<NonNull<usize>>>().sub(1);
            next_fp.write(fp);
            __BSAN_PROV_STACK = next_fp.cast::<Provenance>();
            NonNull::new_unchecked(next_fp).cast::<usize>()
        }
    }

    pub fn store_provenance(&mut self, value: Provenance, slot: ProvenanceSlot) {
        unsafe {
            slot.0.write(value);
            __BSAN_PROV_STACK = min(__BSAN_PROV_STACK, slot.0.as_ptr())
        }
    }

    pub fn frame_cursor(&self) -> FrameCursor {
        FrameCursor { frame_top: unsafe { NonNull::new_unchecked(__BSAN_PROV_STACK) }, fp: self.fp }
    }
}

#[derive(Clone, Copy)]
pub struct FrameCursor {
    frame_top: NonNull<Provenance>,
    fp: NonNull<usize>,
}

impl FrameCursor {
    pub fn provenance(&self) -> &[Provenance] {
        unsafe {
            let len = self.fp.cast::<Provenance>().offset_from_unsigned(self.frame_top);
            slice::from_raw_parts(self.frame_top.as_ptr(), len)
        }
    }
}

impl Iterator for FrameCursor {
    type Item = Self;
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let next_fp = self.fp.read();
            let next_fp = mem::transmute::<usize, Option<NonNull<usize>>>(next_fp);
            next_fp.map(|fp| {
                let frame_top = self.fp.add(1).cast::<Provenance>();
                *self = FrameCursor { frame_top, fp };
                *self
            })
        }
    }
}

impl Drop for LocalCtx {
    fn drop(&mut self) {
        unsafe { munmap(self.stack_bottom, self.stack_size) }
    }
}

#[cfg(test)]
mod tests {
    use super::{LocalCtx, ProvenanceSlot};
    use crate::Provenance;
    fn with_local<F>(f: F)
    where
        F: FnOnce(&mut LocalCtx),
    {
        f(&mut LocalCtx::new(true));
    }

    #[test]
    fn push_frame() {
        with_local(|local| {
            local.push_frame();
        })
    }

    #[test]
    fn pop_frame() {
        with_local(|local| {
            local.push_frame();
            unsafe {
                local.pop_frame();
            }
        })
    }

    #[test]
    fn empty_frame() {
        with_local(|local| {
            let mut frame = local.frame_cursor();
            assert!(frame.next().is_none());
            assert!(frame.provenance().is_empty());
        })
    }

    #[test]
    fn store_provenance() {
        with_local(|local| {
            let base = local.push_frame();
            unsafe {
                local.store_provenance(Provenance::wildcard(), ProvenanceSlot(base.sub(1)));
            }
            assert!(local.frame_cursor().provenance().len() == 1);
            unsafe { local.pop_frame() };
        })
    }

    #[test]
    fn iter_frames() {
        with_local(|local| {
            const N: usize = 5;
            let mut fp_list = vec![];
            for _ in 0..N {
                fp_list.push(local.fp);
                let prov = local.push_frame();
                unsafe {
                    let slot = prov.sub(1);
                    local.store_provenance(Provenance::wildcard(), ProvenanceSlot(slot));
                }
            }
            for (i, cursor) in local.frame_cursor().enumerate() {
                assert!(cursor.fp == fp_list[N - i - 1]);
            }
        })
    }
}
