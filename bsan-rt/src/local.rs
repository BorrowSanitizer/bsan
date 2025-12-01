use core::{ffi, ptr};

use crate::span::FramePointer;
use crate::{BorTag, Provenance};

/// The number of `Provenance` values stored in the thread
/// local arrays for arguments and return values.
static TLS_SIZE: usize = 100;

/// A thread local array containing the provenance of pointers
/// passed as arguments to a function.
#[thread_local]
#[unsafe(no_mangle)]
pub static mut __BSAN_RETVAL_TLS: [Provenance; TLS_SIZE] = [Provenance::wildcard(); TLS_SIZE];

/// A thread local array containing the provenance of pointers
/// returned from a function.
#[thread_local]
#[unsafe(no_mangle)]
pub static mut __BSAN_PARAM_TLS: [Provenance; TLS_SIZE] = [Provenance::wildcard(); TLS_SIZE];

/// A stack-sized chunk of memory for containing protected
/// borrow tags. Each thread has its own tag stack, which is
/// initialized and deallocated by the LLVM wrapper. This variable
/// stores the current value of the tag stack pointer, which is
/// updated by our instrumentation.
#[thread_local]
#[unsafe(no_mangle)]
pub static mut __BSAN_PROT_TAG_STACK: *mut BorTag = ptr::null_mut();

/// A pointer to the local state of the current thread. This is
/// managed by the LLVM wrapper, but we define it here, since thread-local
/// symbols declared in a compiler-rt library do not appear to be relocatable,
/// even when compilation is configured that way.
#[thread_local]
#[unsafe(no_mangle)]
pub static mut __BSAN_CURR_THREAD: *mut ffi::c_void = ptr::null_mut();

/// The frame pointer of the caller of the last instrumented function that
/// called an uninstrumented function. When we enter an instrumented function
/// from a possibly uninstrumented function, we check to see if our "grandparent"
/// frame pointer matches this value. If so, we can trust that the contents
/// of `__BSAN_PARAM_TLS` are correct and initialized. Otherwise, we wipe the
/// contents of `__BSAN_PARAM_TLS`. We set this marker to null to indicate to the
/// caller that they can trust the contents of `__BSAN_RETVAL_TLS`. If this marker
/// is non-null when a function returns, then we know to wipe the contents
/// of `__BSAN_RETVAL_TLS`.
#[thread_local]
#[unsafe(no_mangle)]
pub static mut __BSAN_TLS_MARKER: FramePointer = FramePointer::null();
