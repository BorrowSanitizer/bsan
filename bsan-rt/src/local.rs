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

/// The frame pointer of the caller of the last instrumented function that called an
/// uninstrumented function. When we enter an instrumented function from
/// an possibly uninstrumented function, we check to see if our "grandparent"
/// frame pointer matches this value. If so, we can trust that the contents
/// of `__BSAN_PARAM_TLS` are correct and initialized. Otherwise, we need to
/// overwrite it with wildcard values and set this pointer to null.
#[thread_local]
#[unsafe(no_mangle)]
pub static mut __BSAN_PARAM_TLS_MARKER: FramePointer = FramePointer::null();

/// After validating the parameter TLS, we set this marker equal to the value of
/// the parameter TLS marker. This will be the null frame pointer if we came from
/// an uninstrumented function, and it will be the value of our "grandparent" frame
/// pointer if we came from an instrumented function. The caller of a possibly 
/// uninstrumented function can check this value after the call against the value it
/// stored in the parameter TLS marker. If they match, then the return value can be
/// trusted. If not, then we overwrite the return value TLS with wildcard values.
#[thread_local]
#[unsafe(no_mangle)]
pub static mut __BSAN_RETVAL_TLS_MARKER: FramePointer = FramePointer::null();
