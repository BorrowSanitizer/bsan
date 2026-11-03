//@run:0
//@rustc-env: BSAN_OPTIONS=visits_per_gc=1
// Checks that a handler running on an alternate signal stack can run the GC.
// The handler's stack pointer lies outside of its thread's stack, so the GC
// must bound the thread's live frames by the stack pointer of the code that the
// signal interrupted. With `visits_per_gc=1`, every retag in the handler
// requests a collection.
#[path = "../utils/watchdog.rs"]
mod watchdog;

use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::time::Duration;

const WATCHDOG: Duration = Duration::from_secs(30);
const ALTSTACK_SIZE: usize = 256 * 1024;
const SIGNALS: usize = 20;

static SHARED: AtomicPtr<u64> = AtomicPtr::new(std::ptr::null_mut());
static HANDLED: AtomicUsize = AtomicUsize::new(0);

extern "C" fn on_usr1(_sig: libc::c_int) {
    let p = SHARED.load(Ordering::Relaxed);
    let x = unsafe { &*p };
    let x_r = &*x;
    assert_eq!(*x_r, 42);
    HANDLED.fetch_add(1, Ordering::Relaxed);
}

fn child_workload() {
    unsafe {
        let stack = libc::mmap(
            std::ptr::null_mut(),
            ALTSTACK_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(stack, libc::MAP_FAILED);
        let ss = libc::stack_t { ss_sp: stack, ss_flags: 0, ss_size: ALTSTACK_SIZE };
        assert_eq!(libc::sigaltstack(&ss, std::ptr::null_mut()), 0);

        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_usr1 as extern "C" fn(libc::c_int) as usize;
        sa.sa_flags = libc::SA_ONSTACK;
        assert_eq!(libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut()), 0);
    }

    let b = Box::new(42u64);
    SHARED.store(&*b as *const u64 as *mut u64, Ordering::Relaxed);
    // A local whose provenance must survive the handlers' collections.
    let local = 7u64;
    let local_r = &local;
    for i in 0..SIGNALS {
        unsafe { libc::raise(libc::SIGUSR1) };
        assert_eq!(HANDLED.load(Ordering::Relaxed), i + 1);
        assert_eq!(*local_r, 7);
    }
    SHARED.store(std::ptr::null_mut(), Ordering::Relaxed);
}

fn main() {
    watchdog::run_with_watchdog(WATCHDOG, child_workload);
}
