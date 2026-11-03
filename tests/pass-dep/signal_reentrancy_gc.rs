//@run:0
//@rustc-env: BSAN_OPTIONS=visits_per_gc=1000
#[path = "../utils/watchdog.rs"]
mod watchdog;

use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

// libc doesn't bind `setitimer` on Linux, so declare it here.
extern "C" {
    fn setitimer(
        which: libc::c_int,
        new_value: *const libc::itimerval,
        old_value: *mut libc::itimerval,
    ) -> libc::c_int;
}

static SHARED: AtomicPtr<u64> = AtomicPtr::new(std::ptr::null_mut());
static HANDLED: AtomicUsize = AtomicUsize::new(0);

const WORKERS: usize = 4;
const RUN_FOR: Duration = Duration::from_secs(3);
// Well above RUN_FOR and BSan's 10s `gc_hang_threshold_ms`.
const WATCHDOG: Duration = Duration::from_secs(30);

// Like `signal_reentrancy_stress`, but with several threads and a low GC
// threshold, so that SIGALRM also interrupts threads that are running the
// GC or waiting at a safepoint for another thread's GC to finish.
// Only shared references are used, so any failure is a runtime bug, not UB.

extern "C" fn on_alarm(_sig: libc::c_int) {
    let p = SHARED.load(Ordering::Relaxed);
    if p.is_null() {
        return;
    }
    let x = unsafe { &*p };
    let x_r = &*x;
    std::hint::black_box(*x_r);
    HANDLED.fetch_add(1, Ordering::Relaxed);
}

fn sigalrm_mask(how: libc::c_int) {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGALRM);
        libc::pthread_sigmask(how, &set, std::ptr::null_mut());
    }
}

fn worker(shared: &u64) {
    // Threads inherit the main thread's mask, which blocks SIGALRM.
    sigalrm_mask(libc::SIG_UNBLOCK);
    let start = Instant::now();
    while start.elapsed() < RUN_FOR {
        for _ in 0..64 {
            let s_r = &*shared;
            std::hint::black_box(*s_r);
            // Short-lived allocations keep the GC busy.
            std::hint::black_box(Box::new(*s_r));
        }
    }
}

fn child_workload() {
    let b = Box::new(42u64);
    SHARED.store(&*b as *const u64 as *mut u64, Ordering::Relaxed);

    // Block SIGALRM here, so the timer's signals go to the workers.
    sigalrm_mask(libc::SIG_BLOCK);
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_alarm as extern "C" fn(libc::c_int) as usize;
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
    }

    std::thread::scope(|s| {
        for _ in 0..WORKERS {
            s.spawn(|| worker(&b));
        }
        // Fire SIGALRM every 50µs.
        unsafe {
            let tick = libc::timeval { tv_sec: 0, tv_usec: 50 };
            let it = libc::itimerval { it_interval: tick, it_value: tick };
            setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut());
        }
    });

    // Stop the timer and clear the pointer before `b` is freed, so a late
    // signal can't read freed memory.
    unsafe {
        let off: libc::itimerval = std::mem::zeroed();
        setitimer(libc::ITIMER_REAL, &off, std::ptr::null_mut());
    }
    SHARED.store(std::ptr::null_mut(), Ordering::Relaxed);
    assert!(HANDLED.load(Ordering::Relaxed) > 0, "the SIGALRM handler never ran");
}

fn main() {
    watchdog::run_with_watchdog(WATCHDOG, child_workload);
}
