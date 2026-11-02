//@run:0
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

// How long the child retags for. Bounded by time rather than iterations,
// since one retag costs tens of microseconds under BSan.
const RUN_FOR: Duration = Duration::from_secs(3);
// Well above RUN_FOR and BSan's 10s `gc_hang_threshold_ms`.
const WATCHDOG: Duration = Duration::from_secs(30);

// Regression test for signal handlers re-entering the BSan runtime: SIGALRM fires
// constantly while the main thread retags, so handlers interrupt runtime code.
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

fn child_workload() {
    let b = Box::new(42u64);
    SHARED.store(&*b as *const u64 as *mut u64, Ordering::Relaxed);

    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_alarm as extern "C" fn(libc::c_int) as usize;
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());

        // Fire SIGALRM every 50µs.
        let tick = libc::timeval { tv_sec: 0, tv_usec: 50 };
        let it = libc::itimerval { it_interval: tick, it_value: tick };
        setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut());
    }

    let start = Instant::now();
    while start.elapsed() < RUN_FOR {
        for _ in 0..256 {
            let b_r = &*b;
            std::hint::black_box(*b_r);
        }
    }

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
