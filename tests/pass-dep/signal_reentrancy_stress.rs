use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::{Duration, Instant};

static SHARED: AtomicPtr<u64> = AtomicPtr::new(std::ptr::null_mut());

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
        libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut());
    }

    for _ in 0..4_000_000 {
        let b_r = &*b;
        std::hint::black_box(*b_r);
    }

    // Stop the timer and clear the pointer before `b` is freed, so a late
    // signal can't read freed memory.
    unsafe {
        let off: libc::itimerval = std::mem::zeroed();
        libc::setitimer(libc::ITIMER_REAL, &off, std::ptr::null_mut());
    }
    SHARED.store(std::ptr::null_mut(), Ordering::Relaxed);
}

fn main() {
    match unsafe { libc::fork() } {
        0 => { child_workload(); unsafe { libc::_exit(0) } }
        pid => {
            let start = Instant::now();
            loop {
                let mut status = 0;
                if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } == pid {
                    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                            "child crashed: {status:#x}");
                    return;
                }
                if start.elapsed() > Duration::from_secs(20) {
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                    panic!("child deadlocked");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
