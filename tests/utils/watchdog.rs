#![allow(dead_code)]

use std::time::{Duration, Instant};

/// Runs `body` in a forked child and fails if the child crashes or does not
/// exit within `timeout`, so that a deadlock fails the test instead of hanging
/// the test suite. Requires the `libc` dependency.
pub fn run_with_watchdog(timeout: Duration, body: fn()) {
    match unsafe { libc::fork() } {
        -1 => fail("fork failed"),
        0 => {
            body();
            unsafe { libc::_exit(0) }
        }
        pid => {
            let start = Instant::now();
            loop {
                let mut status = 0;
                if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } == pid {
                    if !(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0) {
                        fail(&format!("child crashed: {status:#x}"));
                    }
                    return;
                }
                if start.elapsed() > timeout {
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                    fail(&format!("child did not exit within {timeout:?}; it probably deadlocked"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

// Exits instead of panicking: under `RUST_BACKTRACE=1`, symbolizing a panic's
// backtrace in an instrumented binary can take many minutes.
fn fail(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(1)
}
