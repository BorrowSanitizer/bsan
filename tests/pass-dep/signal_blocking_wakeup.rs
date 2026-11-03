//@run:0
// Checks that a thread blocked in a system call still receives its signals
// promptly. The runtime defers a signal only while its thread is running
// runtime code, never while the thread waits in a system call, even one that
// is intercepted. If it did, these waits would never end.
#[path = "../utils/watchdog.rs"]
mod watchdog;

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

// libc doesn't bind `pthread_kill` on Linux, so declare it here.
extern "C" {
    fn pthread_kill(thread: libc::pthread_t, sig: libc::c_int) -> libc::c_int;
}

const WATCHDOG: Duration = Duration::from_secs(30);

static WAKE_FD: AtomicI32 = AtomicI32::new(-1);
static SUSPEND_HANDLED: AtomicBool = AtomicBool::new(false);

extern "C" fn write_wake_byte(_sig: libc::c_int) {
    let fd = WAKE_FD.load(Ordering::Relaxed);
    unsafe { libc::write(fd, b"x".as_ptr() as *const libc::c_void, 1) };
}

extern "C" fn note_suspend(_sig: libc::c_int) {
    SUSPEND_HANDLED.store(true, Ordering::Relaxed);
}

fn install(sig: libc::c_int, handler: extern "C" fn(libc::c_int), flags: libc::c_int) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as usize;
        sa.sa_flags = flags;
        assert_eq!(libc::sigaction(sig, &sa, std::ptr::null_mut()), 0);
    }
}

// `read` is intercepted. With `SA_RESTART`, the kernel restarts it after the
// handler returns. The handler writes the byte that `read` is waiting for, so
// `read` only returns if the handler ran while the thread was blocked.
fn read_wakes_up() {
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    WAKE_FD.store(fds[1], Ordering::Relaxed);
    install(libc::SIGUSR1, write_wake_byte, libc::SA_RESTART);

    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        tx.send(unsafe { libc::pthread_self() }).unwrap();
        let mut byte = 0u8;
        let n = unsafe { libc::read(fds[0], &mut byte as *mut u8 as *mut libc::c_void, 1) };
        assert_eq!(n, 1);
        assert_eq!(byte, b'x');
    });
    let thread = rx.recv().unwrap();
    // Give the reader time to block in `read`.
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(unsafe { pthread_kill(thread, libc::SIGUSR1) }, 0);
    reader.join().unwrap();
}

// `sigsuspend` returns once a handler has run. The waiter blocks the signal
// until it calls `sigsuspend`, so the signal can only be handled there.
fn sigsuspend_wakes_up() {
    install(libc::SIGUSR2, note_suspend, 0);
    let (tx, rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || unsafe {
        let mut usr2: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut usr2);
        libc::sigaddset(&mut usr2, libc::SIGUSR2);
        libc::pthread_sigmask(libc::SIG_BLOCK, &usr2, std::ptr::null_mut());
        tx.send(libc::pthread_self()).unwrap();

        let mut none: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut none);
        assert_eq!(libc::sigsuspend(&none), -1);
        assert!(SUSPEND_HANDLED.load(Ordering::Relaxed));
    });
    let thread = rx.recv().unwrap();
    assert_eq!(unsafe { pthread_kill(thread, libc::SIGUSR2) }, 0);
    waiter.join().unwrap();
}

fn child_workload() {
    read_wakes_up();
    sigsuspend_wakes_up();
}

fn main() {
    watchdog::run_with_watchdog(WATCHDOG, child_workload);
}
