//@run:0
// Checks that wrapping the program's signal handlers is invisible to the
// program: `sigaction` and `signal` report the program's own handlers, never
// the runtime's trampoline, and dispositions and flags behave as without BSan.

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

// libc doesn't bind `pthread_kill` on Linux, so declare it here.
extern "C" {
    fn pthread_kill(thread: libc::pthread_t, sig: libc::c_int) -> libc::c_int;
}

static A_RAN: AtomicUsize = AtomicUsize::new(0);
static B_RAN: AtomicUsize = AtomicUsize::new(0);
static SIGVAL: AtomicPtr<libc::c_void> = AtomicPtr::new(std::ptr::null_mut());
static HANDLER_TID: AtomicI32 = AtomicI32::new(0);
static TARGET_HIT: AtomicBool = AtomicBool::new(false);

extern "C" fn handler_a(_sig: libc::c_int) {
    A_RAN.fetch_add(1, Ordering::Relaxed);
}

extern "C" fn handler_b(_sig: libc::c_int, _info: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    B_RAN.fetch_add(1, Ordering::Relaxed);
}

extern "C" fn record_sigval(
    _sig: libc::c_int,
    info: *mut libc::siginfo_t,
    _uc: *mut libc::c_void,
) {
    SIGVAL.store(unsafe { (*info).si_value().sival_ptr }, Ordering::Relaxed);
}

extern "C" fn record_tid(_sig: libc::c_int) {
    HANDLER_TID.store(unsafe { libc::gettid() }, Ordering::Relaxed);
    TARGET_HIT.store(true, Ordering::Release);
}

fn action(handler: usize, flags: libc::c_int) -> libc::sigaction {
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = handler;
    sa.sa_flags = flags;
    sa
}

fn install(sig: libc::c_int, sa: &libc::sigaction) -> libc::sigaction {
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::sigaction(sig, sa, &mut old) }, 0);
    old
}

fn query(sig: libc::c_int) -> libc::sigaction {
    let mut cur: libc::sigaction = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::sigaction(sig, std::ptr::null(), &mut cur) }, 0);
    cur
}

fn raise(sig: libc::c_int) {
    assert_eq!(unsafe { libc::raise(sig) }, 0);
}

// Installing, querying, and reinstalling a previous action round-trips the
// program's handlers and their `SA_SIGINFO` flag.
fn oldact_round_trip() {
    let a = handler_a as extern "C" fn(libc::c_int) as usize;
    let b = handler_b as extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void)
        as usize;
    install(libc::SIGUSR1, &action(a, 0));

    let old = install(libc::SIGUSR1, &action(b, libc::SA_SIGINFO));
    assert_eq!(old.sa_sigaction, a);
    assert_eq!(old.sa_flags & libc::SA_SIGINFO, 0);

    let cur = query(libc::SIGUSR1);
    assert_eq!(cur.sa_sigaction, b);
    assert_ne!(cur.sa_flags & libc::SA_SIGINFO, 0);
    raise(libc::SIGUSR1);
    assert_eq!(B_RAN.load(Ordering::Relaxed), 1);

    // Reinstall the action that `oldact` reported.
    install(libc::SIGUSR1, &old);
    let cur = query(libc::SIGUSR1);
    assert_eq!(cur.sa_sigaction, a);
    assert_eq!(cur.sa_flags & libc::SA_SIGINFO, 0);
    raise(libc::SIGUSR1);
    assert_eq!(A_RAN.load(Ordering::Relaxed), 1);
    assert_eq!(B_RAN.load(Ordering::Relaxed), 1);

    install(libc::SIGUSR1, &action(libc::SIG_DFL, 0));
}

// `signal` returns the previous handler, and has BSD semantics.
fn signal_returns_previous() {
    let a = handler_a as extern "C" fn(libc::c_int) as libc::sighandler_t;
    let ran = A_RAN.load(Ordering::Relaxed);
    assert_eq!(unsafe { libc::signal(libc::SIGUSR2, a) }, libc::SIG_DFL);
    assert_eq!(unsafe { libc::signal(libc::SIGUSR2, libc::SIG_IGN) }, a);
    assert_eq!(unsafe { libc::signal(libc::SIGUSR2, a) }, libc::SIG_IGN);

    let cur = query(libc::SIGUSR2);
    assert_eq!(cur.sa_sigaction, a);
    assert_ne!(cur.sa_flags & libc::SA_RESTART, 0);
    raise(libc::SIGUSR2);
    assert_eq!(A_RAN.load(Ordering::Relaxed), ran + 1);

    assert_eq!(unsafe { libc::signal(libc::SIGUSR2, libc::SIG_DFL) }, a);
    assert_eq!(unsafe { libc::signal(-1, a) }, libc::SIG_ERR);
}

// An ignored signal is dropped, and queries report `SIG_IGN`.
fn sig_ign() {
    install(libc::SIGUSR1, &action(libc::SIG_IGN, 0));
    assert_eq!(query(libc::SIGUSR1).sa_sigaction, libc::SIG_IGN);
    raise(libc::SIGUSR1);
    install(libc::SIGUSR1, &action(libc::SIG_DFL, 0));
}

// With `SA_RESETHAND`, the handler runs once, and then the kernel resets the
// action to `SIG_DFL`.
fn sa_resethand() {
    let a = handler_a as extern "C" fn(libc::c_int) as usize;
    let ran = A_RAN.load(Ordering::Relaxed);
    install(libc::SIGUSR2, &action(a, libc::SA_RESETHAND));
    assert_eq!(query(libc::SIGUSR2).sa_sigaction, a);
    raise(libc::SIGUSR2);
    assert_eq!(A_RAN.load(Ordering::Relaxed), ran + 1);
    assert_eq!(query(libc::SIGUSR2).sa_sigaction, libc::SIG_DFL);
}

// An `SA_SIGINFO` handler receives the value passed to `sigqueue`.
fn sigqueue_value() {
    let f = record_sigval
        as extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void)
        as usize;
    install(libc::SIGUSR1, &action(f, libc::SA_SIGINFO));
    let value = libc::sigval { sival_ptr: 0x1234 as *mut libc::c_void };
    // A signal sent to the process can go to any thread, but the test has
    // only one, so the handler runs before `sigqueue` returns.
    assert_eq!(unsafe { libc::sigqueue(libc::getpid(), libc::SIGUSR1, value) }, 0);
    assert_eq!(SIGVAL.load(Ordering::Relaxed), 0x1234 as *mut libc::c_void);
    install(libc::SIGUSR1, &action(libc::SIG_DFL, 0));
}

// `pthread_kill` runs the handler on the target thread.
fn pthread_kill_other_thread() {
    let f = record_tid as extern "C" fn(libc::c_int) as usize;
    install(libc::SIGUSR2, &action(f, 0));
    let (tx, rx) = std::sync::mpsc::channel();
    let target = std::thread::spawn(move || {
        tx.send((unsafe { libc::pthread_self() }, unsafe { libc::gettid() })).unwrap();
        let start = Instant::now();
        while !TARGET_HIT.load(Ordering::Acquire) {
            assert!(start.elapsed() < Duration::from_secs(10), "the signal never arrived");
            std::thread::yield_now();
        }
    });
    let (thread, tid) = rx.recv().unwrap();
    assert_eq!(unsafe { pthread_kill(thread, libc::SIGUSR2) }, 0);
    target.join().unwrap();
    assert_eq!(HANDLER_TID.load(Ordering::Relaxed), tid);
    install(libc::SIGUSR2, &action(libc::SIG_DFL, 0));
}

fn main() {
    oldact_round_trip();
    signal_returns_previous();
    sig_ign();
    sa_resethand();
    sigqueue_value();
    pthread_kill_other_thread();
}
