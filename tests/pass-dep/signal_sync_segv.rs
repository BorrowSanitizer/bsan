//@run:0
// Checks that the program's handler for a synchronous signal runs at the
// faulting instruction with the right `siginfo`, and that execution resumes
// there when the handler returns.

use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

static PAGE: AtomicPtr<libc::c_void> = AtomicPtr::new(std::ptr::null_mut());
static FAULT_ADDR: AtomicPtr<libc::c_void> = AtomicPtr::new(std::ptr::null_mut());
static FAULTS: AtomicUsize = AtomicUsize::new(0);

const PAGE_SIZE: usize = 4096;

extern "C" fn on_segv(_sig: libc::c_int, info: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    FAULTS.fetch_add(1, Ordering::Relaxed);
    FAULT_ADDR.store(unsafe { (*info).si_addr() }, Ordering::Relaxed);
    // Make the page readable, so the faulting load succeeds when it reruns.
    let page = PAGE.load(Ordering::Relaxed);
    unsafe { libc::mprotect(page, PAGE_SIZE, libc::PROT_READ) };
}

fn main() {
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            PAGE_SIZE,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED);
    PAGE.store(page, Ordering::Relaxed);

    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_segv
            as extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void)
            as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        assert_eq!(libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut()), 0);
    }

    let value = unsafe { std::ptr::read_volatile(page as *const u8) };
    assert_eq!(value, 0);
    assert_eq!(FAULTS.load(Ordering::Relaxed), 1);
    assert_eq!(FAULT_ADDR.load(Ordering::Relaxed), page);

    unsafe { libc::munmap(page, PAGE_SIZE) };
}
