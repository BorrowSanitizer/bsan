//@run: 1
// A compare-exchange that succeeds writes, so it is forbidden through a
// pointer derived from a shared reference without interior mutability.
use std::sync::atomic::{AtomicUsize, Ordering};

fn main() {
    let x = 0usize;
    let ptr = &x as *const usize as *const AtomicUsize;
    let _ = unsafe { (*ptr).compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst) };
}
