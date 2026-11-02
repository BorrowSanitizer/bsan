// A compare-exchange that fails only reads, so it is permitted through a
// pointer derived from a shared reference without interior mutability.
use std::sync::atomic::{AtomicUsize, Ordering};

fn main() {
    let x = 0usize;
    let ptr = &x as *const usize as *const AtomicUsize;
    let res = unsafe { (*ptr).compare_exchange(1, 2, Ordering::SeqCst, Ordering::SeqCst) };
    assert_eq!(res, Err(0));
}
