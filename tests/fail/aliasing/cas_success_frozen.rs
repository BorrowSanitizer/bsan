//@run: 1
//@revisions: x86_64 aarch64
//@[x86_64]only-target: x86_64
//@[aarch64]only-target: aarch64

use std::sync::atomic::{AtomicUsize, Ordering};

fn main() {
    let x = 0usize;
    let ptr = &x as *const usize as *const AtomicUsize;
    let _ = unsafe { (*ptr).compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst) };
}
