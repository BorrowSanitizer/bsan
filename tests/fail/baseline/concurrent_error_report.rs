//@run: 1
//! Two threads detect UB at the same time. Only one of them may report it:
//! without a lock around the reporting path, both write to stderr at once and
//! the two reports interleave line by line.
use std::sync::Barrier;
use std::thread;

fn main() {
    let barrier = Barrier::new(2);
    thread::scope(|s| {
        for _ in 0..2 {
            s.spawn(|| {
                let mut x = 1;
                let p = &mut x as *mut i32;
                // Line the threads up so they hit UB at the same instant.
                barrier.wait();
                oob_write(p);
            });
        }
    });
}

#[inline(never)]
fn oob_write(p: *mut i32) {
    unsafe { p.add(1).write(0) }
}
