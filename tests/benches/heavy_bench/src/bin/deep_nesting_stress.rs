//! Deep nesting
//!
//! Creates deeply nested borrows of a single allocation to stress borrow tree tracking depth.

use std::sync::{Arc, Barrier};
use std::thread;

fn main() {
    let num_threads = 8;
    let barrier = Arc::new(Barrier::new(num_threads));

    let mut handles = vec![];
    for _ in 0..num_threads {
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            // Synchronize all threads to maximize contention
            barrier.wait();

            // === Deep nesting (stress tree borrows depth) ===
            // Allocate a buffer and create deeply nested mutable references
            let mut buf = vec![0u8; 8192];
            let mut slice: &mut [u8] = &mut buf;
            for depth in 0..20 {
                let len = slice.len();
                if len < 2 {
                    break;
                }
                let half = len / 2;
                slice = &mut slice[..half];
                slice[0] = depth as u8;
                std::hint::black_box(slice[0]);
            }
            std::hint::black_box(&buf);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
