//! VecDeque
//!
//! Tests ring buffer allocation/reallocation and popping/pushing patterns.

use std::collections::VecDeque;
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

            // === VecDeque (ring buffer pattern) ===
            // Tests reallocation patterns different from Vec
            let mut deque = VecDeque::with_capacity(16);
            for i in 0..500 {
                deque.push_back(vec![0u8; 48 + (i % 200)]);
                if deque.len() > 100 {
                    let popped = deque.pop_front().unwrap();
                    std::hint::black_box(popped);
                }
            }
            drop(deque);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
