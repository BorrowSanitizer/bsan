//! Rapid alloc/free cycling (throughput)
//!
//! Tests raw allocator throughput with varied sizes under multi-threaded contention.

use std::sync::{Arc, Barrier};
use std::thread;

fn main() {
    let num_threads = 8;
    let barrier = Arc::new(Barrier::new(num_threads));

    let mut handles = vec![];
    for tid in 0..num_threads {
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            // Synchronize all threads to maximize contention
            barrier.wait();

            // === Rapid alloc/free cycling (1000 iterations) ===
            // Tests raw allocator throughput with varied sizes
            for i in 0..1000 {
                // Vary sizes: 16, 64, 256, 1024, 4096 bytes
                let size = match i % 5 {
                    0 => 16,
                    1 => 64,
                    2 => 256,
                    3 => 1024,
                    _ => 4096,
                };
                let mut v: Vec<u8> = vec![0u8; size];
                // Touch memory to prevent optimization
                v[0] = (tid as u8).wrapping_add(i as u8);
                if size > 1 {
                    v[size - 1] = 0xFF;
                }
                // Create mutable references (triggers BSAN retags if instrumented)
                let slice = &mut v[..];
                slice[0] = slice[0].wrapping_add(1);
                std::hint::black_box(&v);
                // v drops here - rapid free
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
