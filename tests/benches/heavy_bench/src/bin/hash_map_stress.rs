//! HashMap
//!
//! Tests allocator behavior and retagging with hash table resizing and key/value updates.

use std::collections::HashMap;
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

            // === HashMap (300 entries) ===
            // Tests allocator behavior with hash table resizing
            let mut hmap = HashMap::new();
            for i in 0..300 {
                hmap.insert(format!("key_{}_{}", tid, i), vec![i as u8; 64]);
            }
            for (_, v) in hmap.iter_mut() {
                v[0] = v[0].wrapping_add(1);
                std::hint::black_box(&v);
            }
            drop(hmap);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
