//! LinkedList fragmentation
//!
//! Each node is a separate heap allocation, maximally fragmented, with walkers and mutators.

use std::collections::LinkedList;
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

            // === LinkedList fragmentation (300 nodes) ===
            // Each node is a separate heap allocation, maximally fragmented
            let mut list = LinkedList::new();
            for i in 0..300usize {
                list.push_back(vec![i as u8; 32 + (i % 128)]);
            }
            // Walk and mutate (retags on every node if instrumented)
            for item in list.iter_mut() {
                item[0] = item[0].wrapping_add(1);
                std::hint::black_box(&item);
            }
            // Pop from front while pushing to back (reuse pattern)
            for _ in 0..150 {
                if let Some(mut front) = list.pop_front() {
                    front.push(0xAB);
                    list.push_back(front);
                }
            }
            drop(list);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
