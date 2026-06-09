//! Comprehensive allocator stress test - BSAN-safe.
//!
//! Tests 5 allocation patterns across 8 synchronized threads.
//! No cross-container element transfers or mid-iteration removals
//! that might trigger BSAN false positives.

use std::collections::{BTreeMap, HashMap, LinkedList, VecDeque};
use std::sync::{Arc, Barrier};
use std::thread;

fn main() {
    let num_threads = 8;
    let barrier = Arc::new(Barrier::new(num_threads));

    let mut handles = vec![];
    for tid in 0..num_threads {
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();

            // === Phase 1: Rapid alloc/free cycling with varied sizes ===
            for i in 0..50 {
                let size = match i % 5 {
                    0 => 16,
                    1 => 64,
                    2 => 256,
                    3 => 1024,
                    _ => 4096,
                };
                let mut v: Vec<u8> = vec![0u8; size];
                v[0] = (tid as u8).wrapping_add(i as u8);
                if size > 1 {
                    v[size - 1] = 0xFF;
                }
                let slice = &mut v[..];
                slice[0] = slice[0].wrapping_add(1);
                std::hint::black_box(&v);
                // v drops here
            }

            // === Phase 2: LinkedList - fragmented node allocations ===
            let mut list = LinkedList::new();
            for i in 0..50usize {
                list.push_back(vec![i as u8; 32]);
            }
            for item in list.iter_mut() {
                item[0] = item[0].wrapping_add(1);
                std::hint::black_box(&*item);
            }
            drop(list);

            // === Phase 3: BTreeMap - complex B-tree node allocations ===
            let mut btree = BTreeMap::new();
            for i in 0..50 {
                btree.insert(i, format!("t{}_v{}", tid, i));
            }
            for (_, v) in btree.iter_mut() {
                v.push('!');
                std::hint::black_box(&*v);
            }
            drop(btree);

            // === Phase 4: HashMap - hash table resize allocations ===
            let mut hmap = HashMap::new();
            for i in 0..50 {
                hmap.insert(i, vec![i as u8; 64]);
            }
            for (_, v) in hmap.iter_mut() {
                v[0] = v[0].wrapping_add(1);
                std::hint::black_box(&*v);
            }
            drop(hmap);

            // === Phase 5: VecDeque - ring buffer allocations ===
            let mut deque = VecDeque::new();
            for i in 0..50 {
                deque.push_back(vec![0u8; 48]);
                std::hint::black_box(deque.back().unwrap());
                if i > 0 {
                    // Access front too
                    std::hint::black_box(deque.front().unwrap());
                }
            }
            drop(deque);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
