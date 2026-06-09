//! Comprehensive allocator stress test.
//!
//! This program is designed to stress-test allocation patterns that would
//! reveal differences between allocators:
//!
//! 1. Rapid alloc/free cycling (throughput)
//! 2. Mixed-size allocations (fragmentation)
//! 3. High thread contention (lock contention)  
//! 4. Producer-consumer handoff (cross-thread freeing)
//!
//! Run with and without BSAN instrumentation to isolate allocator vs
//! instrumentation overhead.

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
            // Synchronize all threads to maximize contention
            barrier.wait();

            // === Phase 1: Rapid alloc/free cycling (1000 iterations) ===
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

            // === Phase 2: LinkedList fragmentation (500 nodes) ===
            // Each node is a separate heap allocation, maximally fragmented
            let mut list = LinkedList::new();
            for i in 0..500usize {
                list.push_back(vec![i as u8; 32 + (i % 128)]);
            }
            // Walk and mutate (retags on every node if instrumented)
            for item in list.iter_mut() {
                item[0] = item[0].wrapping_add(1);
                std::hint::black_box(&item);
            }
            // Pop from front while pushing to back (reuse pattern)
            for _ in 0..250 {
                if let Some(mut front) = list.pop_front() {
                    front.push(0xAB);
                    list.push_back(front);
                }
            }
            drop(list);

            // === Phase 3: BTreeMap with string values (500 entries) ===
            // Complex node layout, pointer-heavy, many small allocs
            let mut btree = BTreeMap::new();
            for i in 0..500 {
                btree.insert(i, format!("thread_{}_value_{}", tid, i));
            }
            // Mutate values (retags on internal B-tree nodes if instrumented)
            for (_, v) in btree.iter_mut() {
                v.push('!');
                std::hint::black_box(&v);
            }
            // Remove half (exercises deallocation paths)
            for i in (0..500).step_by(2) {
                btree.remove(&i);
            }
            drop(btree);

            // === Phase 4: HashMap (500 entries) ===
            // Tests allocator behavior with hash table resizing
            let mut hmap = HashMap::new();
            for i in 0..500 {
                hmap.insert(format!("key_{}_{}", tid, i), vec![i as u8; 64]);
            }
            for (_, v) in hmap.iter_mut() {
                v[0] = v[0].wrapping_add(1);
                std::hint::black_box(&v);
            }
            drop(hmap);

            // === Phase 5: VecDeque (ring buffer pattern) ===
            // Tests reallocation patterns different from Vec
            let mut deque = VecDeque::with_capacity(16);
            for i in 0..1000 {
                deque.push_back(vec![0u8; 48 + (i % 200)]);
                if deque.len() > 100 {
                    let popped = deque.pop_front().unwrap();
                    std::hint::black_box(popped);
                }
            }
            drop(deque);

            // === Phase 6: Deep nesting (stress tree borrows depth) ===
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
