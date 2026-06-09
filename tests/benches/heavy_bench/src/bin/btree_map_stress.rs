//! BTreeMap with string values
//!
//! Complex node layout, pointer-heavy, many small allocs.

use std::collections::BTreeMap;
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

            // === BTreeMap with string values (200 entries) ===
            // Complex node layout, pointer-heavy, many small allocs
            let mut btree = BTreeMap::new();
            for i in 0..200 {
                btree.insert(i, format!("thread_{}_value_{}", tid, i));
            }
            // Mutate values (retags on internal B-tree nodes if instrumented)
            for (_, v) in btree.iter_mut() {
                v.push('!');
                std::hint::black_box(&v);
            }
            // Remove half (exercises deallocation paths)
            for i in (0..200).step_by(2) {
                btree.remove(&i);
            }
            drop(btree);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
