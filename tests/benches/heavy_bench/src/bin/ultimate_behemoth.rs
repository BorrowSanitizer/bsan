use std::collections::LinkedList;
use std::thread;

unsafe extern "C" {
    fn __bsan_clear_nodes_rust(ptr: *mut u8);
}

fn node_clearing_enabled() -> bool {
    std::env::var("BSAN_CLEAR_NODES")
        .map(|v| v != "0")
        .unwrap_or(true)
}

#[inline(never)]
fn call_gc_with_root(ptr: *mut u8) {
    if node_clearing_enabled() {
        unsafe {
            __bsan_clear_nodes_rust(ptr);
        }
    }
}

fn main() {
    let num_threads = 4;
    let small_objects_per_thread = 50;
    let big_tree_size = 300;

    let mut handles = vec![];
    for _ in 0..num_threads {
        handles.push(thread::spawn(move || {
            // 1. Lots of small trees
            // Creates 2,000 separate `Tree` instances (one for each Box)
            // Stresses the `ShadowHeap` mapping and global `RwLock` in `snapshots`
            let mut small_trees = LinkedList::new();
            for i in 0..small_objects_per_thread {
                let mut b = Box::new([0u8; 16]);
                b[0] = (i % 255) as u8;
                std::hint::black_box(b[0]);
                small_trees.push_back(b);
            }

            // 2. One Big Tree
            // Creates a single large `Tree` instance but with 10,000 disjoint mutable borrows!
            // This tests the `RangeMap` algorithmic complexity (BTreeMap vs Flat Vec).
            let mut big_chunk = vec![0u8; big_tree_size].into_boxed_slice();

            // We split it into `big_tree_size` independent mutable borrows
            // To do this dynamically in Rust without recursion or `split_at_mut` loops,
            // we can use raw pointers to simulate many disjoint &mut regions,
            // which triggers bsan to record them.
            // Actually, we can just iterate and take a slice of 1 byte each time.
            let mut refs = Vec::with_capacity(big_tree_size);

            // A safer way to create disjoint borrows to stress the Tree
            // is `split_at_mut`. We can slice off 1 byte iteratively.
            let mut remainder = &mut *big_chunk;
            for i in 0..big_tree_size {
                let (first, rest) = remainder.split_at_mut(1);
                first[0] = 42;
                std::hint::black_box(first[0]);
                // Keep the borrow alive
                let ptr = first.as_mut_ptr();
                refs.push(ptr);
                remainder = rest;

                if i > 0 && i % 50 == 0 {
                    let old_len = refs.len();
                    let new_len = old_len / 2;
                    for r in &mut refs[new_len..old_len] {
                        *r = std::ptr::null_mut();
                    }
                    refs.truncate(new_len);
                    call_gc_with_root(remainder.as_mut_ptr());
                }
            }

            // Keep everything alive until the end
            std::hint::black_box(small_trees);
            std::hint::black_box(big_chunk);
            std::hint::black_box(refs);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
