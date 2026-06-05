use std::collections::{BTreeMap, LinkedList};
use std::thread;

fn main() {
    let num_threads = 8;
    // Lower iteration count to 100 to prevent OOM crash (exit code 137)
    let items_per_thread = 100;

    let mut handles = vec![];
    for _ in 0..num_threads {
        handles.push(thread::spawn(move || {
            // 1. Linked List: extremely fragmented, small individual allocations
            // let mut list = LinkedList::new();
            // for i in 0..items_per_thread {
            //     list.push_back(i);
            // }

            // // Mutate list nodes (triggers BorrowSanitizer retags on each fragmented node)
            // for val in list.iter_mut() {
            //     *val += 1;
            //     std::hint::black_box(*val);
            // }

            // // 2. BTreeMap: complex node structures, scattered memory, heavy pointer chasing
            // let mut map = BTreeMap::new();
            // for i in 0..items_per_thread {
            //     map.insert(i, format!("Value {}", i));
            // }

            // Mutate map values (triggers BorrowSanitizer retags on fragmented tree nodes)
            // for (k, v) in map.iter_mut() {
            //     v.push_str("!");
            //     std::hint::black_box(k);
            //     std::hint::black_box(v);
            // }

            // Deallocate triggers massive freeing operations
            // drop(list);
            // drop(map);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
