use std::thread;

fn main() {
    let num_threads = 16;
    let allocs_per_thread = 1_000;

    let mut handles = vec![];
    for _ in 0..num_threads {
        handles.push(thread::spawn(move || {
            // Keep chunks alive to maximize concurrent active objects
            let mut keep = Vec::with_capacity(allocs_per_thread);
            for i in 0..allocs_per_thread {
                let mut chunk = Box::new([0u8; 32]);

                // Create multiple mutable references to force tree borrows
                let r1 = &mut chunk[0..16];
                r1[0] = (i % 255) as u8;

                let r2 = &mut r1[0..8];
                r2[0] = 2;

                let r3 = &mut r2[0..4];
                r3[0] = 3;

                // Force a read access to update the tree state
                let val = r3[0];
                std::hint::black_box(val);

                // Read access on parent
                let val2 = r2[0];
                std::hint::black_box(val2);

                keep.push(chunk);
            }
            std::hint::black_box(keep);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
