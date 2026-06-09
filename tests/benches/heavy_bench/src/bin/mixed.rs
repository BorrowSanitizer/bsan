use std::thread;

fn main() {
    let num_threads = 8;
    // We want a mix of huge trees and tiny trees.
    // Scaled down to prevent OOM while maintaining representative pattern
    let small_allocs = 4_000 / num_threads;

    let mut handles = vec![];
    for _ in 0..num_threads {
        handles.push(thread::spawn(move || {
            // ONE BIG TREE
            // Allocate a 512KB chunk to serve as a massive tree
            let mut big_chunk: Vec<u8> = vec![0; 512 * 1024];

            // Create a deeply nested set of references over the big chunk
            for i in 0..50 {
                // Borrow smaller and smaller chunks
                let offset = i * 512;
                let size = 1024 * 1024 - (i * 1000);
                if size <= 0 || offset >= big_chunk.len() {
                    break;
                }

                let chunk_len = big_chunk.len();
                let r = &mut big_chunk[offset..(offset + size.min(chunk_len - offset))];
                if r.len() > 0 {
                    r[0] = (i % 256) as u8;
                }
            }

            // MANY SMALL TREES
            for _ in 0..small_allocs {
                // 64 bytes is typical for small structs
                let mut small_chunk: Vec<u8> = vec![0; 64];

                // Just 1-2 borrows per small tree
                let r1 = &mut small_chunk[0..32];
                r1[0] = 1;

                let r2 = &mut r1[0..16];
                r2[0] = 2;

                // Read access
                std::hint::black_box(r2[0]);
                std::hint::black_box(r1[0]);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
