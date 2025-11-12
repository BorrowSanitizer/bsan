use std::thread;
const NTHREADS: u32 = 5;

// This is the `main` thread
fn main() {
    // Make a vector to hold the children which are spawned.
    let mut children = vec![];

    for i in 0..NTHREADS {
        // Spin up another thread
        children.push((
            i,
            thread::spawn(move || {
                println!("thread");
            }),
        ));
    }

    for (_i, child) in children {
        // Wait for the thread to finish. Returns a result.
        let _ = child.join();
    }
}
