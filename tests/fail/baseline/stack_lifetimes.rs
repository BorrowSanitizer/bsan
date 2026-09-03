//@run:1

use std::ptr;

fn main() {
    let mut stash: *mut u64 = ptr::null_mut();
    let mut i: u32 = 0;
    let mut _acc: u64 = 0;
    while i < 2 {
        // This variable has a new lifetime for
        // each iteration of the loop. Semantically,
        // this means that the pointer in iteration i
        // must be invalid for iteration i+1.
        let mut slot: u64 = 0xAAAA_0000 | i as u64;
            
        if !stash.is_null() {
            // Access using a pointer to `slot` that
            // was created during a different lifetime.
            unsafe {
                _acc += *stash; // UB!
            }
        }
        // Store a pointer to `slot`, which will be
        // dereferenced on the next iteration.
        stash = &raw mut slot;
        i += 1;
    }
}