//@run:1
use std::alloc::{Layout, alloc, realloc};

fn main() {
    unsafe {
        let x = alloc(Layout::from_size_align_unchecked(1, 1));
        let _y = realloc(x, Layout::from_size_align_unchecked(1, 1), 1);
        let _z = *x; //miri: ~ ERROR: has been freed
    }
}
