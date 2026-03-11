//@run:1
use std::alloc::{Layout, alloc, dealloc};

fn main() {
    unsafe {
        let x = alloc(Layout::from_size_align_unchecked(1, 1));
        dealloc(x, Layout::from_size_align_unchecked(1, 1));
        dealloc(x, Layout::from_size_align_unchecked(1, 1)); //miri: ~ERROR: has been freed
    }
}
