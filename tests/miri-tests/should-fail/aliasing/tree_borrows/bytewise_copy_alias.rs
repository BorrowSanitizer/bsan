//@run: 1
//
// FALSE NEGATIVE (tracked by BorrowSanitizer#225).

use std::mem::{size_of, MaybeUninit};

fn main() {
    let mut x: i32 = 67;
    let rx = &mut x;
    let ptr_x = rx as *mut i32; // raw pointer carrying unique tag A

    let vx = &mut x; // sibling mutable borrow of the same location
    *vx = 42; // foreign write: disables tag A under Tree Borrows

    // create an unitiliazed buffer to copy ptr_x value to byte-byte
    let mut buf = MaybeUninit::<*mut i32>::uninit();
    let dst = buf.as_mut_ptr().cast::<u8>();

    // cast to first byte of ptr_x
    let src = (&ptr_x as *const *mut i32).cast::<u8>();
    // loop 4 times (size_of(i32) == 4 bytes)
    for i in 0..size_of::<*mut i32>() {
        unsafe {
            // https://doc.rust-lang.org/std/ptr/fn.read_volatile.html
            // tell the compiler to treat this as a volatile operation so that it does not optimize away our byte-byte copy
            *dst.add(i) = src.add(i).read_volatile();
        }
    }
    let laundered = unsafe { buf.assume_init() };

    // same as ptr_x except ptr reads 0 provenance (omnivalid) due to `__bsan_memcpy` early return
    // when `num_bytes < PTR_BYTES`
    unsafe {
        *laundered = 69;
    }

    println!("aliasing violation through a byte-copied pointer was not detected");
}
