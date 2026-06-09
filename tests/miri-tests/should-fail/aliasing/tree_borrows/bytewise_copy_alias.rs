//@run: 1
//
// FALSE NEGATIVE (tracked by BorrowSanitizer#225).
use rand::seq::SliceRandom;
use core::mem;

fn main() {
    let mut x: i32 = 1;
    let rx = &mut x;
    let ptr_x = rx as *mut i32; // raw pointer carrying unique tag A

    let vx = &mut x; // sibling mutable borrow of the same location
    *vx = 1; // foreign write: disables tag A under Tree Borrows

    unsafe fn memcpy<T>(to: *mut T, from: *const T) {
        let to = to.cast::<mem::MaybeUninit<u8>>();
        let from = from.cast::<mem::MaybeUninit<u8>>();
        let mut indices = (0..mem::size_of::<T>()).collect::<Vec<usize>>();
        // Randomly shuffle the order in which bytes are copied.
        indices.shuffle(&mut rand::rng());
        for i in indices {
            unsafe {
                let b = from.add(i).read();
                to.add(i).write(b);
            }
        }
    }

    let mut ptr2 = core::ptr::null_mut();
    unsafe { memcpy(&mut ptr2, &ptr_x) };
    unsafe { *ptr2 = 0; }
}
