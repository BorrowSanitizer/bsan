//@run:1
use libc::{c_void, qsort};

extern "C" fn cmp(a: *const c_void, b: *const c_void) -> i32 {
    unsafe { **(a as *const *const i32) - **(b as *const *const i32) }
}

fn main() {
    let (x, y, z) = (1, 3, 2);
    let mut v = [&x as *const i32, &y, &z];

    // qsort is uninstrumented. each element of the
    // input array is copied in-place without copying 
    // its shadow, leading to a false positive access 
    // out-of-bounds. 
    unsafe { qsort(v.as_mut_ptr().cast(), 3, 8, Some(cmp)) };

    println!("{:?}", v.map(|p| unsafe { *p }));
}