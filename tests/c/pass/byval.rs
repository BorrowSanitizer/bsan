//@run:0
use c_deps as _;

#[repr(C)]
struct Big {
    ptr: *const u64,
    pad: [u64; 2],
}


// Leaves the provenance of `x` in the first parameter slot.
#[inline(never)]
fn stale(x: &u8) -> u8 {
    *x
}

fn main() {
    let value = 42u64;
    let unrelated = 0u8;

    stale(&unrelated);
    // In LLVM, the function `read_byval` will be passed the 
    // struct Big `byval` as an array of bytes `[24 x i8]`.
    // In C, it will be received as `{ ptr, [2 x i64] }`.
    // Unless boundary validation kicks in, we will read a stale
    // provenance value created by passing `&unrelated` above. 
    // The body of `read_byval` reads a `u64`, which will trigger
    // an access out-of-bounds. 
    assert_eq!(unsafe { read_byval(Big { ptr: &value, pad: [0; 2] }) }, 42);

    stale(&unrelated);
    assert_eq!(unsafe { rust_read_byval(Big { ptr: &value, pad: [0; 2] }) }, 42);
}

unsafe extern "C" {
    fn read_byval(b: Big) -> u64;
}

#[inline(never)]
unsafe extern "C" fn rust_read_byval(b: Big) -> u64 {
    return *b.ptr;
}
