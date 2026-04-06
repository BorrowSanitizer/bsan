//@run:1
fn main() {
    let v: Vec<u16> = vec![1, 2];
    // Miri uses an offset of 5 here, since OOB takes higher
    // priority then misaligned accesses. However, native checks
    // for alignment take priority over our instrumentation,
    // so we need an aligned offset for this test.
    let x = unsafe { *v.as_ptr().wrapping_byte_sub(6) }; //miri: ~ ERROR: before the beginning of the allocation
    panic!("this should never print: {}", x);
}
