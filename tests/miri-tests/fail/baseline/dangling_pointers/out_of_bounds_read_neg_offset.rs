//@run:1
fn main() {
    let v: Vec<u16> = vec![1, 2];
    // This read is also misaligned. We make sure that the OOB message has priority.
    let x = unsafe { *v.as_ptr().wrapping_byte_sub(6) }; //miri: ~ ERROR: before the beginning of the allocation
    panic!("this should never print: {}", x);
}
