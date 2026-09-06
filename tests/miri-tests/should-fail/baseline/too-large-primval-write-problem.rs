//@run:0
// `PrimVal`s in Miri are represented with 8 bytes (u64) and at the time of writing, the `-x`
// will sign extend into the entire 8 bytes. Then, if you tried to write the `-x` into
// something smaller than 8 bytes, like a 4 byte pointer, it would crash in byteorder crate
// code that assumed only the low 4 bytes would be set. Actually, we were masking properly for
// everything except pointers before I fixed it, so this was probably impossible to reproduce on
// 64-bit.
//
// This is just intended as a regression test to make sure we don't reintroduce this problem.

// This test was originally only used for 32-bit architectures in Miri. We modified it as a 64-bit
// test case, which should fail if pointer to integer conversion is modelled properly.
#![allow(integer_to_ptr_transmutes)]
fn main() {
    use std::mem::transmute;

    // Make the weird PrimVal.
    let x = 1i32;
    let bad = unsafe { transmute::<i32, *const u8>(-x) };

    // Force it through the Memory::write_primval code.
    drop(Box::new(bad));
}
