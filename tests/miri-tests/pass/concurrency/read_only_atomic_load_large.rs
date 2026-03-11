//@run:0
// Should not rely on the aliasing model for its failure.
//miri: @compile-flags: -Zmiri-disable-stacked-borrows
// Needs atomic accesses larger than the pointer size
//miri: @ignore-bitwidth: 64
//miri: @ignore-target: mips-

use std::sync::atomic::{AtomicI64, Ordering};

#[repr(align(8))]
struct AlignedI64(#[allow(dead_code)] i64);

fn main() {
    static X: AlignedI64 = AlignedI64(0);
    let x = &X as *const AlignedI64 as *const AtomicI64;
    let x = unsafe { &*x };
    // Some targets can implement atomic loads via compare_exchange, so we cannot allow them on
    // read-only memory.
    x.load(Ordering::Relaxed); //miri: ~ERROR: cannot be performed on read-only memory
}
