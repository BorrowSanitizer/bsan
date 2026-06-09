//@run: 1
//
// FALSE NEGATIVE (tracked by BorrowSanitizer#223).
//
// This program commits a genuine Tree Borrows aliasing violation, but first
// launders the offending pointer through a byte-by-byte copy. An ideal checker
// (and Miri) reports the violation, so the first line marks this as a run-fail test.
// BorrowSanitizer currently does NOT detect it. This file lives under
// `should-fail/` to document that known false negative; it is not part of the
// green CI suite (`tests/ui.rs::main` does not run `should-fail`).
//
// Why this is undefined behavior:
//   `rx = &mut x` creates a unique child tag A of `x`'s tree. `ptr_x` is a raw
//   reborrow that keeps tag A. `vx = &mut x` is a second, sibling mutable
//   borrow; the write `*vx = 2` is a *foreign write* relative to A, which
//   transitions A to `Disabled` under Tree Borrows. A later write through a
//   pointer still carrying tag A is then a child-write on a disabled node ==
//   UB. Without the laundering this is exactly tests/fail/aliasing/unique_ref.rs,
//   which BorrowSanitizer detects.
//
// Why BorrowSanitizer misses it here:
//   Provenance ({ BorTag, *mut AllocInfo }) lives in shadow memory, one word
//   per pointer-sized, pointer-aligned slot. A copy is only carried through
//   shadow memory by `__bsan_memcpy` -> `__bsan_shadow_transfer` ->
//   `ShadowHeap::memcpy`, which early-returns when the length is below one
//   pointer (`num_bytes < PTR_BYTES`, bsan-rt/src/memory/shadow.rs). Copying the
//   pointer one byte at a time never moves a provenance word, so the
//   destination shadow stays zeroed. A zeroed shadow word is the `omnivalid`
//   provenance ({ tag 0, null }); `BorrowTracker::for_access`
//   (bsan-rt/src/borrow_tracker.rs) short-circuits `omnivalid` to `Ok(())` with
//   no tree check, so the disabled-tag write is allowed. Recovering the concrete
//   provenance from a byte-wise copy requires validating the reconstructed
//   `*mut AllocInfo` against real metadata, which needs the concurrent slab
//   allocator from BorrowSanitizer#223 (not yet implemented).
//
// NOTE: the copy MUST stay sub-pointer-width. A single full-width
// `copy_nonoverlapping::<u8>(.., .., 8)` lowers to one pointer-width shadow
// transfer, which WOULD preserve provenance and let BorrowSanitizer catch this.
// `read_volatile` keeps the loop a true per-byte copy the optimizer cannot
// coalesce into a single `memcpy`.

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

    // same as ptr_x except ptr reads 0 provenance (omnivalid) as our __bsan_memcpy will early return
    // when `num_bytes < PTR_BYTES`
    unsafe {
        *laundered = 69;
    }

    println!("aliasing violation through a byte-copied pointer was not detected");
}
