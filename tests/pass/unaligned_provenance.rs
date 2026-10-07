//@run:0
// A pointer stored at an unaligned address keeps its provenance
// when it is loaded back from the same address (#315).
#[repr(C, packed)]
struct Packed {
    pad: u32,
    ptr: *const u8,
}

fn main() {
    let a = Box::new(1u8);
    let b = Box::new(2u8);
    // An 8-byte aligned buffer, so `ptr` begins 4 bytes into a slot.
    let mut buf = [0u64; 2];
    let p = buf.as_mut_ptr().cast::<Packed>();
    unsafe {
        (*p).ptr = &*a;
        let x = (*p).ptr;
        assert_eq!(*x, 1);

        // Overwrite it at the same unaligned address.
        (*p).ptr = &*b;
        let y = (*p).ptr;
        assert_eq!(*y, 2);
    }
}
