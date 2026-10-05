//@run: 1
// A pointer stored at an unaligned address keeps its provenance,
// so a use-after-free through it is still detected (#315).
#[repr(C, packed)]
struct Packed {
    pad: u32,
    ptr: *const u8,
}

fn main() {
    // An 8-byte aligned buffer, so `ptr` begins 4 bytes into a slot.
    let mut buf = [0u64; 2];
    let p = buf.as_mut_ptr().cast::<Packed>();
    unsafe {
        let a = Box::new(1u8);
        (*p).ptr = &*a;
        drop(a);
        let x = (*p).ptr;
        std::hint::black_box(*x);
    }
}
