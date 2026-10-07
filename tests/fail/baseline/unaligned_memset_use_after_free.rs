//@run: 1
// A memset that ends just before an unaligned pointer, within the same
// slot, must not clear that pointer's provenance, so a use-after-free
// through it is still detected (#315).
#[repr(C, packed)]
struct Unaligned(*const u8);

fn main() {
    let mut buf = [0u64; 3];
    let b = buf.as_mut_ptr().cast::<u8>();
    unsafe {
        let a = Box::new(1u8);
        // `p` begins 4 bytes into the second slot.
        (*b.add(12).cast::<Unaligned>()).0 = &*a;
        // Overwrites bytes [0, 12), which share a slot with `p`, but not `p`.
        std::ptr::write_bytes(b, 0, std::hint::black_box(12));
        let p = (*b.add(12).cast::<Unaligned>()).0;
        drop(a);
        std::hint::black_box(*p);
    }
}
