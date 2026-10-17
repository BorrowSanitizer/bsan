//@run: 1
#[repr(C, packed)]
struct Unaligned(*const u8);

fn main() {
    let mut buf = [0u64; 3];
    let b = buf.as_mut_ptr().cast::<u8>();
    unsafe {
        let a = Box::new(1u8);
        // `p` begins 4 bytes into the second slot.
        (*b.add(12).cast::<Unaligned>()).0 = &*a;
        // Overwrites bytes [8, 12), which share a slot with `p`, but not `p`.
        b.add(8).cast::<u32>().write(0);
        let p = (*b.add(12).cast::<Unaligned>()).0;
        drop(a);
        std::hint::black_box(*p);
    }
}
