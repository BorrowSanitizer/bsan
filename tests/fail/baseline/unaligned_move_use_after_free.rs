//@run: 1
// An overlapping move that shifts a pointer within its slot keeps
// its provenance, so a use-after-free through it is detected (#315).
#[repr(C, packed)]
struct Unaligned(*const u8);

fn main() {
    let mut buf = [0u64; 3];
    let b = buf.as_mut_ptr().cast::<u8>();
    unsafe {
        let a = Box::new(1u8);
        b.cast::<*const u8>().write(&*a);
        std::ptr::copy(b, b.add(3), 8);
        let p = (*b.add(3).cast::<Unaligned>()).0;
        drop(a);
        std::hint::black_box(*p);
    }
}
