//@run: 1
// A misaligned copy moves a pointer's provenance along with its
// bytes, so a use-after-free through the copy is detected (#315).
#[repr(C, packed)]
struct Unaligned(*const u8);

fn main() {
    let mut src = [0u64; 3];
    let mut dst = [0u64; 4];
    let s = src.as_mut_ptr().cast::<u8>();
    let d = dst.as_mut_ptr().cast::<u8>();
    unsafe {
        let a = Box::new(1u8);
        s.add(8).cast::<*const u8>().write(&*a);
        std::ptr::copy_nonoverlapping(s, d.add(3), 24);
        let p = (*d.add(11).cast::<Unaligned>()).0;
        drop(a);
        std::hint::black_box(*p);
    }
}
