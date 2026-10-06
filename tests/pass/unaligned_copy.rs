//@run:0
// Copies that shift pointers relative to their provenance slots (#315).
use std::ptr;

// We read through a packed field, instead of `read_unaligned`, which
// passes the pointer as an integer and loses its provenance.
#[repr(C, packed)]
struct Unaligned(*const u8);

unsafe fn read_ptr(at: *const u8) -> *const u8 {
    unsafe { (*at.cast::<Unaligned>()).0 }
}

// Copies an aligned pointer to an address that is `shift` bytes past
// the start of a slot.
fn shifted_copy(shift: usize) {
    let a = Box::new(shift as u8);
    let mut src = [0u64; 3];
    let mut dst = [0u64; 4];
    let s = src.as_mut_ptr().cast::<u8>();
    let d = dst.as_mut_ptr().cast::<u8>();
    unsafe {
        s.add(8).cast::<*const u8>().write(&*a);
        ptr::copy_nonoverlapping(s, d.add(shift), 24);
        let p = read_ptr(d.add(8 + shift));
        assert_eq!(*p, shift as u8);
    }
}

// A copy must not change provenance outside of the bytes that it writes.
fn copy_preserves_untouched_slots() {
    let q = Box::new(1u8);
    let r = Box::new(2u8);
    let mut src = [0u64; 3];
    let mut dst = [0u64; 2];
    let s = src.as_mut_ptr().cast::<u8>();
    let d = dst.as_mut_ptr().cast::<u8>();
    unsafe {
        s.add(8).cast::<*const u8>().write(&*q);
        d.add(8).cast::<*const u8>().write(&*r);
        // Writes only the first 8 bytes of `dst`.
        ptr::copy_nonoverlapping(s.add(4), d, 8);
        let r2 = d.add(8).cast::<*const u8>().read();
        assert_eq!(*r2, 2);
    }
}

// An overlapping move that shifts a pointer within its slot.
fn overlapping_move() {
    let a = Box::new(3u8);
    let mut buf = [0u64; 3];
    let b = buf.as_mut_ptr().cast::<u8>();
    unsafe {
        b.cast::<*const u8>().write(&*a);
        ptr::copy(b, b.add(3), 8);
        let p = read_ptr(b.add(3));
        assert_eq!(*p, 3);
    }
}

fn main() {
    for shift in 0..8 {
        shifted_copy(shift);
    }
    copy_preserves_untouched_slots();
    overlapping_move();
}
