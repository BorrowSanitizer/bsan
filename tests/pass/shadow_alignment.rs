//@run: 0
#![allow(unused)]
use std::ptr;

fn main() {
    packed_struct();
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct Skewed {
    head: u32,        // offset 0
    p: *const u8,     // offset 4  -- straddles granules 0 and 1
    tail: u32,        // offset 12
}

#[repr(C, align(8))]
struct Buf(Skewed);


fn packed_struct() {
    let p_alloc = Box::new(1u8);
    let q_alloc = Box::new(2u8);
    let p: *const u8 = &*p_alloc;
    let q: *const u8 = &*q_alloc;

    let mut src_box = Box::new([0u64; 3]);
    let mut dst_box = Box::new(Buf(Skewed { head: 0, p: ptr::null(), tail: 0 }));

    let src = (&raw mut *src_box).cast::<u8>();
    let dst = &raw mut *dst_box;
    let dst_bytes = dst.cast::<u8>();

    unsafe {
        src.cast::<*const u8>().write(q);
        //   SRC:
        //        main: | q | q |   |   |
        //      shadow: |   q   |   |   |

        (*dst).0.p = p;
        //   DST:
        //        main: |   | p | p |   |
        //      shadow: |   p   |   |   |

        ptr::copy_nonoverlapping(src, dst_bytes, 4);

        //   DST:
        //        main: | q | p | p |   |
        //      shadow: |   q   |   |   |
        //                    ^   ^

        let p2 = (*dst).0.p;
        assert_eq!(p2, p);
        assert_eq!(*p2, 1);
    }
}