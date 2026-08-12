fn main() {
    let p_alloc = Box::new(0);
let q_alloc = Box::new(0);

let p = Box::<u8>::as_ptr(&p_alloc);
let q = Box::<u8>::as_ptr(&q_alloc);

// Create source and destination arrays that are four words long.
let mut src = [0u32; 8];
let mut dst = [0u32; 8];

let src_bytes = src.as_mut_ptr().cast::<u8>();
let dst_bytes = dst.as_mut_ptr().cast::<u8>();

unsafe {

    src_bytes.add(8).cast::<*const u8>().write(q);

    //   SRC:
    //        main: |   |   | q | q |   |
    //      shadow: |   |   | q | q |   |

    src_bytes.add(4).cast::<*const u8>().write_unaligned(p);

    //   SRC:
    //        main: |   | p | p | q |   |
    //      shadow: | p | p | q | q |   |

    std::ptr::copy_nonoverlapping(src_bytes, dst_bytes.add(4), 20);


    //   DEST:
    //        main: |   |   | p | p | q |
    //      shadow: | p | p | q | q |   |
    //                        ^   ^

    let p2 = dst_bytes.add(8).cast::<*const u8>().read();
    assert_eq!(p2, p);

    println!("{}", *p2);  // False positive UB! We're accessing p using q's provenance.
}
}