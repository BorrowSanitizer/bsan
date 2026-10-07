//@run:0
// A misaligned copy must move each pointer's provenance along with
// its bytes, instead of copying whole slots (#315). Previously, the stale
// provenance of `q` was copied beneath `p`, causing a false positive.
fn main() {
    let p_alloc = Box::new(0);
    let q_alloc = Box::new(0);

    let p = Box::<u8>::as_ptr(&p_alloc);
    let q = Box::<u8>::as_ptr(&q_alloc);

    let mut src = [0u32; 8];
    let mut dst = [0u32; 8];

    let src_bytes = src.as_mut_ptr().cast::<u8>();
    let dst_bytes = dst.as_mut_ptr().cast::<u8>();

    unsafe {
        src_bytes.add(8).cast::<*const u8>().write(q);
        src_bytes.add(4).cast::<*const u8>().write_unaligned(p);
        std::ptr::copy_nonoverlapping(src_bytes, dst_bytes.add(4), 20);

        let p2 = dst_bytes.add(8).cast::<*const u8>().read();
        assert_eq!(p2, p);
        assert_eq!(*p2, 0);
    }
}
