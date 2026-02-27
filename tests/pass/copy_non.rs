use std::ptr::copy_nonoverlapping;

//@run
fn main() {
    let mut x = [0u8; 10];
    let src = [1u8; 10];
    unsafe {
        copy_nonoverlapping(src.as_ptr(), x.as_mut_ptr(), 10);
    }
    assert_eq!(x, src);
}