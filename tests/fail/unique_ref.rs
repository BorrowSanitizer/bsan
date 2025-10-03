//@run: 1
fn main() {
    let mut x = 1;
    let rx = &mut x;
    let ptr_x = rx as *mut i32;
    let vx = &mut x;
    *vx = 2;
    unsafe {
        *ptr_x = 1;
    }
}
