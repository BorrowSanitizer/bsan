//@run: 1
fn main() {
    let mut x = 1;
    let rx = &mut x;
    let ptr_x = rx as *mut i32;
    foo(rx, ptr_x);
}

fn foo(_r: &mut i32, p: *mut i32) {
    unsafe { *p = 1 };
}