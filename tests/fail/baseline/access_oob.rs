//@run: 1
fn main() {
    let mut x = 1;
    let rx = &mut x;
    let ptr_x = rx as *mut i32;
    foo(ptr_x);
}

fn foo(p: *mut i32) {
    unsafe { p.add(1).write(0) }
}