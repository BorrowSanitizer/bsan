//@run: 1
fn main() {
    let x = 1;
    let rx = &x;
    foo(rx as *const i32);
}

fn foo(ptr: *const i32) {
    unsafe { *(ptr as *mut i32) = 1 };
}