#![allow(unused)]

fn main() {
    let x = 42;
    let rx = &x;

    let px = rx as *const i32;

    let mx = cast_to_mut(px);

    change(mx, 12);

    println!("Value of x (via ptr) {}", unsafe { *mx });
}

fn change(ptr: *mut i32, n: i32) {
    unsafe { *ptr = n };
}

fn cast_to_mut(ptr: *const i32) -> *mut i32 {
    ptr as *mut i32
}
