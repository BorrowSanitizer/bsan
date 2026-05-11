fn main() {
    println!("Hello, BorrowSanitizer!");
}

#[test]
fn default() {
    assert!(true)
}


// We add in UB that would otherwise
// be detected.
#[test]
#[cfg(feature = "nop")]
fn nop() {
    let mut x = 1;
    let rx = &mut x;
    let ptr_x = rx as *mut i32;
    let vx = &mut x;
    *vx = 2;
    unsafe {
        *ptr_x = 1;
    }
}