//@run:1
//miri: @compile-flags: -Zmiri-permissive-provenance

fn main() {
    let p = 44 as *const i32;
    let x = unsafe { *p }; //miri: ~ ERROR: is a dangling pointer
    panic!("this should never print: {}", x);
}
