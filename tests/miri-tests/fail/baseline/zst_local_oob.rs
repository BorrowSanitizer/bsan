//@run:1
fn main() {
    // make sure ZST locals cannot be accessed
    let x = &() as *const () as *const i8;
    let _val = unsafe { *x }; //miri: ~ ERROR: attempting to access 1 byte
}
