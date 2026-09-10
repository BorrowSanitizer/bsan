//@run:1
#[allow(deref_nullptr)]
fn main() {
    unsafe { *std::ptr::null_mut() = 0i32 }; //miri: ~ ERROR: null pointer
}
