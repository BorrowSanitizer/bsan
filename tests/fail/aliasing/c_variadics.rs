//@run: 1
fn main() {
    #[inline(never)]
    unsafe extern "C" fn write_with_first_arg(val: i32, mut ap: ...) {
        unsafe {
            *(ap.next_arg::<*mut i32>()) = val;
        }
    }

    let mut x = 1;
    let rx = &mut x;
    let ptr_x = rx as *mut i32;
    let vx = &mut x;
    *vx = 2;
    
    unsafe {
        write_with_first_arg(128, ptr_x);
    }
}