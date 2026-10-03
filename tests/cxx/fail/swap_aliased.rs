//@run: 1
use cxx_deps as _;

unsafe extern "C" {
    fn swap_aliased(a: &mut i32, b: &mut i32);
}

fn main() {
    let mut value = 1;
    let ptr = &raw mut value;
    unsafe { swap_aliased(&mut *ptr, &mut value) };
    assert_eq!(value, 1);
}
