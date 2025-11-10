//@run: 1
use std::ptr::NonNull;

fn main() {
    unsafe {
        let x = &mut 0;
        let mut ptr1 = NonNull::from(x);
        let mut ptr2 = ptr1.clone();
        let raw1 = ptr1.as_mut();
        let raw2 = ptr2.as_mut();
        let _val = *raw1; 
        *raw2 = 2;
        *raw1 = 3; 
    }
}
