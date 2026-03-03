//@run: 1

fn foo() {
    unsafe {    
        let i = 4;
        let ptr = &i as *const i32 as *mut i32 as *mut i32;
        let b2 = Box::from_raw(ptr);
        println!("before drop");
        drop(b2);
    }
}

fn main() {
    foo();
    println!("after drop");
}