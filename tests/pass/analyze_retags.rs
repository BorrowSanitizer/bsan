//@run:0
//@rustc-env: BSAN_OPTIONS=visits_per_gc=0
#[path = "../utils/mod.rs"]
#[macro_use]
mod utils;

fn print_diff(ptr: *mut i32, msg: &str) {
    println!("--- {} ---", msg);
    diff!(ptr);
    snapshot!(ptr);
}

fn main() {
    let mut x = 0;
    let ptr = &mut x as *mut i32;
    
    // Initial snapshot
    snapshot!(ptr);
    
    // Let's print state first
    tree!(ptr);
    snapshot!(ptr);
    {
        let y = &mut x;
        print_diff(y as *mut _, "After &mut x");
        *y = 1;
    }
    print_diff(ptr, "After scope 1");
    {
        let z = &mut x;
        print_diff(z as *mut _, "After second &mut x");
        *z = 2;
    }
    print_diff(ptr, "After scope 2");
}