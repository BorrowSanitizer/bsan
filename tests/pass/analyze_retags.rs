//@run:0
extern "C" {
    fn __bsan_debug_tree_size(ptr: *mut u8);
    fn __bsan_debug_print_borrow_state(ptr: *mut u8);
    fn __bsan_debug_snapshot(ptr: *mut u8);
    fn __bsan_debug_print_diff(ptr: *mut u8);
}

fn snapshot(ptr: *mut i32) {
    unsafe { __bsan_debug_snapshot(ptr as *mut u8); }
}

fn print_diff(ptr: *mut i32, msg: &str) {
    unsafe {
        println!("--- {} ---", msg);
        __bsan_debug_print_diff(ptr as *mut u8);
        // Update snapshot so next diff is relative to this point
        __bsan_debug_snapshot(ptr as *mut u8);
    }
}

fn main() {
    let mut x = 0;
    let ptr = &mut x as *mut i32;
    
    // Initial snapshot
    snapshot(ptr);
    
    // Let's print state first
    unsafe { __bsan_debug_print_borrow_state(ptr as *mut u8); }
    snapshot(ptr);

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