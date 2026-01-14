extern "C" {
    fn __bsan_debug_tree_size(ptr: *mut u8);
    fn __bsan_debug_print_borrow_state(ptr: *mut u8);
    fn __bsan_debug_snapshot(ptr: *mut u8);
    fn __bsan_debug_print_diff(ptr: *mut u8);
}

/*
fn print_size(ptr: *mut i32, msg: &str) {
    unsafe {
        println!("--- {} ---", msg);
        __bsan_debug_tree_size(ptr as *mut u8);
    }
}
*/

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

fn foo(x: &mut i32) {
    print_diff(x as *mut _, "Inside foo");
}

fn bar(x: &mut i32) {
    print_diff(x as *mut _, "Inside bar (start)");
    foo(x);
    print_diff(x as *mut _, "Inside bar (end)");
}

//@run
fn main() {
    let mut x = 0;
    let ptr = &mut x as *mut i32;
    
    // Initial snapshot
    snapshot(ptr);
    print_diff(ptr, "Initial"); // Should be empty? or just initial state if snapshot was empty before?
    // Wait, snapshot puts current state into snapshot.
    // So diff(current, snapshot) == empty.
    
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

    foo(&mut x);
    print_diff(ptr, "After foo");

    bar(&mut x);
    print_diff(ptr, "After bar");
}
