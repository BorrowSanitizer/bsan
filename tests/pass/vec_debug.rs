extern "C" {
    fn __bsan_init();
    fn __bsan_deinit();

    fn __bsan_debug_print(ptr: *mut u8);

    fn __bsan_debug_print_borrow_state(ptr: *mut u8);
    fn __bsan_debug_gc(ptr: *mut u8);
    fn __bsan_debug_tree_size(ptr: *mut u8);
}

//@run
fn main() {
    let mut v: Vec<i64> = Vec::new();

    let p: *mut i64 = v.as_mut_ptr();
    let pv: *mut u8 = p as *mut u8;

    unsafe { __bsan_debug_tree_size(pv) };
    unsafe { __bsan_debug_print_borrow_state(pv) };

    for i in 0..5 {
        v.push(i);
        let p: *mut i64 = v.as_mut_ptr();
        let pv: *mut u8 = p as *mut u8;
        unsafe { __bsan_debug_tree_size(pv) };
        unsafe { __bsan_debug_print_borrow_state(pv) };
    }

    // print out each element's tree ptr
    for elem in v.iter_mut() {
        let p: *mut i64 = &raw mut *elem;
        let pv: *mut u8 = p as *mut u8;
        // Should be same tree
        unsafe { __bsan_debug_tree_size(pv) };
        // We only print tree size here to avoid too much output, but let's print state for the first element
        if *elem == 0 {
             unsafe { __bsan_debug_print_borrow_state(pv) };
        }
    }

    let p: *mut i64 = v.as_mut_ptr();
    let pv: *mut u8 = p as *mut u8;
    unsafe { __bsan_debug_tree_size(pv) };
    unsafe { __bsan_debug_print_borrow_state(pv) };

    for _ in 0..v.len() {
        v.pop();
        let p: *mut i64 = v.as_mut_ptr();
        let pv: *mut u8 = p as *mut u8;
        unsafe { __bsan_debug_tree_size(pv) };
        unsafe { __bsan_debug_print_borrow_state(pv) };
    }
    
    let p: *mut i64 = v.as_mut_ptr();
    let pv: *mut u8 = p as *mut u8;
    unsafe { __bsan_debug_tree_size(pv) };
    unsafe { __bsan_debug_print_borrow_state(pv) };
}
