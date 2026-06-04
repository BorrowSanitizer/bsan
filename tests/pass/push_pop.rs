//@run:0
extern "C" {
    fn __bsan_init();
    fn __bsan_deinit();

    fn __bsan_debug_print(ptr: *mut u8);

    fn __bsan_debug_print_borrow_state(ptr: *mut u8);
}

fn main() {
    let mut v: Vec<i64> = Vec::new();

    let p: *mut i64 = v.as_mut_ptr();
    let pv: *mut u8 = p as *mut u8;

    unsafe { __bsan_debug_print_borrow_state(pv) };

    for _ in 0..5 {
        v.push(0);
    }

    // print out each element's tree ptr
    for elem in v.iter_mut() {
        let p: *mut i64 = &raw mut *elem;
        let pv: *mut u8 = p as *mut u8;

        unsafe { __bsan_debug_print_borrow_state(pv) };
    }

    for _ in 0..v.len() {
        v.pop();
    }
}
