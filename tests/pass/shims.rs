//@run:0
extern "Rust" {
    pub fn miri_promise_symbolic_alignment(ptr: *const (), align: usize);
}

fn main() {
    let x: i32 = 0;
    unsafe {
        miri_promise_symbolic_alignment((&raw const x).cast::<()>(), 4);
    }
}