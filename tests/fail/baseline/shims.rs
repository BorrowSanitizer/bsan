//@run:1
extern "Rust" {
    pub fn miri_promise_symbolic_alignment(ptr: *const (), align: usize);
}

#[repr(align(8))]
#[derive(Copy, Clone)]
struct Align8(#[allow(dead_code)] u64);

fn main() {
    let buffer = [0u32; 128]; // get some 4-aligned memory
    let buffer = buffer.as_ptr();
    // "Promising" the alignment down to 1 must not hurt.
    unsafe { miri_promise_symbolic_alignment(buffer.cast(), 1) };
    let _val = unsafe { buffer.read() };
    // Let's find a place to promise alignment 8.
    let align8 = if buffer.addr() % 8 == 0 { buffer } else { buffer.wrapping_add(1) };
    assert!(align8.addr() % 8 == 0);
    unsafe { miri_promise_symbolic_alignment(align8.cast(), 8) };
    // Promising the alignment down to 1 *again* still must not hurt.
    unsafe { miri_promise_symbolic_alignment(buffer.cast(), 1) };
    // Now we can do 8-aligned reads here.
    let _val = unsafe { align8.cast::<Align8>().read() };
    // Make sure we error if the pointer is not actually aligned.
    unsafe { miri_promise_symbolic_alignment(align8.add(1).cast(), 8) };
}