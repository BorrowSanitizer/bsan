//@run: 1

fn main() {
    unsafe {
        let ptr = Box::into_raw(Box::new(0u16));
        drop(Box::from_raw(ptr as *mut u32));
    }
}
