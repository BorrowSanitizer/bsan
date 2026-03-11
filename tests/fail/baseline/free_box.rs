//@run: 1
fn main() {
    let b = Box::new(1);

    let ptr = Box::into_raw(b);

    unsafe {
        drop(Box::from_raw(ptr));
    }

    unsafe {
        *ptr = 1;
    }
}
