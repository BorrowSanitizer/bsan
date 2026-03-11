//@run:0
fn main() {
    fn panic<T>() -> T {
        panic!()
    }
    // Ensure all memory gets deallocated on a panic: the `Box` we construct, and the `Box`
    // constructed inside `vec!` to eventually turn into a `Vec`.
    std::panic::catch_unwind(|| {
        let _v = vec![Box::new(0), panic()];
    })
    .unwrap_err();
}