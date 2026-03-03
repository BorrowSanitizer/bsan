//@run: 1
fn main() {
    let mut x = Box::new(42);
    let ptr = x.as_mut() as *mut i32;
    let r1 = unsafe { &mut *ptr };
    let r2 = unsafe { &mut *ptr };
    *r2 += 1;
    std::hint::black_box(r1);
    println!("{}", *r2);

    println!("aliasing bug not detected");
}