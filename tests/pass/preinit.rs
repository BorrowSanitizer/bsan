// Credit: Matt Mastracci (https://github.com/BorrowSanitizer/bsan/issues/345)
static DATA: [u8; 4] = [1, 2, 3, 4];

unsafe extern "C" fn early() {
    let r: &[u8] = &DATA;
    std::hint::black_box(r);
}

#[used]
#[link_section = ".init_array.00000"]
static EARLY: unsafe extern "C" fn() = early;

//@ run
fn main() {
    println!("main");
}