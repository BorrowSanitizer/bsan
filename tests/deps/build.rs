// build.rs
fn main() {
    println!("cargo:rustc-env=LIBZ_SYS_STATIC=1");
}