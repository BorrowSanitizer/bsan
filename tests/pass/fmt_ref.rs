//@run
/// Calling the `Display` implementation for a reference causes a pointer to
/// an instrumented function to be passed into part of `alloc`, which may or may not
/// be instrumented depending on whether our custom sysroot is being used. This
/// test will fail with an access-out-of-bounds (false positive) if we link against an
/// uninstrumented sysroot.
fn main() {
    let x = 1;
    let _ = format!("{}", &x);
}