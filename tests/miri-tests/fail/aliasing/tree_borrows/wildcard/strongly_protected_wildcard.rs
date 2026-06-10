//@run:1
//miri: @compile-flags: -Zmiri-tree-borrows -Zmiri-permissive-provenance
//miri: @error-in-other-file: /deallocation through .* is forbidden/
// We need to disable debug assertions because raw pointer dereferences trigger
// nullness and alignment checks, which use ptrtoint, which exposes provenance.
//@compile-flags: -Cdebug-assertions=no
fn inner(x: &mut i32, f: fn(usize)) {
    // `f` may mutate, but it may not deallocate!
    // `f` takes a raw pointer so that the only protector
    // is that on `x`
    f(x as *mut i32 as usize)
}

fn main() {
    inner(Box::leak(Box::new(0)), |raw| {
        drop(unsafe { Box::from_raw(raw as *mut i32) });
    });
}
