//@run:1
//miri: @compile-flags: -Zmiri-tree-borrows -Zmiri-permissive-provenance
// We need to disable debug assertions because raw pointer dereferences trigger
// nullness and alignment checks, which use ptrtoint, which exposes provenance.
//@compile-flags: -Cdebug-assertions=no
/// Checks that with only one exposed reference, wildcard accesses
/// correctly cause foreign accesses.
pub fn main() {
    let mut x: u32 = 42;

    let ptr_base = &mut x as *mut u32;
    let ref1 = unsafe { &mut *ptr_base };
    let ref2 = unsafe { &mut *ptr_base };

    let int1 = ref1 as *mut u32 as usize;
    let wild = int1 as *mut u32;

    //    ┌────────────┐
    //    │            │
    //    │  ptr_base  ├───────────┐
    //    │            │           │
    //    └──────┬─────┘           │
    //           │                 │
    //           │                 │
    //           ▼                 ▼
    //    ┌────────────┐     ┌───────────┐
    //    │            │     │           │
    //    │ ref1(Res)* │     │ ref2(Res) │
    //    │            │     │           │
    //    └────────────┘     └───────────┘

    // Write through the wildcard to the only exposed reference ref1,
    // disabling ref2.
    unsafe { wild.write(13) };

    let _fail = *ref2; //miri: ~ ERROR: /read access through .* is forbidden/
}
