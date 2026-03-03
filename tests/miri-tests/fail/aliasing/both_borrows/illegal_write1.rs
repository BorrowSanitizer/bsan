//@run:1
//miri: @revisions: stack tree
//miri: @[tree]compile-flags: -Zmiri-tree-borrows

#![allow(invalid_reference_casting)]

fn main() {
    let target = Box::new(42); // has an implicit raw
    let xref = &*target;
    {
        let x: *mut u32 = xref as *const _ as *mut _;
        unsafe { *x = 42 };
        //miri: ~[stack]^ ERROR: /write access .* tag only grants SharedReadOnly permission/
        //miri: ~[tree]| ERROR: /write access through .* is forbidden/
    }
    let _x = *xref;
}
