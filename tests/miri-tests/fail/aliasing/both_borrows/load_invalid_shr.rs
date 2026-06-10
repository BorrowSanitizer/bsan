//@run:1
//miri: @revisions: stack tree
//miri: @[tree]compile-flags: -Zmiri-tree-borrows
// Make sure we catch this even without validation
//miri: @compile-flags: -Zmiri-disable-validation

// Make sure that we cannot load from memory a `&` that got already invalidated.
fn main() {
    let x = &mut 42;
    let xraw = x as *mut _;
    let xref = unsafe { &*xraw };
    let xref_in_mem = Box::new(xref);
    unsafe { *xraw = 42 }; // unfreeze
    let _val = *xref_in_mem; //miri: ~[tree]| ERROR: /reborrow through .* is forbidden/
    //miri: ~[stack]^ ERROR: /retag .* tag does not exist in the borrow stack/
    
}
