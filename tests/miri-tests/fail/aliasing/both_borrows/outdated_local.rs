//@run:1
//miri: @revisions: stack tree
//miri: @[tree]compile-flags: -Zmiri-tree-borrows

fn main() {
    let mut x = 0;
    let y: *const i32 = &x;
    x = 1; // this invalidates y by reactivating the lowermost uniq borrow for this local

    assert_eq!(unsafe { *y }, 1);
    //miri: ~[stack]^ ERROR: /read access .* tag does not exist in the borrow stack/
    //miri: ~[tree]| ERROR: /read access through .* is forbidden/

    assert_eq!(x, 1);
}
