//@run:0
//miri: @revisions: stack tree
//miri: @[tree]compile-flags: -Zmiri-tree-borrows
fn main() {
    vec![()].into_iter();
}
