//@run:0
//miri: @revisions: stack tree
//miri: @[tree]compile-flags: -Zmiri-tree-borrows
fn main() {
    assert_eq!(std::thread::available_parallelism().unwrap().get(), 1);
}
