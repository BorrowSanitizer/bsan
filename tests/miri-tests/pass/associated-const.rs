//@run:0
//miri: @revisions: stack tree
//miri: @[tree]compile-flags: -Zmiri-tree-borrows
trait Foo {
    const ID: i32;
}

impl Foo for i32 {
    const ID: i32 = 1;
}

fn main() {
    assert_eq!(1, <i32 as Foo>::ID);
}
