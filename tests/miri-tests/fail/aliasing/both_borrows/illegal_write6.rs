//@run:1
//miri: @revisions: stack tree
//miri: @[tree]compile-flags: -Zmiri-tree-borrows

fn main() {
    let x = &mut 0u32;
    let p = x as *mut u32;
    foo(x, p);
}

fn foo(a: &mut u32, y: *mut u32) -> u32 {
    *a = 1;
    let _b = &*a;
    unsafe { *y = 2 };
    //miri: ~[stack]^ ERROR: /not granting access .* because that would remove .* which is strongly protected/
    //miri: ~[tree]| ERROR: /write access through .* is forbidden/
    return *a;
}
