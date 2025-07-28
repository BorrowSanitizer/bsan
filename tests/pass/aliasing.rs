#![allow(unused)]

fn change(ptr: *mut i32, n: i32) {
    unsafe { *ptr = n };
}

fn cast_to_mut(ptr: *const i32) -> *mut i32 {
    ptr as *mut i32
}

// write through a reference with a Frozen permission.
fn frozen_permission_write_through() {
    let root: i32 = 42;
    // Frozen permission (shared ref)

    let ref_shared = &root;

    let ptr = ref_shared as *const i32;

    change(cast_to_mut(ptr), 12);

    println!("{}", ref_shared);
}

// read or write through a reference with Disabled permission.
fn read_write_disabled() {
    let mut root: i32 = 42;

    // get mutable pointer to root
    let ptr = &mut root as *mut i32;

    let reserved = &mut root;

    change(ptr, 12);

    // reserved is now Disabled

    let reserved_ptr = reserved as *mut i32;

    // write
    change(ptr, 16);
    // read
    println!("{}", reserved);
}

fn protect(x: &mut i32, mut closure: impl FnMut()) -> i32 {
    let ptr = x as *mut i32;
    change(ptr, 16);
    closure();
    *x
}

// reborrowing is your friend
unsafe fn invalidate_protection() {
    let mut root: i32 = 42;

    let shared_ref = &root;

    let ptr = shared_ref as *const i32;

    // reborrow pointer into new reference

    let new_ref = &mut *cast_to_mut(ptr);

    let closure = move || {
        *new_ref = 12;
    };

    protect(&mut root, closure);

    println!("{}", root);
}

// Program that works under Tree Borrows but fails under Stacked Borrows
fn reordered_reads() {
    let root: i32 = 42;

    todo!("Implement reordered reads");
}

fn dynamic_range() {
    let mut root: Vec<i32> = vec![1, 2, 3];

    let x = &mut root[0];

    unsafe {
        let y = &*(x as *mut i32).add(2);

        println!("{}", y);
    }
}
/*

Tasks

Trying to write through a reference with a Frozen permission.
Trying to read or write through a reference with a Disabled permission.
Invalidating a "protected" permission
A program that is accepted under Tree Borrows, but not under Stacked Borrows.
*/
fn main() {
    // frozen_permission_write_through();
    read_write_disabled();
    //unsafe { invalidate_protection(); }
    //reordered_reads();
    // dynamic_range();
}
