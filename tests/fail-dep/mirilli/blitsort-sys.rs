//@run:1
// This is a copy of the test `test_sorted` from `blitsort-sys` at version 0.1.0
use blitsort_sys::*;
use std::cmp::Ordering;
use std::ffi::c_void;
use std::mem::size_of;

pub trait BlitSort<T> {
    fn sorted(&mut self);
}

impl<T: Ord> BlitSort<T> for [T] {
    fn sorted(&mut self) {
        unsafe {
            extern "C" fn cmp<T>(a: *const c_void, b: *const c_void) -> i32
            where
                T: Ord,
            {
                unsafe {
                    let a: &T = &*(a as *const T);
                    let b: &T = &*(b as *const T);
                    match a.cmp(b) {
                        Ordering::Equal => 0,
                        Ordering::Greater => 1,
                        Ordering::Less => -1,
                    }
                }
            }
            blitsort(
                self.as_ptr() as *mut c_void,
                self.len(),
                size_of::<T>(),
                Some(cmp::<T>),
            );
        }
    }
}

fn main() {
    let mut array1 = [
        0, 10, 1, 9, 2, 8, 3, 7, 3, 5, 2, 1, 5, 32, 5, 3, 313, 55, 13, 5,
    ];
    let mut array2 = array1.clone();
    array1.sorted();
    array2.sort();
    assert_eq!(array1, array2);
}
