//@run:1
#![feature(portable_simd)]
use std::simd::*;

fn main() {
    unsafe {
        let vec: &[i8] = &[10, 11, 12, 13, 14, 15, 16, 17, 18];
        let idxs = Simd::from_array([9, 3, 0, 17]);
        let _result = Simd::gather_select_unchecked(&vec, Mask::splat(true), idxs, Simd::splat(0));
        //miri: ~^ERROR: attempting to access 1 byte
    }
}
