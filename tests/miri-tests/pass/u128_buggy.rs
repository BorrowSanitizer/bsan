//@run:0
use std::hint::black_box as b;

fn main() {
    let z: u128 = 0xABCD_EF;
    assert_eq!((z as f64) as u128, z);
}
