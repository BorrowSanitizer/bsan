//@run:0

fn main() {
    let z: u128 = 0xABCD_EF;
    assert_eq!((z as f64) as u128, z);
}
