//@run:1
// This test is adapted from `dec_quad_get_coefficient` in `dec-number-sys` at version 0.0.25
use dec_number_sys::*;

macro_rules! c {
  () => {
    &mut dec_context_128()
  };
}

macro_rules! n {
  ($s:expr) => {
    dec_quad_from_string(stringify!($s), c!())
  };
}

fn main() {
  assert_eq!(0, dec_quad_get_coefficient(&n!(1), &mut bcd_quad(u128::MAX)));
  assert_eq!(-2147483648, dec_quad_get_coefficient(&n!(-1), &mut bcd_quad(u128::MAX)));
}