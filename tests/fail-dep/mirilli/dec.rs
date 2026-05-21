//@run:1
// This is a copy of the test `test_ordered_decimal128` from `dec` at version 0.4.8

use dec::{OrderedDecimal, Decimal128};
use std::cmp::Ordering;

fn main() -> Result<(), Box<dyn std::error::Error>>{
    let lhs = "NaN";
    let rhs = "1";
    let expected = Ordering::Greater;
    let lhs: OrderedDecimal<Decimal128> = OrderedDecimal(lhs.parse()?);
    let rhs: OrderedDecimal<Decimal128> = OrderedDecimal(rhs.parse()?);
    assert_eq!(lhs.cmp(&rhs), expected);
    Ok(())
}