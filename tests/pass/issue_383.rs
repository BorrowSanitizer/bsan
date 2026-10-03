//@compile-flags: -Copt-level=3
//@run:0
// SimplifyCFG used to merge a protected function-entry retag in `try_parse_digits`
// with an unprotected retag in its loop body, which leaked the protector.
fn main() {
    String::from("1.3").parse::<f64>().unwrap();
}
