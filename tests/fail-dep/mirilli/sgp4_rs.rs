//@run:1
// This is adapted from `test_negative_time_propagation` in sgp4-rs at version 0.4.0
use sgp4_rs::*;

fn main() {
    let line1 = "1 25544U 98067A   20148.21301450  .00001715  00000-0  38778-4 0  9992";
    let line2 = "2 25544  51.6435  92.2789 0002570 358.0648 144.9972 15.49396855228767";

    let _ = TwoLineElement::new(line1, line2).unwrap();
}