#![allow(unused)]

fn main() {
    let mut v: std::vec::Vec<i32> = Vec::new();

    for _ in 0..1000 {
        v.push(0);
    }

    // Reset vector to 0
    v.resize(0,0);


    // Read vector
    let vx = &v;
}
