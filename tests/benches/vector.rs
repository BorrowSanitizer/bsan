#![allow(unused)]

// Pushes 1000 elements and then resizes vector to 0
fn main() {
    let mut v: std::vec::Vec<i32> = Vec::new();

    for _ in 0..1000 {
        v.push(1);
    }

    v.resize(0, 0);

}
