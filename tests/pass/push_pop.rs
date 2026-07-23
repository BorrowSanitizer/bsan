//@run:0
//@rustc-env: BSAN_OPTIONS=visits_per_gc=0
#[path = "../utils/mod.rs"]
#[macro_use]
mod utils;

fn main() {
    let mut v: Vec<i64> = Vec::new();
    tree!(v.as_mut_ptr());

    for _ in 0..5 {
        v.push(0);
    }

    for elem in v.iter_mut() {
        tree!(&raw mut *elem)
    }

    for _ in 0..v.len() {
        v.pop();
    }
}
