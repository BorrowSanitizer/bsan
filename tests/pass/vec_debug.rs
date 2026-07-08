//@run:0
//@rustc-env: BSAN_OPTIONS=retags_per_gc=0

#[path = "../utils/mod.rs"]
#[macro_use]
mod utils;

const N: usize = 5;

fn main() {
    let mut v = Vec::new();

    nodes!(v.as_mut_ptr());
    tree!(v.as_mut_ptr());

    for i in 0..N {
        v.push(i);
        nodes!(v.as_mut_ptr());
        tree!(v.as_mut_ptr());
    }
    
    for i in 0..v.len() {
        nodes!(v.as_mut_ptr());
        if v[i] == 0 {
            tree!(v.as_ptr());
        } 
    }

    for _ in 0..v.len() {
        v.pop();
        nodes!(v.as_mut_ptr());
        tree!(v.as_mut_ptr());
    }
}
