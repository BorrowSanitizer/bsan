//@compile-flags: -Copt-level=3
//@run:0
fn recurse(b: &mut bool) {
    if *b {
    } else {
        *b = true;
        recurse(b)
    }
}

fn recurse_count(b: &mut bool, ct: usize) {
    if *b {
    } else {
        if ct > 0 {
            *b = true;
        }
        recurse_count(b, ct + 1)
    }
}

fn run_recurse() {
    let mut b = false;
    recurse(&mut b);
    b = false;
    std::hint::black_box(&b);
}

fn run_recurse_count() {
    let mut b = false;
    recurse_count(&mut b, 0);
    b = false;
    std::hint::black_box(&b);
}

fn main() {
    run_recurse();
    run_recurse_count();
}