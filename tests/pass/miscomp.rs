//@run:0
// This tiny little example triggered an assertion within LLVM,
// causing compilation to fail. It's because we separate the
// process of determining when to insert a run-time check from
// inserting the checks themselves. The provenance associated with
// a given location became desynchronized with the check. If an 
// allocation has multiple lifetimes, which is the case for `i`
// in this loop, then when we instrumented `i`, we used the provenance
// of its last lifetime, which is not valid for every check.
fn main() {
    let mut i = 0;
    while i < 2 {
        std::hint::black_box(&mut 0u64);
        i += 1;
    }
}