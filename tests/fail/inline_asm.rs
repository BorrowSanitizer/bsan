use std::arch::asm;

extern "C" {
    fn __bsan_debug_print(ptr: *mut u8);
}
//@ revisions: asm-conservative none

// We are conservative by default
// Note: It seems as though passing in flags to LLVM plugins is not supported by rustc due to versioning
// concerns. See https://internals.rust-lang.org/t/should-rustc-support-custom-llvm-plugin/13807
// TODO: Investigate this for future reference
//@ [asm-conservative] compile-flags:
//@ [none] compile-flags: -Z llvm-plugins=~/.rustup/toolchains/bsan/libbsan_plugin.so -C llvm-args="-bsan-asm-conservative=false" -C passes="bsan-pass"
fn main() {
    let x: u64;
    unsafe {
        asm!("mov {}, 67", out(reg) x); // very interesting syntax for the constraints
    }

    // We need to print out it's provenance value to check if it was correctly set to Wildcard
    unsafe {
        __bsan_debug_print(x as *mut u8);
    }
}
