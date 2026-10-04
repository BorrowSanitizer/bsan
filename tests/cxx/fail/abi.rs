//@run: 1
// This test will fail with an aliasing violation if
// we correctly propagate provenance for raw bytes for structs
// that use integer ABI lowerings for pointer fields. 
use cxx_deps as _;

/// The following struct is passed and returned from C++ as a 
/// pair of integers:
/// ```
///     ; Rust emits the following LLVM IR for the callsite
///     ; of `swap_pair` below
///     %5 = load [2 x i64], ptr %2, align 8
///     %6 = call [2 x i64] @swap_pair([2 x i64] %5) #8
///     store [2 x i64] %6, ptr %0, align 8
/// 
///     ; Clang emits the following signature for `@swap_pair`
///     define [2 x i64] @swap_pair([2 x i64] %0)
/// ```
/// This means that we need to treat every unknown integer loaded 
/// from memory as potentially carrying provenance. If Cland and Rust 
/// had support for the byte type, then this would be `[2 x b64]`, so we
/// could special-case this and otherwise avoid having to treat the
/// `[2 x i64]` case as carrying provenance. 

#[repr(C)]
struct Pair {
    first: *mut i32,
    second: *mut i32,
}

unsafe extern "C" {
    fn swap_pair(pair: Pair) -> Pair;
}

fn main() {
    let mut value = 0;
    let mut other = 0;
    let ptr = &raw mut value;
    unsafe {
        let pair = Pair { first: &mut *ptr, second: &mut other };
        let swapped = swap_pair(pair);
        *ptr = 1;
        *swapped.second = 2;
    }
}
