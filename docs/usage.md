# Usage
You can manually enable BorrowSanitizer by passing the flag `-Zsanitizer=borrow` to the Rust compiler, like so: 
```
RUSTFLAGS="-Zsanitizer=borrow" cargo build
```
Replace `<host>` with your current target. You can find out what this is executing the command `rustc -vV`. If a crate has doctests, then you will need to enable BorrowSanitizer within *both* `RUSTFLAGS` and `RUSTDOCFLAGS` for it to compile correctly.

The distribution build of our toolchain includes a Cargo plugin that will handle this step automatically.
```
cargo bsan
```
Our plugin also links Rust programs against an instrumented sysroot, so that you can avoid rebuilding the standard library when switching between projects.

## Clang
Our default development configuration builds a version of Clang that supports BorrowSanitizer. You can access from build scripts by setting the environment variables `CC` and `CXX` to the absolute path to the `clang` binary in our build directory, like so:
```
export CC=".../host/llvm/bin/clang"
```
Alternatively, you can set our entire build of LLVM to be first in your path, so that all invocations of `clang` will default to our custom one.
```
export PATH=".../host/llvm/bin/:$PATH"
```
You can enable BorrowSanitizer in `clang` by passing the flag `-fsanitize=borrow`.