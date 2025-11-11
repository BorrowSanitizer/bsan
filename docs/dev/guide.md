# Development Guide

BorrowSanitizer has multiple components. Each can be built, linted, and tested individually via `xb`. 

| Component                  | Subdirectory  | Link  |
|----------------------------|---------------|:-----:|
| Cargo Plugin               | `cargo-bsan`  | [{{#include ../images/link.svg}}](https://github.com/BorrowSanitizer/bsan/tree/main/cargo-bsan)  |
| Rustc Plugin               | `bsan-driver` | [{{#include ../images/link.svg}}](https://github.com/BorrowSanitizer/bsan/tree/main/bsan-driver) |
| Backend Instrumentation Pass       | `bsan-pass`   | [{{#include ../images/link.svg}}](https://github.com/BorrowSanitizer/bsan/tree/main/bsan-pass)   |
| Runtime                    | `bsan-rt`     | [{{#include ../images/link.svg}}](https://github.com/BorrowSanitizer/bsan/tree/main/bsan-rt)     |


### Why do we need a custom toolchain? 
We also rely on forks of both the Rust toolchain and LLVM. Initially, we developed everything in-tree within our Rust fork, but we have since found that it's easier to iterate by externalizing everything as a plugin. This includes our LLVM pass, which is "injected" into the compilation process using Rust's unstable [`-Zllvm-plugin`](https://github.com/rust-lang/rust/issues/127577) flag. Overall, our approach is similar what worked for the [Enzyme project](https://github.com/rust-lang/enzyme), which also relies on an out-of-tree LLVM plugin.

Although most of BorrowSanitizer has been externalized, we do still need our custom compiler. We *really* wanted to avoid this, but it ended up being necessary to support inserting "retag" instructions into LLVM IR. Under each of Rust's aliasing models, a retag updates the permission associated with a pointer, indicating that a reference has been created, reborrowed, or passed into a function. Retags are already implemented as [MIR intrinsics](https://doc.rust-lang.org/std/intrinsics/mir/fn.Retag.html), but we needed a way to lower them further down into LLVM IR, so that our instrumentation pass can transform them into calls into our runtime library.

We were unable to add a custom retag function via our frontend compiler plugin (`bsan-driver`), since Rust's plugin interface gives mostly immutable access to the HIR; it's not possible to add in a new type of this kind after typechecking has been completed. So, we needed a way to declare our function ahead-of-time. The best mechanism for doing this is an intrinsic. Rust's intrinsics are provided by either the frontend or one of more of its codegen backends. Since we need retags to be available at the LLVM level, we needed to modify the LLVM codegen backend. It's possible to add a custom codegen backend without modifying the compiler by using an out-of-tree plugin (see [`rustc_interface`](https://doc.rust-lang.org/stable/nightly-rustc/rustc_interface/interface/struct.Config.html#structfield.make_codegen_backend)). Better yet, this approach has been successful for projects that have been widely adopted, like [Kani](https://github.com/model-checking/kani). However, in our case, we only needed to add support for a single intrinsic while preserving the existing LLVM backend *and* keeping it up-to-date with nightly. For long-term maintenance, we decided that forking Rust would be easier than factoring out just the LLVM backend.

We intend to submit these changes incrementally upstream, so that other tool developers can benefit.