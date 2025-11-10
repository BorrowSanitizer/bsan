# Introduction

> 🎉 We presented at the 2025 Rust Verification Workshop ([RV2025](https://sites.google.com/view/rustverify2025)). Here's our [presentation](pdfs/RW2025_presentation.pdf) and [abstract](pdfs/rw2025.pdf).

**BorrowSanitizer** is a dynamic analysis tool for detecting Rust-specific aliasing bugs in multi-language applications.

![the BorrowSanitizer project logo](images/bsan.svg "project logo" =x75 center )

The Rust compiler provides powerful, *static* safety guarantees by restricting aliasing and mutability. However, developers can bypass these restrictions by using a subset of [`unsafe`](https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html) features. These features are necessary for Rust to interoperate with other languages. However, if developers use unsafe code incorrectly, then they can break the rules of Rust's aliasing model, which the compiler relies on to be able to optimize programs. Incorrect optimizations can introduce security vulnerabilities.

Rust developers can find aliasing bugs using [Miri](https://github.com/rust-lang/miri), an interpreter. Miri is **the only tool** that can find violations of Rust's latest [Tree Borrows](https://www.ralfj.de/blog/2023/06/02/tree-borrows.html) aliasing model, but it cannot find these bugs in foreign code. Miri is also significantly slower than native execution, which makes it impractical to use techniques like fuzzing or property-based testing to find these Rust-specific bugs.

BorrowSanitizer is an LLVM sanitizer for finding aliasing violations. Our goal is for it to be fast enough for use with fuzzing tools and to have support for Rust, C, and C++ in interoperation. We intend for it to be a production-ready tool.

> 🚧 Our project is still in early stages. BorrowSanitizer is not functional yet. 🚧

Join [our Zulip](https://bsan.zulipchat.com/) if you are interested in contributing or if you have any additional questions about our project. You can build and test our sanitizer by following the setup instructions in the next section. All of our code is open-source and publicly available [on GitHub](https://github.com/borrowsanitizer).