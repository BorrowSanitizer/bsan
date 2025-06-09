[![CI](https://github.com/BorrowSanitizer/bsan/actions/workflows/ci.yml/badge.svg)](https://github.com/BorrowSanitizer/bsan/actions/workflows/ci.yml) [![docs](https://github.com/borrow-sanitizer/docs/actions/workflows/docs.yml/badge.svg)](https://borrowsanitizer.com) [![project chat](https://img.shields.io/badge/zulip-join_chat-brightgreen.svg)](https://bsan.zulipchat.com/) [![Open in Dev Containers](https://img.shields.io/static/v1?label=Dev%20Containers&message=Open&color=blue)](https://vscode.dev/redirect?url=vscode://ms-vscode-remote.remote-containers/cloneInVolume?url=https://github.com/BorrowSanitizer/bsan)

# <a href="https://borrowsanitizer.com"><img height="50px" src="https://borrowsanitizer.com/images/bsan.svg" alt="BorrowSanitizer" /></a> <a href="https://github.com/verus-lang/verus"><picture><source media="(prefers-color-scheme: dark)" height="60px" height="60px" srcset="https://borrowsanitizer.com/images/bsan-text-dark.svg"/><img height="60px" height="60px" src="https://borrowsanitizer.com/images/bsan-text-light.svg" alt="BorrowSanitizer" /></picture></a>

BorrowSanitizer is work-in-progress LLVM instrumentation pass for detecting aliasing violations in multi-language Rust applications. Our project is still in early stages, and it is not functional yet. Our goal is to support detecting the following types of errors:
* Violations of Rust's [*Tree Borrows*](https://perso.crans.org/vanille/treebor/) aliasing model.
* Accesses out-of-bounds
* Use-after free errors.


## Setup
We only support x86 and ARM Linux. You can build, install, and test BorrowSanitizer using `xb`, our build script. For first-time setup, run:
```
xb setup
```
This will install a [custom Rust toolchain](https://github.com/BorrowSanitizer/rust) under the name `bsan`. You can speed this up by building our [dev container](https://containers.dev/), which already has the `bsan` toolchain installed. We recommend using the container to avoid any environment-specific issues.

You can install BorrowSanitizer with:
```
xb install
```
This will place our binaries into the Cargo [home directory](https://doc.rust-lang.org/cargo/guide/cargo-home.html), which is usually `$HOME/.cargo`. You will need to have `bsan` set as the active toolchain (e.g. `rustup default bsan`) for our tool to work. 

To test a crate using BorrowSanitizer, run:
```
cargo bsan test
```
Check out [our website](https://borrowsanitizer.com) for more information.

---
BorrowSanitizer is dual-licensed under [Apache](https://github.com/BorrowSanitizer/bsan/blob/main/LICENSE-APACHE) and [MIT](https://github.com/BorrowSanitizer/bsan/blob/main/LICENSE-MIT), following the Rust project.

[<img src="https://borrowsanitizer.com/images/zulip-icon-circle.svg" alt="Zulip" style="height: 1em;"/> Zulip](https://zulip.com/) sponsors free hosting for BorrowSanitizer. Zulip is an organized team chat app designed for efficient communication.
