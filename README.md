[![CI](https://github.com/BorrowSanitizer/bsan/actions/workflows/ci.yml/badge.svg)](https://github.com/BorrowSanitizer/bsan/actions/workflows/ci.yml) [![Benchmarks](https://github.com/BorrowSanitizer/bsan/actions/workflows/bench.yml/badge.svg)](https://borrowsanitizer.github.io/bsan/) [![docs](https://github.com/borrow-sanitizer/docs/actions/workflows/docs.yml/badge.svg)](https://borrowsanitizer.com) [![project chat](https://img.shields.io/badge/zulip-join_chat-brightgreen.svg)](https://bsan.zulipchat.com/) [![Open in Dev Containers](https://img.shields.io/static/v1?label=Dev%20Containers&message=Open&color=blue)](https://vscode.dev/redirect?url=vscode://ms-vscode-remote.remote-containers/cloneInVolume?url=https://github.com/BorrowSanitizer/bsan)

# BorrowSanitizer

<img src="bor.svg" align="right" width="175px" alt=""
 title="Art by Molly MacLaren">
 
BorrowSanitizer is a work-in-progress LLVM instrumentation pass for detecting aliasing violations in multi-language Rust applications. Our project is still in early development, but may help you find cross-language bugs otherwise undetectable by Miri. Our goal is to support detecting the following types of errors:

* Violations of Rust's [*Tree Borrows*](https://perso.crans.org/vanille/treebor/) aliasing model.
* Accesses out-of-bounds
* Use-after free errors.

Check out [our website](https://borrowsanitizer.com) for more information.

## Usage
The easiest way to try BorrowSanitizer is inside a Docker container. Our image supports the following platforms:

|   **Platform**    |         **Target**            | **Description**            |
|-------------------|-------------------------------|----------------------------|
|   `linux/amd64`   | `aarch64-unknown-linux-gnu`   |ARM64 Linux                 |
|   `linux/arm64`   |  `x86_64-unknown-linux-gnu`   |X86 Linux                   |

First, pull our [latest image](https://github.com/BorrowSanitizer/bsan/pkgs/container/bsan) from GitHub's container registry.
```
docker pull ghcr.io/borrowsanitizer/bsan:latest
```
Then, launch a container and attach a shell.
```
docker run -it bsan:latest
```
Once inside the container, you can use our Cargo plugin to build and test crates using BorrowSanitizer. 
```
cargo bsan test
```
Our plugin supports most of the same subcommands as Miri. When it's used for the first time, it will perform a one-time setup step of building an instrumented sysroot. You can trigger this step manually using the `setup` subcommand. 

## Contributing
We follow the LLVM Project's [AI Tool Use Policy](https://llvm.org/docs/AIToolPolicy.html). All AI-generated content must be disclosed. There must always be a human in the loop. 

We welcome contributions! Please consult our [contribution guide](https://github.com/BorrowSanitizer/bsan/blob/main/CONTRIBUTING.md) and join [our Zulip](https://bsan.zulipchat.com/) if you have questions.

## Bugs found by BorrowSanitizer

BorrowSanitizer has been used to find a variety of new cross-language aliasing bugs in open source projects. 
* [Overlapping references in `aws-lc-rs`](https://github.com/aws/aws-lc-rs/pull/1288)
* [Writing through an immutable reference in CXX](https://github.com/dtolnay/cxx/issues/1762)

## License & Credits

BorrowSanitizer is dual-licensed under [Apache](https://github.com/BorrowSanitizer/bsan/blob/main/LICENSE-APACHE) and [MIT](https://github.com/BorrowSanitizer/bsan/blob/main/LICENSE-MIT), following the Rust project.

[<img src="https://borrowsanitizer.com/images/zulip-icon-circle.svg" alt="Zulip" style="height: 1em;"/> Zulip](https://zulip.com/) sponsors free hosting for BorrowSanitizer. Zulip is an organized team chat app designed for efficient communication.


