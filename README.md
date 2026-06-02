[![CI](https://github.com/BorrowSanitizer/bsan/actions/workflows/ci.yml/badge.svg)](https://github.com/BorrowSanitizer/bsan/actions/workflows/ci.yml) [![Benchmarks](https://github.com/BorrowSanitizer/bsan/actions/workflows/bench.yml/badge.svg)](https://borrowsanitizer.github.io/bsan/) [![docs](https://github.com/borrow-sanitizer/docs/actions/workflows/docs.yml/badge.svg)](https://borrowsanitizer.com) [![project chat](https://img.shields.io/badge/zulip-join_chat-brightgreen.svg)](https://bsan.zulipchat.com/) [![Open in Dev Containers](https://img.shields.io/static/v1?label=Dev%20Containers&message=Open&color=blue)](https://vscode.dev/redirect?url=vscode://ms-vscode-remote.remote-containers/cloneInVolume?url=https://github.com/BorrowSanitizer/bsan)

# <a href="https://borrowsanitizer.com"><img height="50px" width="30px" src="https://borrowsanitizer.com/images/bsan.svg" alt="BorrowSanitizer" /></a> <a href="https://github.com/BorrowSanitizer/bsan"><picture><source media="(prefers-color-scheme: dark)" height="60px" height="60px" srcset="https://borrowsanitizer.com/images/bsan-text-dark.svg"/><img height="60px" height="60px" src="https://borrowsanitizer.com/images/bsan-text-light.svg" alt="BorrowSanitizer" /></picture></a>

BorrowSanitizer is work-in-progress LLVM instrumentation pass for detecting aliasing violations in multi-language Rust applications. Our project is still in early stages, and it is not functional yet. Our goal is to support detecting the following types of errors:

* Violations of Rust's [*Tree Borrows*](https://perso.crans.org/vanille/treebor/) aliasing model.
* Accesses out-of-bounds
* Use-after free errors.

This project contains a fork of Miri's borrow tracker ([`bsan-shared`](https://github.com/BorrowSanitizer/bsan/tree/main/bsan-shared), [`bsan-rt`](https://github.com/BorrowSanitizer/bsan/tree/main/bsan-rt)), as well as several other components from both Miri and the Rust compiler. 

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

## Building from Source
Every single command needed to build, test, and install BorrrowSanitizer can be accessed through `xb`, our build script. For first-time setup, run:
```
xb setup
```
This will install a [custom Rust toolchain](https://github.com/BorrowSanitizer/rust) under the name `bsan`.
Then, to install BorrowSanitizer, run:
```
xb install
```
This will place our tool's binaries into Cargo's [home directory](https://doc.rust-lang.org/cargo/guide/cargo-home.html) (`$HOME/.cargo`). You will need to have `bsan` set as the active toolchain (e.g. `rustup default bsan`) for our tool to work. 

You can build and test components of the project using the `build` and `test` subcommands. For example, running `xb build` will build everything, but you can also pass the name of a subdirectory to build just that component, like so:
```
xb build bsan-rt
```
Nearly every subcommand can be used this way. 

After making a change, you should run all of our CI steps locally using:
```
xb ci
```
---
BorrowSanitizer is dual-licensed under [Apache](https://github.com/BorrowSanitizer/bsan/blob/main/LICENSE-APACHE) and [MIT](https://github.com/BorrowSanitizer/bsan/blob/main/LICENSE-MIT), following the Rust project.

[<img src="https://borrowsanitizer.com/images/zulip-icon-circle.svg" alt="Zulip" style="height: 1em;"/> Zulip](https://zulip.com/) sponsors free hosting for BorrowSanitizer. Zulip is an organized team chat app designed for efficient communication.
