# Setup
The easiest way to try BorrowSanitizer is inside a Docker container. Our image supports the following platforms:

|   **Platform**    |         **Target**            | **Description**            |
|-------------------|-------------------------------|----------------------------|
|   `linux/amd64`   | `aarch64-apple-darwin`        |   ARM64 macOS (M-series)   |
|   `linux/arm64`   |  `x86_64-unknown-linux-gnu`   |    X86 Linux               |

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
If you only want to install BorrowSanitizer, then run:
```
xb install
```
This will install a [custom Rust toolchain](https://github.com/BorrowSanitizer/rust) under the name `bsan`. You can speed this up by building our [dev container](https://containers.dev/), which already has the `bsan` toolchain installed. We recommend using the container to avoid any environment-specific issues. 

You can build and test components of the project using the `build` and `test` subcommands. For example, running `xb build` will build everything, but you can also pass the name of a subdirectory to build just that component, like so:
```
xb build bsan-rt
```
Nearly every subcommand can be used this way. 

After making a change, you should run all of our CI steps locally using:
```
xb ui
```

This will place our binaries into Cargo's [home directory](https://doc.rust-lang.org/cargo/guide/cargo-home.html) (`$HOME/.cargo`). You will need to have `bsan` set as the active toolchain (e.g. `rustup default bsan`) for our tool to work. 