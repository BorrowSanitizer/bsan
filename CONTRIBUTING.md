# Contributing

### First Time Setup
Every single command needed to build, test, and install BorrrowSanitizer can be accessed through `xb`, our build script.

For first-time setup, run:
```
# install the nightly Rust toolchain and dependencies
rustup toolchain install nightly --component rust-src rustc-dev llvm-tools-preview

# install build dependencies
sudo apt-get update && sudo apt-get install -y cmake ninja-build clang lld clang-tidy

./xb setup
```
This will install a [custom Rust toolchain](https://github.com/BorrowSanitizer/rust) under the name `bsan`.

Then, to install BorrowSanitizer, run:
```
./xb install
```
This will place our tool's binaries into Cargo's [home directory](https://doc.rust-lang.org/cargo/guide/cargo-home.html) (`$HOME/.cargo`). You will need to have `bsan` set as the active toolchain (e.g. `rustup default bsan`) for our tool to work.

You can build and test components of the project using the `build` and `test` subcommands. For example, running `xb build` will build everything, but you can also pass the name of a subdirectory to build just that component, like so:
```
./xb build bsan-rt
```
Nearly every subcommand can be used this way.

After making a change, you should run all of our CI steps locally using:
```
./xb ci
```