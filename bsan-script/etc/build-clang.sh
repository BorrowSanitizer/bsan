#!/bin/bash
# This script builds clang from source by reusing build artifacts
# from `rust-dev`.
set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 <llvm-sha> <rust-sha> <target> <output>"
    exit 1
fi

check_dependencies() {
    local missing=()
    for cmd in "$@"; do
        command -v "$cmd" &> /dev/null || missing+=("$cmd")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo "Missing dependencies: ${missing[*]}" >&2
        return 1
    fi
    return 0
}

check_dependencies git cmake ninja lld curl || exit 1

LLVM_SHA=$1
RUSTC_SHA=$2
# The target architecture that we are building for.
TARGET=$3

# We place an archive with the build output into the current directory.
OUTPUT_DIR="$PWD"
# we produce the file $OUTPUT.tar.xz
OUTPUT="$4-$TARGET"

# Rust's LLVM fork.
LLVM_ORIGIN="https://github.com/rust-lang/llvm-project.git"

# The endpoint where CI artifacts are hosted for nightly builds.
RUST_DEV_ENDPOINT="https://ci-artifacts.rust-lang.org/rustc-builds/$RUSTC_SHA"

# Rust distributes a `rust-dev` archive that contains build artifacts which can
# be reused to speed-up building the compiler from source (download-ci-llvm). The 
# artifact contains a copy of libLLVM for the current nightly.
RUST_DEV_ARTIFACT="rust-dev-nightly-$TARGET"
RUST_DEV_URL="$RUST_DEV_ENDPOINT/$RUST_DEV_ARTIFACT.tar.xz"

# Create a temporary directory where we build everything.
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

git init -q
git remote add origin $LLVM_ORIGIN
git sparse-checkout init --cone
git sparse-checkout set cmake llvm clang third-party libc
git fetch -q --depth=1 --filter=tree:0 origin "$LLVM_SHA"
git checkout -q FETCH_HEAD
 
echo "Downloading rust-dev artifacts..."
curl --proto '=https' --tlsv1.2 -sSfL --retry 3 \
    "$RUST_DEV_URL" -o rust-dev.tar.xz
tar -xf rust-dev.tar.xz --strip-components=1

# Rust's libLLVM is labelled "libLLVM.so.<MAJOR>.<MINOR>-rust-<VERSION>-nightly"
LIB_LLVM=$(find "$PWD"/rust-dev/lib/libLLVM.so.*-rust-* | head -1)
LIB_LLVM_NAME=$(basename "$LIB_LLVM")
LLVM_VERSION_SUFFIX="-${LIB_LLVM_NAME#*-}"

# We reinitialize rust-dev as a build directory for LLVM,
# keeping the same suffix that Rust uses.
cmake -S llvm -B "rust-dev" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_LINK_LLVM_DYLIB=ON \
    -DLLVM_VERSION_SUFFIX="$LLVM_VERSION_SUFFIX" \
    -DLLVM_TARGETS_TO_BUILD=host \
    -DLLVM_ENABLE_ASSERTIONS=OFF \
    -DLLVM_ABI_BREAKING_CHECKS=FORCE_OFF \
    -DLLVM_ENABLE_RTTI=OFF \
    -DLLVM_INCLUDE_TESTS=OFF \
    -DLLVM_INCLUDE_BENCHMARKS=OFF \
    -DLLVM_INCLUDE_EXAMPLES=OFF

# Clang needs all of these generated headers, which are not shipped
# with rust-dev by default. 
ninja -C rust-dev intrinsics_gen omp_gen acc_gen analysis_gen \
    target_parser_gen vt_gen

# Build clang
cmake -S clang -B clang-build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PWD/dist/$OUTPUT" \
    -DLLVM_DIR="$PWD/rust-dev/lib/cmake/llvm" \
    -DLLVM_TABLEGEN_EXE="$PWD/rust-dev/bin/llvm-tblgen" \
    -DLLVM_ENABLE_ASSERTIONS=OFF \
    -DLLVM_ENABLE_RTTI=OFF \
    -DLLVM_ENABLE_PLUGINS=ON \
    -DCLANG_PLUGIN_SUPPORT=ON \
    -DLLVM_INCLUDE_TESTS=OFF \
    -DCLANG_INCLUDE_TESTS=OFF

cmake --build clang-build --target clang clang-format libclang
cmake --build clang-build --target install-clang install-clang-cpp \
    install-clang-format install-clang-resource-headers install-libclang

tar -cJf "$OUTPUT_DIR/$OUTPUT.tar.xz" -C dist "$OUTPUT"
