#!/bin/bash
set -euo pipefail

# This script builds clang from source by reusing build artifacts
# from `rust-dev``. This script is intentionally flaky - it relies on the
# current layout of the `rust-dev` archive, and manually generates headers
# required for building clang. We expect to execute this semi-regularly, as
# Rust's nightly LLVM is updated, so we can accommodate some failures. This
# entire process can be avoided once 

if [[ $# -ne 4 ]]; then
    echo "usage: $0 <llvm-sha> <rust-sha> <target> <output>"
    exit 1
fi

OUTPUT_DIR="$PWD"

LLVM_SHA=$1
RUSTC_SHA=$2
TARGET=$3

# we produce the file $OUTPUT.tar.xz
OUTPUT=$4

LLVM_ORIGIN="https://github.com/rust-lang/llvm-project.git"

# The endpoint where CI artifacts are hosted for the given nightly build.
RUST_DEV_ENDPOINT="https://ci-artifacts.rust-lang.org/rustc-builds/$RUSTC_SHA"

# The rust-dev artifact.
RUST_DEV_ARTIFACT="rust-dev-nightly-$TARGET"

RUST_DEV_URL="$RUST_DEV_ENDPOINT/$RUST_DEV_ARTIFACT.tar.xz"

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

TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

echo "Cloning LLVM into a temporary directory: $TMP_DIR"

# initialize an empty git repository
git init -q

# point it to llvm-project, and enable sparse checkout
git remote add origin $LLVM_ORIGIN

# we only need llvm, clang, and shared dependencies (cmake, third-party)
git sparse-checkout init --cone
git sparse-checkout set cmake llvm clang third-party

git fetch -q --depth=1 --filter=tree:0 origin "$LLVM_SHA"
git checkout -q FETCH_HEAD

echo "Downloading rust-dev artifacts:"
echo "  - url: $RUST_DEV_URL"
echo "  - dest: $TMP_DIR/rust-dev"

mkdir rust-dev
curl --proto '=https' --tlsv1.2 -sSfL --retry 3 \
    "$RUST_DEV_URL" -o rust-dev.tar.xz
tar -xf rust-dev.tar.xz --strip-components=2 -C rust-dev \
    "$RUST_DEV_ARTIFACT/rust-dev"

echo "Rebuilding LLVM CMake installation config..."
cmake -S llvm -B llvm-cfg -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_LINK_LLVM_DYLIB=ON \
    -DLLVM_TARGETS_TO_BUILD=host \
    -DLLVM_ENABLE_ASSERTIONS=OFF \
    -DLLVM_ABI_BREAKING_CHECKS=FORCE_OFF \
    -DLLVM_ENABLE_RTTI=OFF \
    -DLLVM_INCLUDE_TESTS=OFF \
    -DLLVM_INCLUDE_BENCHMARKS=OFF \
    -DLLVM_INCLUDE_EXAMPLES=OFF \
    -DLLVM_NATIVE_TOOL_DIR="$PWD/rust-dev/bin"

# rust-dev places libLLVM within `rust-dev/lib`
# with the extention `.so.<MAJOR>.<MINOR>-rust-<semver>-<channel>`
LIB_LLVM=$(find "$PWD"/rust-dev/lib/libLLVM.so.*-rust-* | head -1)
LIB_LLVM_NAME=$(basename "$LIB_LLVM")

if [[ "$LIB_LLVM_NAME" =~ ^libLLVM\.so\.([0-9]+)\.([0-9]+) ]]; then
    MAJOR="${BASH_REMATCH[1]}"
    MINOR="${BASH_REMATCH[2]}"
else
    echo "Error: could not parse LLVM major.minor version from '$LIB_LLVM_NAME'" >&2
    exit 1
fi

# llvm-cfg is expecting to find it at `llvm-cfg/lib`
# with both `.so` and `.so.<MAJOR>.<MINOR>`
mkdir -p "$PWD/llvm-cfg/lib"

ln -sf "$LIB_LLVM" "$PWD/llvm-cfg/lib/libLLVM.so"
ln -sf "$LIB_LLVM" "$PWD/llvm-cfg/lib/libLLVM.so.${MAJOR}.${MINOR}"

# Rebuilding headers that are missing 
ninja -C llvm-cfg intrinsics_gen omp_gen acc_gen analysis_gen \
    target_parser_gen vt_gen
    
# Build clang
cmake -S clang -B clang-build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PWD/install" \
    -DLLVM_DIR="$PWD/llvm-cfg/lib/cmake/llvm" \
    -DLLVM_TABLEGEN_EXE="$PWD/rust-dev/bin/llvm-tblgen" \
    -DLLVM_ENABLE_ASSERTIONS=OFF \
    -DLLVM_ENABLE_RTTI=OFF \
    -DLLVM_ENABLE_PLUGINS=ON \
    -DCLANG_PLUGIN_SUPPORT=ON \
    -DLLVM_INCLUDE_TESTS=OFF \
    -DCLANG_INCLUDE_TESTS=OFF
cmake --build clang-build --target clang clang-format

cmake --build clang-build --target install-clang install-clang-cpp \
    install-clang-format install-clang-resource-headers
strip install/bin/clang-* install/lib/libclang-cpp.so.* || true

mkdir -p "dist/$OUTPUT/lib"
cp -a install/bin "dist/$OUTPUT/bin"
cp -a install/lib/clang "dist/$OUTPUT/lib/clang"
cp -a install/lib/libclang-cpp.so* "dist/$OUTPUT/lib/"
tar -cJf "$OUTPUT_DIR/$OUTPUT.tar.xz" -C dist "$OUTPUT"