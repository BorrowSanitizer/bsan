#!/usr/bin/env bash
set -euo pipefail

# This script builds a version of clang that is compatible with a particular
# nightly version of Rust, using the prebuilt LLVM artifacts provided by
# Rust's CI pipeline (e.g. download-ci-llvm).
if [[ $# -ne 4 ]]; then
    echo "usage: $0 <llvm-sha> <rust-sha> <target> <output>" >&2
    exit 1
fi

LLVM_SHA=$1
RUSTC_SHA=$2
TARGET=$3
OUTPUT_DIR="$PWD"

# We produce an archive with the specified output name, 
# followed by the toolchain's target.
OUTPUT="$4-$TARGET"

TMP_DIR="${TMP_DIR:-$(mktemp -d)}"
mkdir -p "$TMP_DIR"
cd "$TMP_DIR"

git init -q
git remote add origin https://github.com/rust-lang/llvm-project.git
git sparse-checkout init --cone
git sparse-checkout set cmake llvm clang third-party libc
git fetch -q --depth=1 --filter=tree:0 origin "$LLVM_SHA"
git checkout -q FETCH_HEAD

# The rust-dev component is what gets downloaded when you
# build Rust from source using ./x.py under the default
# bootstrap configuration. It contains a prebuilt libLLVM,
# along with llvm tool binaries.
curl --proto '=https' --tlsv1.2 -sSfL --retry 3 \
    "https://ci-artifacts.rust-lang.org/rustc-builds/$RUSTC_SHA/rust-dev-nightly-$TARGET.tar.xz" \
    -o rust-dev.tar.xz
tar -xf rust-dev.tar.xz --strip-components=1

LLVM_CONFIG="$TMP_DIR/rust-dev/bin/llvm-config"
LLVM_VERSION=$("$LLVM_CONFIG" --version)
LLVM_CMAKE_DIR=$("$LLVM_CONFIG" --cmakedir)
LLVM_TBLGEN=$("$LLVM_CONFIG" --bindir)/llvm-tblgen

# Rust adds a custom suffix to libLLVM for linux toolchains,
# indicating the Rust semver and channel of the toolchain.
# For example: `libLLVM-23-rust-1.99.0-nightly`.
# When we build clang, we need to point it toward a version
# of libLLVM that has the same name, which we can obtain from `llvm-config`.
# The version reported by `llvm-config` will be `23-rust-1.99.0-nightly`,
# so we need to extract everything after the first dash. On Darwin, Rust does
# not apply a suffix, but it's still reported by `llvm-config`, so we do not
# need to skip the parsing here. 
case "$LLVM_VERSION" in
    *-*) LLVM_VERSION_SUFFIX="-${LLVM_VERSION#*-}" ;;
    *)
        echo "no rust suffix in llvm version: $LLVM_VERSION" >&2
        exit 1
        ;;
esac

# We will place the `clang` binaries within the toolchain's 
# root `bin` directory, so we need to adjust their rpath to 
# look for libLLVM in the adjacent `lib` directory.
case "$TARGET" in
    *-apple-darwin) RPATH='@loader_path/../lib' ;;
    *)              RPATH='$ORIGIN/../lib' ;;
esac

# What we downloaded in `rust-dev` is a partial copy of 
# LLVM's build artifacts. We need the generated headers and
# CMake files, too. So, we point CMake at the unzipped directory
# and build LLVM to produce only what we're missing. Note that we
# still provide the suffix on Darwin, but we also set
# `-DLLVM_VERSIONED_DYLIB_NAME_ON_DARWIN` to avoid applying it,
# matching what Rust does.
cmake -S llvm -B rust-dev -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_LINK_LLVM_DYLIB=ON \
    -DLLVM_VERSION_SUFFIX="$LLVM_VERSION_SUFFIX" \
    -DLLVM_VERSIONED_DYLIB_NAME_ON_DARWIN=OFF \
    -DLLVM_TARGETS_TO_BUILD=host \
    -DLLVM_ENABLE_ASSERTIONS=OFF \
    -DLLVM_ABI_BREAKING_CHECKS=FORCE_OFF \
    -DLLVM_ENABLE_RTTI=OFF \
    -DLLVM_INCLUDE_TESTS=OFF \
    -DLLVM_INCLUDE_BENCHMARKS=OFF \
    -DLLVM_INCLUDE_EXAMPLES=OFF

# We also need tblgen-ed headers. This list is unavoidable at
# the moment; If we set `-DLLVM_ENABLE_PROJECTS=clang`, this would
# automatically build these dependencies, but it will also build
# all of LLVM from source, which we want to avoid. 
ninja -C rust-dev intrinsics_gen omp_gen acc_gen analysis_gen \
    target_parser_gen vt_gen

cmake -S clang -B clang-build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$TMP_DIR/dist/$OUTPUT" \
    -DCMAKE_INSTALL_RPATH="$RPATH" \
    -DCMAKE_INSTALL_NAME_DIR="@rpath" \
    -DLLVM_DIR="$LLVM_CMAKE_DIR" \
    -DLLVM_TABLEGEN_EXE="$LLVM_TBLGEN" \
    -DLLVM_ENABLE_ASSERTIONS=OFF \
    -DLLVM_ENABLE_RTTI=OFF \
    -DLLVM_ENABLE_PLUGINS=ON \
    -DCLANG_PLUGIN_SUPPORT=ON \
    -DLLVM_INCLUDE_TESTS=OFF \
    -DCLANG_INCLUDE_TESTS=OFF

cmake --build clang-build --target install-clang install-clang-cpp \
    install-clang-format install-clang-resource-headers install-libclang

# Setting `COPYFILE_DISABLE` prevents MacOS-specific attribute data 
# from being included within the generated archive as files with 
# the ._* extention
COPYFILE_DISABLE=1 tar -cJf "$OUTPUT_DIR/$OUTPUT.tar.xz" -C dist "$OUTPUT"