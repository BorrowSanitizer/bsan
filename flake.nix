{
  description = "BorrowSanitizer Development Environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        xb = pkgs.writeShellScriptBin "xb" ''
          ROOT_DIR=$(git rev-parse --show-toplevel 2>/dev/null || echo ".")
          if [ -f "$ROOT_DIR/xb" ]; then
            exec "$ROOT_DIR/xb" "$@"
          else
            echo "Error: 'xb' script not found in project root."
            exit 1
          fi
        '';

        fhs = pkgs.buildFHSEnv {
          name = "bsan-dev";

          targetPkgs = pkgs: with pkgs; [
            git
            curl
            vim
            gdb
            pkg-config

            cmake
            ninja

            perf
            hyperfine
            jq
            valgrind

            rustup
            clang
            gcc
            stdenv.cc.cc
            glibc.dev
            clang-tools
            python3

            llvmPackages.llvm.dev
            zlib
            openssl
            libxml2
            libffi

            xb
          ];

          profile = ''
            PROJECT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
            export RUST_DIR="$PROJECT_ROOT/.nix-rust"
            export RUSTUP_HOME="$RUST_DIR/rustup"
            export CARGO_HOME="$RUST_DIR/cargo"

            export PATH="$CARGO_HOME/bin:$PATH"

            export CC=clang
            export CXX=clang++

            mkdir -p "$RUSTUP_HOME" "$CARGO_HOME"

            if ! rustup toolchain list 2>/dev/null | grep -q "bsan"; then
                rustup toolchain install nightly
                rustup default nightly

                xb --skip setup
                xb install
                rustup default bsan
            fi

            rustc -vV
          '';

          runScript = "bash";
        };

      in
      {
        devShells.default = fhs.env;
      }
    );
}
