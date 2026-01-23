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
          if [ -f "./xb" ]; then
            exec ./xb "$@"
          else
            echo "Error: './xb' script not found in current directory."
            exit 1
          fi
        '';

        fhs = pkgs.buildFHSEnv {
          name = "xb-dev-env";

          targetPkgs = pkgs: with pkgs; [
            git
            curl
            vim
            gdb
            pkg-config

            cmake
            ninja

            clang
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
            export CC=clang
            export CXX=clang++
            export PATH=$HOME/.cargo/bin:$PATH

            if ! command -v rustup >/dev/null; then
                curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain nightly -y
            fi

            xb --skip setup

            xb install

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
