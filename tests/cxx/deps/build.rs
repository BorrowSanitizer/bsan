use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest_dir.parent().unwrap();

    let mut build = cc::Build::new();
    // We can use `cc` here directly without much additional configuration 
    // because invocations to `clang` will be intercepted by `cargo-bsan` and 
    // then reconfigured with flags to instrument each file. 
    build.cpp(true).std("c++20").warnings(true).extra_warnings(true).warnings_into_errors(true);

    // Recursively scan every directory under `cxx` and build each `.cpp` file into a 
    // single static archive.
    for suite in root.read_dir().unwrap() {
        let suite = suite.unwrap().path();
        if !suite.is_dir() || suite == manifest_dir {
            continue;
        }
        println!("cargo:rerun-if-changed={}", suite.display());
        for entry in suite.read_dir().unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "cpp") {
                println!("cargo:rerun-if-changed={}", path.display());
                build.file(path);
            }
        }
    }
    build.compile("cxx_deps");
}
