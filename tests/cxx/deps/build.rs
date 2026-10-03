use std::env;
use std::path::PathBuf;

/// Compiles the C++ half of every test in `tests/cxx` into a single static library,
/// which is bundled into this crate. `cargo bsan` sets `CXX` to a wrapper that
/// instruments each source file and compiles it against the instrumented libc++.
fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let root = root.parent().unwrap();

    let mut build = cc::Build::new();
    build.cpp(true).std("c++20").warnings(true).extra_warnings(true).warnings_into_errors(true);

    for suite in ["pass", "fail"] {
        let suite = root.join(suite);
        println!("cargo:rerun-if-changed={}", suite.display());
        for entry in suite.read_dir().unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "cpp") {
                println!("cargo:rerun-if-changed={}", path.display());
                build.file(path);
            }
        }
    }
    build.compile("bsan_test_cxx");
}
