//@run:0
fn main() {
    let exec_path = std::env::args().nth(0).unwrap();
    let current_exe = std::env::current_exe()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert_eq!(exec_path, current_exe);
}
