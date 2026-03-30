//@run:0
//miri: @compile-flags: -Zmiri-mute-stdout-stderr

fn main() {
    println!("print to stdout");
    eprintln!("print to stderr");
}
