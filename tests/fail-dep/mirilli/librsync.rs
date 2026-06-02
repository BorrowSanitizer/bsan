//@run:1
// This is a copy of the test `send_patch` from librsync at version 0.2.3

use std::thread;
use librsync::{Patch};
use std::io::{Read, Cursor};

const DATA: &str = "this is a string to be tested";

fn data2_delta() -> Vec<u8> {
    vec![
        0x72, 0x73, 0x02, 0x36, 0x10, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61,
        0x6e, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x45, 0x0a, 0x13, 0x00,
    ]
}

fn main() {
    let base = Cursor::new(DATA);
    let delta = data2_delta();
    let delta = Cursor::new(delta);
    let mut patch = Patch::new(base, delta).unwrap();
    let t = thread::spawn(move || {
        let mut computed_new = String::new();
        patch.read_to_string(&mut computed_new).unwrap();
    });
    t.join().unwrap();
}