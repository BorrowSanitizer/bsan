//@run:1
// This is a direct copy of the test `zero_length_read_at_eof`
// from `bzip2` at 0.6.0.
use bzip2::read::{BzDecoder, BzEncoder};
use bzip2::Compression;
use std::io::Read;

fn main() {
    let m = Vec::<u8>::new();
    let mut c = BzEncoder::new(&m[..], Compression::default());

    let mut result = Vec::<u8>::new();
    c.read_to_end(&mut result).unwrap();

    let mut d = BzDecoder::new(&result[..]);
    let mut data = Vec::<u8>::new();
    assert!(d.read(&mut data).unwrap() == 0);
}