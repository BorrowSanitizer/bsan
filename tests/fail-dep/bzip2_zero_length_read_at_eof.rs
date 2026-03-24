//@run:1
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