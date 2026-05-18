//@run:1
// This is a direct copy of the test `deflate::tests::zero_length_read_with_data`
// from `flate2` at 1.0.28. It was fixed in a subsequent version.
use flate2::{read, Compression};
use std::io::Read;

fn main() {
    let m = vec![3u8; 128 * 1024 + 1];
    let mut c = read::DeflateEncoder::new(&m[..], Compression::default());

    let mut result = Vec::new();
    c.read_to_end(&mut result).unwrap();

    let mut d = read::DeflateDecoder::new(&result[..]);
    let mut data = Vec::new();
    assert_eq!(d.read(&mut data).unwrap(), 0);
}