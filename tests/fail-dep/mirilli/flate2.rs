//@run:1
// This is a direct copy of the test `deflate::tests::zero_length_read_with_data`
// from `flate2` at 1.0.28. It was fixed in a subsequent version. This is the same
// error, but a different test case than the one used in the MiriLLI study. That used
// `deflate::tests::drop_writes`, which is slow in our current version.
use flate2::{read, Compression};
use std::io::Read;

fn main() {
    zero_length_read_with_data();
}

fn zero_length_read_with_data() {
    let m = vec![3u8; 128 * 1024 + 1];
    let mut c = read::DeflateEncoder::new(&m[..], Compression::default());

    let mut result = Vec::new();
    c.read_to_end(&mut result).unwrap();

    let mut d = read::DeflateDecoder::new(&result[..]);
    let mut data = Vec::new();
    assert_eq!(d.read(&mut data).unwrap(), 0);
}

/* 
fn drop_writes() {
    let mut data = Vec::new();
    write::DeflateEncoder::new(&mut data, Compression::default())
        .write_all(b"foo")
        .unwrap();
    let mut r = read::DeflateDecoder::new(&data[..]);
    let mut ret = Vec::new();
    r.read_to_end(&mut ret).unwrap();
    assert_eq!(ret, b"foo");
}
*/
