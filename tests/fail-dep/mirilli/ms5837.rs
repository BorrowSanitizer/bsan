//@run:1
// This test is adapted from `crc4` in `ms5837` at version 0.2.1
#[allow(unused_imports)]
use ms5837::*;

mod c_implementation {
    extern "C" {
        // C implementation described in the data sheet.
        // This is test only to validate the rust implementation.
        pub fn crc4(buffer: *const u16) -> u8;
    }
}

fn main() {
    let c_input_buffer = [0xABCDu16, 1, 2, 3, 4, 5, 6, 7];
    unsafe {
        c_implementation::crc4(c_input_buffer.as_ptr());
    }
}