use core::fmt;

// Ported from rustc_abi

/// Unique identifier for `Size` (used in Tree Borrows implementation)
#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Size(u64);

// Abstraction to get number of bits/bytes. Internally stores as bytes
#[allow(dead_code)]
impl Size {
    pub const ZERO: Size = Size(0);
    /// Get a Size defined by a number of bits
    /// Rounds `bits` up to the next-higher byte boundary, if `bits` is
    /// not a multiple of 8.
    pub fn from_bits(bits: impl TryInto<u64>) -> Size {
        let bits = bits.try_into().ok().unwrap();

        // Avoid potential overflow from `bits + 7`.
        Size(bits / 8 + ((bits % 8) + 7) / 8)
    }
    /// Get a Size defined by a number of bytesi
    pub fn from_bytes(bytes: impl TryInto<u64>) -> Size {
        Size(bytes.try_into().ok().unwrap())
    }
    /// Get the number of bytes in a size
    pub fn bytes(self) -> u64 {
        self.0
    }
    /// Get the number of bytes in a size as a usize
    pub fn bytes_usize(self) -> usize {
        self.0.try_into().unwrap()
    }
    /// Get the number of bits in a size
    /// Could overflow if the number of bytes represented as bits does not fit as a u64
    /// Use usize if working with very large values
    pub fn bits(self) -> u64 {
        self.bytes().checked_mul(8).unwrap()
    }
    /// Get the number of bits in a size as usize
    pub fn bits_usize(self) -> usize {
        self.bits().try_into().unwrap()
    }
}

impl fmt::Debug for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "s{}", self.0)
        } else {
            write!(f, "size{}", self.0)
        }
    }
}
