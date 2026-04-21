use alloc::alloc::Global;
use core::{fmt, ops};

use hashbrown::{HashMap, HashSet};
use rustc_hash::FxBuildHasher;

#[allow(unused)]
pub type FxHashSet<T, A = Global> = HashSet<T, FxBuildHasher, A>;
pub type FxHashMap<K, V, A = Global> = HashMap<K, V, FxBuildHasher, A>;

/// Unique identifier for `Size` (used in Tree Borrows implementation)
#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Size(u64);

// Abstraction to get number of bits/bytes. Internally stores as bytes
impl Size {
    pub const ZERO: Size = Size(0);
    /// Get a Size defined by a number of bits
    /// Rounds `bits` up to the next-higher byte boundary, if `bits` is
    /// not a multiple of 8.
    #[cfg(test)]
    pub fn from_bits(bits: impl TryInto<u64>) -> Size {
        let bits = bits.try_into().ok().unwrap();

        // Avoid potential overflow from `bits + 7`.
        Size(bits / 8 + (bits % 8).div_ceil(8))
    }
    /// Get a Size defined by a number of bytes
    pub fn from_bytes(bytes: impl TryInto<u64>) -> Size {
        Size(bytes.try_into().ok().unwrap())
    }
    /// Get the number of bytes in a size
    pub fn bytes(self) -> u64 {
        self.0
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

impl ops::Add for Size {
    type Output = Size;

    fn add(self, other: Size) -> Size {
        Size::from_bytes(self.bytes().checked_add(other.bytes()).unwrap_or_else(|| {
            panic!("Size::add: {} + {} doesn't fit in u64", self.bytes(), other.bytes())
        }))
    }
}
