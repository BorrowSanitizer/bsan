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

#[macro_export]
macro_rules! vec_in {
    ($alloc:expr) => {
        Vec::new_in(alloc)
    };

    // Handle the custom "Elem" syntax for range initialization
    // This is more specific, so it must come before the next arm.
    ($alloc:expr, Elem { range: $range:expr, init: $init:expr }) => (
        {
            let init_fn = $init;
            let range = $range;

            // Be efficient: pre-allocate if the iterator gives a size hint
            let (lower, upper) = range.size_hint();
            let capacity = upper.unwrap_or(lower);
            let mut vec = Vec::with_capacity_in(capacity, $alloc);

            // Create the items by iterating and calling the initializer
            for i in range {
                vec.push(init_fn(i));
            }
            vec
        }
    );

    // Handle a comma-separated list of expressions (your original arm)
    // This is a general "catch-all", so it must come last.
    ($alloc:expr, $($x:expr),+ $(,)?) => (
        {
            // This is a simple way, but not the most efficient for many elements.
            // A more advanced macro could count the elements to pre-allocate.
            let mut vec = Vec::new_in($alloc);
            $(
                vec.push($x);
            )+
            vec
        }
    );
}
