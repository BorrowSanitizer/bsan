use alloc::alloc::Global;
use core::{fmt, ops};

use hashbrown::{HashMap, HashSet};
use rustc_hash::FxBuildHasher;

#[allow(dead_code)]
pub type FxHashSet<T, A = Global> = HashSet<T, FxBuildHasher, A>;
pub type FxHashMap<K, V, A = Global> = HashMap<K, V, FxBuildHasher, A>;

/// Unique identifier for `Size` (used in Tree Borrows implementation)
#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Size(u64);

// Abstraction to get number of bits/bytes. Internally stores as bytes
impl Size {
    pub const ZERO: Size = Size(0);
    pub const MAX: Size = Size(u64::MAX);
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

    /// Get a Size defined by a number of bytes
    pub fn from_addr<T>(ptr: impl TryInto<*mut T>) -> Size {
        Self::from_bytes(ptr.try_into().ok().unwrap().addr())
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

impl fmt::LowerHex for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
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

impl ops::Sub for Size {
    type Output = Size;
    fn sub(self, other: Size) -> Size {
        Size::from_bytes(self.bytes().checked_sub(other.bytes()).unwrap_or_else(|| {
            panic!("Size::sub: {} - {} underflows u64", self.bytes(), other.bytes())
        }))
    }
}

#[derive(Copy, Clone, PartialEq)]
pub struct AllocRange {
    pub start: Size,
    pub size: Size,
}

#[inline]
pub fn alloc_range(start: Size, size: Size) -> AllocRange {
    AllocRange { start, size }
}

#[allow(unused)]
impl AllocRange {
    #[inline]
    pub fn end(self) -> Size {
        self.start + self.size // This does overflow checking.
    }

    /// Returns the `subrange` within this range; panics if it is not a subrange.
    #[inline]
    pub fn subrange(self, subrange: AllocRange) -> AllocRange {
        let sub_start = self.start + subrange.start;
        let range = alloc_range(sub_start, subrange.size);
        assert!(range.end() <= self.end(), "access outside the bounds for given AllocRange");
        range
    }

    #[inline]
    pub fn relative_to(&self, start: Size) -> Option<AllocRange> {
        self.within_range(start).then_some(Self {
            start: Size::from_bytes(start.bytes() - self.start.bytes()),
            size: self.size,
        })
    }

    #[inline]
    pub fn within_range(&self, size: Size) -> bool {
        size >= self.start && size < self.end()
    }
}

impl fmt::Debug for AllocRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("[{0:#x}..{1:#x}]", self.start.bytes(), self.end().bytes()))
    }
}

impl fmt::Display for AllocRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

pub trait ToUsize {
    fn to_usize(self) -> usize;
}

impl ToUsize for u32 {
    fn to_usize(self) -> usize {
        self.try_into().unwrap()
    }
}
