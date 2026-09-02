use alloc::vec::Vec;
use core::fmt::{self, Debug};
use core::mem;
use core::ops::{Deref, DerefMut};

use crate::helpers::ToUsize;

/// Intermediate key between a UniKeyMap and a UniValMap.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UniIndex {
    idx: u32,
}

impl UniIndex {
    pub fn root() -> Self {
        UniIndex { idx: 0 }
    }
    pub fn is_root(self) -> bool {
        self == Self::root()
    }
}

impl Debug for UniIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.idx.fmt(f)
    }
}

#[derive(Debug, Clone, Eq)]

pub struct UniValMap<V> {
    /// The mapping data. Thanks to Vec we get both fast accesses, and
    /// a memory-optimal representation if there are few deletions.
    data: Vec<Option<V>>,
}

impl<V: PartialEq> UniValMap<V> {
    /// Exact equality of two maps.
    /// Less accurate but faster than `equivalent`, mostly because
    /// of the fast path when the lengths are different.
    pub fn identical(&self, other: &Self) -> bool {
        self.data == other.data
    }

    /// Equality up to trailing `None`s of two maps, i.e.
    /// do they represent the same mapping ?
    pub fn equivalent(&self, other: &Self) -> bool {
        let min_len = self.data.len().min(other.data.len());
        self.data[min_len..].iter().all(Option::is_none)
            && other.data[min_len..].iter().all(Option::is_none)
            && (self.data[..min_len] == other.data[..min_len])
    }
}

impl<V: PartialEq> PartialEq for UniValMap<V> {
    /// 2023-05: We found that using `equivalent` rather than `identical`
    /// in the equality testing of the `RangeMap` is neutral for most
    /// benchmarks, while being quite beneficial for `zip-equal`
    /// and to a lesser extent for `unicode`, `slice-get-unchecked` and
    /// `backtraces` as well.
    fn eq(&self, other: &Self) -> bool {
        self.equivalent(other)
    }
}

impl<V> Default for UniValMap<V> {
    fn default() -> Self {
        Self { data: Vec::default() }
    }
}

impl<V> UniValMap<V> {
    /// Whether this index has an associated value.
    pub fn contains_idx(&self, idx: UniIndex) -> bool {
        self.data.get(idx.idx.to_usize()).and_then(Option::as_ref).is_some()
    }

    /// Reserve enough space to insert the value at the right index.
    fn extend_to_length(&mut self, len: usize) {
        if len > self.data.len() {
            let nb = len - self.data.len();
            self.data.reserve(nb);
            for _ in 0..nb {
                self.data.push(None);
            }
        }
    }

    /// Assign this key to a new index. Panics if the key is already assigned,
    /// use `get_or_insert` for a version that instead returns the existing
    /// assignment.
    #[track_caller]
    pub fn insert(&mut self, idx: UniIndex, val: V) {
        self.extend_to_length(idx.idx.to_usize() + 1);
        self.data[idx.idx.to_usize()] = Some(val);
    }

    /// Get the value at this index, if it exists.
    pub fn get(&self, idx: UniIndex) -> Option<&V> {
        self.data.get(idx.idx.to_usize()).and_then(Option::as_ref)
    }

    /// Get the value at this index mutably, if it exists.
    pub fn get_mut(&mut self, idx: UniIndex) -> Option<&mut V> {
        self.data.get_mut(idx.idx.to_usize()).and_then(Option::as_mut)
    }

    /// Delete any value associated with this index.
    /// Returns None if the value was not present, otherwise
    /// returns the previously stored value.
    pub fn remove(&mut self, idx: UniIndex) -> Option<V> {
        if idx.idx.to_usize() >= self.data.len() {
            return None;
        }
        let mut res = None;
        mem::swap(&mut res, &mut self.data[idx.idx.to_usize()]);
        res
    }

    /// Returns true if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.data.iter().all(|v| v.is_none())
    }

    /// Iterates over all key-value pairs in the map.
    pub fn iter(&self) -> impl Iterator<Item = (UniIndex, &V)> {
        self.data
            .iter()
            .enumerate()
            .filter_map(|(i, v)| v.as_ref().map(|r| (UniIndex { idx: i.try_into().unwrap() }, r)))
    }
}

/// From UniIndex to V
#[derive(Debug, Clone)]
pub struct UniKeyValMap<V> {
    mapping: UniValMap<V>,
    /// A counter used to hand out new indices.
    next_idx: u32,
    /// Indices that can be reused: memory gain when the map gets sparse
    /// due to many deletions.
    deassigned: Vec<u32>,
}

impl<V> Default for UniKeyValMap<V> {
    fn default() -> Self {
        Self { mapping: UniValMap::default(), next_idx: 0, deassigned: Vec::default() }
    }
}

impl<V> UniKeyValMap<V> {
    /// How many keys/index pairs are currently active.
    pub fn len(&self) -> usize {
        self.next_idx as usize - self.deassigned.len()
    }

    /// Assign this key to a new index. Panics if the key is already assigned,
    /// use `get_or_insert` for a version that instead returns the existing
    /// assignment.
    #[track_caller]
    pub fn insert(&mut self, val: V) -> UniIndex {
        // We want an unused index. First we attempt to find one from `deassigned`,
        // and if `deassigned` is empty we generate a fresh index.
        let idx = self.deassigned.pop().unwrap_or_else(|| {
            // `deassigned` is empty, so all keys in use are already in `mapping`.
            // The next available key is `mapping.len()`.
            self.next_idx.checked_add(1).expect("UniMap ran out of useable keys")
        });
        let idx = UniIndex { idx };
        self.mapping.insert(idx, val);
        idx
    }

    pub fn keys(&self) -> impl Iterator<Item = UniIndex> {
        self.data
            .iter()
            .enumerate()
            .filter_map(|(idx, opt_val)| opt_val.is_some().then_some(UniIndex { idx: idx as u32 }))
    }
}

/// An access to a single value of the map.
pub struct UniEntry<'a, V> {
    inner: &'a mut Option<V>,
}

impl<'a, V> UniValMap<V> {
    /// Get a wrapper around a mutable access to the value corresponding to `idx`.
    pub fn entry(&'a mut self, idx: UniIndex) -> UniEntry<'a, V> {
        self.extend_to_length(idx.idx.to_usize() + 1);
        UniEntry { inner: &mut self.data[idx.idx.to_usize()] }
    }
}

impl<V> Deref for UniKeyValMap<V> {
    type Target = UniValMap<V>;

    fn deref(&self) -> &Self::Target {
        &self.mapping
    }
}

impl<V> DerefMut for UniKeyValMap<V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.mapping
    }
}

impl<'a, V> UniEntry<'a, V> {
    /// Insert in the map and get the value.
    pub fn or_insert(&mut self, default: V) -> &mut V {
        if self.inner.is_none() {
            *self.inner = Some(default);
        }
        self.inner.as_mut().unwrap()
    }

    pub fn get(&self) -> Option<&V> {
        self.inner.as_ref()
    }
}

mod tests {
    use super::*;
    #[test]
    fn extend_to_length() {
        let mut km = UniKeyValMap::<char>::default();
        km.extend_to_length(10);
        assert!(km.data.len() == 10);
        km.extend_to_length(0);
        assert!(km.data.len() == 10);
        km.extend_to_length(10);
        assert!(km.data.len() == 10);
        km.extend_to_length(11);
        assert!(km.data.len() == 11);
    }

    #[test]
    fn test_sizes() {
        use crate::tree_borrows::tree::{LocationState, Node};
        assert_eq!(core::mem::size_of::<Node>(), 144);
        assert_eq!(core::mem::size_of::<LocationState>(), 3);
        assert_eq!(core::mem::size_of::<UniKeyValMap<Node>>(), 24);
        assert_eq!(core::mem::size_of::<UniKeyValMap<Node>>(), 24);
    }
}
