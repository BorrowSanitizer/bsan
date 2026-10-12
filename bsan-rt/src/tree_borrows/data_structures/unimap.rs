//! This module implements the `UniMap`, which is a way to get efficient mappings
//! optimized for the setting of `tree_borrows/tree.rs`.
//!
//! A `UniKeyMap<K>` is a (slow) mapping from `K` to `UniIndex`,
//! and `UniValMap<V>` is a (fast) mapping from `UniIndex` to `V`.
//! Thus a pair `(UniKeyMap<K>, UniValMap<V>)` acts as a virtual `HashMap<K, V>`.
//!
//! Because of the asymmetry in access time, the use-case for `UniMap` is the following:
//! a tuple `(UniKeyMap<K>, Vec<UniValMap<V>>)` is much more efficient than
//! the equivalent `Vec<HashMap<K, V>>` it represents if all maps have similar
//! sets of keys.

#![allow(dead_code)]

use alloc::vec::Vec;
use core::fmt::{self, Debug};
use core::hash::Hash;
use core::mem;

use crate::helpers::{FxHashMap, ToUsize};

/// Intermediate key between a UniKeyMap and a UniValMap.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct UniIndex(pub u32);

impl Debug for UniIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// From K to UniIndex
#[derive(Debug, Clone)]
pub struct UniKeyValMap<V> {
    data: UniValMap<V>,
    /// Indexes that can be reused: memory gain when the map gets sparse
    /// due to many deletions.
    deassigned: Vec<UniIndex>,
}

/// From UniIndex to V
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

impl<V> Default for UniKeyValMap<V> {
    fn default() -> Self {
        Self { data: UniValMap::default(), deassigned: Vec::default() }
    }
}

impl<V> Default for UniValMap<V> {
    fn default() -> Self {
        Self { data: Vec::default() }
    }
}

impl<V> UniKeyValMap<V> {
    /// How many keys/index pairs are currently active.
    pub fn len(&self) -> usize {
        self.data.len() - self.deassigned.len()
    }

    /// Assign this key to a new index. Panics if the key is already assigned,
    /// use `get_or_insert` for a version that instead returns the existing
    /// assignment.
    #[track_caller]
    pub fn insert(&mut self, val: V) -> UniIndex {
        // We want an unused index. First we attempt to find one from `deassigned`,
        // and if `deassigned` is empty we generate a fresh index.
        let idx = self.deassigned.pop().unwrap_or_else(|| {
            UniIndex(self.data.len().try_into().expect("`UniValMap` ran out of useable keys"))
        });
        if self.data.get(idx).is_some() {
            panic!(
                "This key is already assigned to a different index; either use `get_or_insert` instead if you care about this data, or first call `remove` to undo the preexisting assignment."
            );
        };
        self.data.insert(idx, val);
        idx
    }

    /// Return whatever index this key was using to the deassigned pool.
    ///
    /// Note: calling this function can be dangerous. If the index still exists
    /// somewhere in a `UniValMap` and is reassigned by the `UniKeyMap` then
    /// it will inherit the old value of a completely unrelated key.
    /// If you `UniKeyMap::remove` a key you should make sure to also `UniValMap::remove`
    /// the associated `UniIndex` from ALL `UniValMap`s.
    ///
    /// Example of such behavior:
    /// ```rust,ignore (private type can't be doctested)
    /// let mut keymap = UniKeyMap::<char>::default();
    /// let mut valmap = UniValMap::<char>::default();
    /// // Insert 'a' -> _ -> 'A'
    /// let idx_a = keymap.insert('a');
    /// valmap.insert(idx_a, 'A');
    /// // Remove 'a' -> _, but forget to remove _ -> 'A'
    /// keymap.remove(&'a');
    /// // valmap.remove(idx_a); // If we uncomment this line the issue is fixed
    /// // Insert 'b' -> _
    /// let idx_b = keymap.insert('b');
    /// let val_b = valmap.get(idx_b);
    /// assert_eq!(val_b, Some('A')); // Oh no
    /// // assert_eq!(val_b, None); // This is what we would have expected
    /// ```
    pub fn remove(&mut self, idx: UniIndex) -> Option<V> {
        self.data.remove(idx).and_then(|v| {
            self.deassigned.push(idx);
            Some(v)
        })
    }

    pub fn contains_idx(&self, idx: UniIndex) -> bool {
        self.data.contains_idx(idx)
    }

    pub fn get(&self, idx: UniIndex) -> Option<&V> {
        self.data.get(idx)
    }

    /// Get the value at this index mutably, if it exists.
    pub fn get_mut(&mut self, idx: UniIndex) -> Option<&mut V> {
        self.data.get_mut(idx)
    }

    /// Iterates over all key-value pairs in the map.
    pub fn iter(&self) -> impl Iterator<Item = (UniIndex, &V)> {
        self.data.iter()
    }

    /// Returns true if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl<V> UniValMap<V> {
    /// Returns the length of the underlying vector. Private, because
    /// this is only meaningful in the context of the number of deassigned
    /// keys of a `UniKeyValMap`.
    fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether this index has an associated value.
    pub fn contains_idx(&self, idx: UniIndex) -> bool {
        self.data.get(idx.0.to_usize()).and_then(Option::as_ref).is_some()
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

    /// Assign a value to the index. Returns the previous value, if there
    /// was one.
    pub fn insert(&mut self, idx: UniIndex, val: V) -> Option<V> {
        self.extend_to_length(idx.0.to_usize() + 1);
        mem::replace(&mut self.data[idx.0.to_usize()], Some(val))
    }

    /// Get the value at this index, if it exists.
    pub fn get(&self, idx: UniIndex) -> Option<&V> {
        self.data.get(idx.0.to_usize()).and_then(Option::as_ref)
    }

    /// Get the value at this index mutably, if it exists.
    pub fn get_mut(&mut self, idx: UniIndex) -> Option<&mut V> {
        self.data.get_mut(idx.0.to_usize()).and_then(Option::as_mut)
    }

    /// Delete any value associated with this index.
    /// Returns None if the value was not present, otherwise
    /// returns the previously stored value.
    pub fn remove(&mut self, idx: UniIndex) -> Option<V> {
        if idx.0.to_usize() >= self.data.len() {
            return None;
        }
        let mut res = None;
        mem::swap(&mut res, &mut self.data[idx.0.to_usize()]);
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
            .filter_map(|(i, v)| v.as_ref().map(|r| (UniIndex(i.try_into().unwrap()), r)))
    }
}

/// An access to a single value of the map.
pub struct UniEntry<'a, V> {
    inner: &'a mut Option<V>,
}

impl<'a, V> UniValMap<V> {
    /// Get a wrapper around a mutable access to the value corresponding to `idx`.
    pub fn entry(&'a mut self, idx: UniIndex) -> UniEntry<'a, V> {
        self.extend_to_length(idx.0.to_usize() + 1);
        UniEntry { inner: &mut self.data[idx.0.to_usize()] }
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
        let mut km = UniValMap::<char>::default();
        km.extend_to_length(10);
        assert!(km.data.len() == 10);
        km.extend_to_length(0);
        assert!(km.data.len() == 10);
        km.extend_to_length(10);
        assert!(km.data.len() == 10);
        km.extend_to_length(11);
        assert!(km.data.len() == 11);
    }

    #[derive(Default)]
    struct MapWitness<V> {
        key: UniKeyValMap<V>,
        map: FxHashMap<UniIndex, V>,
    }

    impl<V> MapWitness<V>
    where
        V: Copy + Eq + fmt::Debug,
    {
        fn insert(&mut self, v: V) -> UniIndex {
            // UniMap
            let i = self.key.insert(v);
            // HashMap
            self.map.insert(i, v);
            // Consistency: nothing to check
            i
        }

        fn get(&self, i: UniIndex) {
            // UniMap
            let v1 = self.key.get(i);
            // HashMap
            let v2 = self.map.get(&i);
            // Consistency
            assert_eq!(v1, v2);
        }

        fn get_mut(&mut self, i: UniIndex) {
            // UniMap
            let v1 = self.key.get_mut(i);
            // HashMap
            let v2 = self.map.get_mut(&i);
            // Consistency
            assert_eq!(v1, v2);
        }
        fn remove(&mut self, i: UniIndex) {
            // UniMap
            if self.key.get(i).is_some() {
                self.key.remove(i);
            }
            // HashMap
            self.map.remove(&i);
            // Consistency: nothing to check
        }
    }

    #[test]
    fn consistency_small() {
        let mut m = MapWitness::<char>::default();
        let a = m.insert('a');
        let b = m.insert('b');
        m.get(a);
        m.get_mut(b);
        m.remove(b);
        let c = m.insert('c');
        m.get(a);
        let d = m.insert('d');
        let e = m.insert('e');
        let f = m.insert('f');
        m.get(b);
        m.get(c);
        m.get(d);
        m.get(e);
        m.get(f);
        m.remove(UniIndex(100));
        m.get_mut(UniIndex(100));
        m.get(UniIndex(100));
    }

    #[test]
    fn test_sizes() {
        use crate::tree_borrows::tree::{LocationState, Node};
        assert_eq!(core::mem::size_of::<Node>(), 144);
        assert_eq!(core::mem::size_of::<LocationState>(), 3);
        assert_eq!(core::mem::size_of::<UniValMap<Node>>(), 24);
        assert_eq!(core::mem::size_of::<UniKeyValMap<Node>>(), 48);
    }
}
