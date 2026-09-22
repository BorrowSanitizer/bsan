#ifndef BSAN_SET_H
#define BSAN_SET_H

#include "bsan.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_dense_map.h"

using __sanitizer::DenseMap;

namespace __bsan {

// A set of borrow tags, implemented as a sorted array.
// We need this representation because the contents of the
// tag set are exposed to the Rust core. We provide a pointer
// to the list and its length, which becomes a slice. Using a
// `DenseMap`, or another C++ representation, could be more efficient
// but it would make the API more cumbersome.
class BorTagSet {
public:
  BorTagSet() : begin_(), end_(), last_() {}

  const BorTag *data() const { return begin_; }
  // Mutable access to the underlying array.
  BorTag *data() { return begin_; }
  uptr size() const { return (end_ - begin_); }

  void insert(BorTag Tag);
  void erase(BorTag Tag);
  bool contains(BorTag Tag) const;

  // Frees the underlying allocation.
  void reset() {
    if (begin_)
      InternalFree(begin_);
    begin_ = 0;
    end_ = 0;
    last_ = 0;
  }

  // Removes all elements of the list without freeing
  // the underlying allocation.
  void clear() { end_ = begin_; }

  BorTag &operator[](uptr i) {
    DCHECK_LT(i, end_ - begin_);
    return begin_[i];
  }

  const BorTag &operator[](uptr i) const {
    DCHECK_LT(i, end_ - begin_);
    return begin_[i];
  }

  template <typename Fn> void forEach(Fn fn) const {
    for (uptr i = 0; i < this->size(); ++i) {
      fn((*this)[i]);
    }
  }

  // Keep only the tags that satisfy the given predicate.
  template <typename Fn> void retainIf(Fn keep) {
    uptr w = 0;
    for (uptr r = 0; r < this->size(); ++r) {
      BorTag tag = (*this)[r];
      if (keep(tag)) {
        (*this)[w++] = tag;
      }
    }
    end_ = begin_ + w;
  }

private:
  BorTag *begin_;
  BorTag *end_;
  BorTag *last_;

  // Returns the index where this tag exists, or needs
  // to be inserted.
  uptr LowerBound(BorTag Tag) const;
  void EnsureCapacity(uptr size);
};

// A set of concrete provenance values (e.g. not wildcard, omnivalid, or null).
// Implemented as a mapping from allocations to sets of borrow tags.
class ConcreteProvenanceSet {
public:
  ConcreteProvenanceSet() = default;
  ~ConcreteProvenanceSet();
  ConcreteProvenanceSet(const ConcreteProvenanceSet &) = delete;
  ConcreteProvenanceSet &operator=(const ConcreteProvenanceSet &) = delete;

  void insert(Provenance Prov);
  void remove(Provenance Prov);

  void clear();
  bool contains(Provenance prov);

  void swap(ConcreteProvenanceSet &other) { set_.swap(other.set_); }

  // Removes all entries from the set, after executing the
  // given callback for each allocation.
  void takeFrom(ConcreteProvenanceSet &other) {
    other.drain([&](BlockIndex idx, BorTagSet &tags) {
      tags.forEach([&](BorTag tag) { set_[idx].insert(tag); });
    });
  }

  // Removes all entries from the set, after executing the
  // given callback for each allocation.
  template <typename Fn> void drain(Fn visit) {
    set_.forEach([&](DenseMap<BlockIndex, BorTagSet>::value_type &KV) {
      visit(KV.first, KV.second);
      KV.second.reset();
      return true;
    });
    set_.clear();
  }

  // Retain only the provenance values that satisfy the given predicate.
  template <typename Fn> void retainIf(Fn retain) {
    InternalMmapVector<BlockIndex> ToErase;
    set_.forEach([&](DenseMap<BlockIndex, BorTagSet>::value_type &KV) {
      BlockIndex idx = KV.first;
      KV.second.retainIf([&](BorTag tag) { return retain(idx, tag); });
      if (KV.second.size() == 0) {
        KV.second.reset();
        ToErase.push_back(idx);
      }
      return true;
    });
    for (unsigned i = 0; i < ToErase.size(); ++i)
      set_.erase(ToErase[i]);
  }

  BorTagSet *find(BlockIndex idx) {
    auto *KV = set_.find(idx);
    return KV ? &KV->second : nullptr;
  }

  const BorTagSet *find(BlockIndex idx) const {
    const auto *KV = set_.find(idx);
    return KV ? &KV->second : nullptr;
  }

private:
  DenseMap<BlockIndex, BorTagSet> set_;
};

} // namespace __bsan

#endif // BSAN_GC_H
