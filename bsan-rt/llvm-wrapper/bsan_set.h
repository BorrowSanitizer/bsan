#ifndef BSAN_GC_H
#define BSAN_GC_H
#include "bsan.h"
#include "sanitizer_common/sanitizer_array_ref.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_dense_map.h"

using __sanitizer::DenseMap;
using __sanitizer::Vector;

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

  const BorTag *Data() const { return begin_; }
  // Mutable access to the underlying array.
  BorTag *Data() { return begin_; }
  uptr Size() const { return (end_ - begin_); }

  void Insert(BorTag Tag);
  void Erase(BorTag Tag);
  bool Contains(BorTag Tag) const;

  // Frees the underlying allocation.
  void Reset() {
    if (begin_)
      InternalFree(begin_);
    begin_ = 0;
    end_ = 0;
    last_ = 0;
  }

  // Removes all elements of the list without freeing
  // the underlying allocation.
  void Clear() { end_ = begin_; }

  BorTag &operator[](uptr i) {
    DCHECK_LT(i, end_ - begin_);
    return begin_[i];
  }

  const BorTag &operator[](uptr i) const {
    DCHECK_LT(i, end_ - begin_);
    return begin_[i];
  }

  template <typename Fn> void forEach(Fn fn) const {
    for (uptr i = 0; i < this->Size(); ++i) {
      fn((*this)[i]);
    }
  }

  // Keep only the tags that satisfy the given predicate.
  template <typename Fn> void retainIf(Fn keep) {
    uptr w = 0;
    for (uptr r = 0; r < this->Size(); ++r) {
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

  void insert(BlockIndex Idx, BorTag Tag);
  void remove(BlockIndex Idx, BorTag Tag);

  void clear();
  bool contains(BlockIndex Idx, BorTag Tag);

  void swap(ConcreteProvenanceSet &other) { set_.swap(other.set_); }

  // Removes all entries from the set, after executing the
  // given callback for each allocation.
  void takeFrom(ConcreteProvenanceSet &other) {
    other.drain([&](BlockIndex info, BorTagSet &tags) {
      tags.forEach([&](BorTag tag) { set_[info].Insert(tag); });
    });
  }

  // Removes all entries from the set, after executing the
  // given callback for each allocation.
  template <typename Fn> void drain(Fn visit) {
    set_.forEach([&](DenseMap<BlockIndex, BorTagSet>::value_type &KV) {
      visit(KV.first, KV.second);
      KV.second.Reset();
      return true;
    });
    set_.clear();
  }

  // Retain only the provenance values that satisfy the given predicate.
  template <typename Fn> void retainIf(Fn retain) {
    Vector<BlockIndex> ToErase;
    set_.forEach([&](DenseMap<BlockIndex, BorTagSet>::value_type &KV) {
      BlockIndex info = KV.first;
      KV.second.retainIf([&](BorTag tag) { return retain(info, tag); });
      if (KV.second.Size() == 0) {
        KV.second.Reset();
        ToErase.PushBack(info);
      }
      return true;
    });
    for (unsigned Idx = 0; Idx < ToErase.Size(); ++Idx)
      set_.erase(ToErase[Idx]);
  }

  BorTagSet *find(BlockIndex Idx) {
    auto *KV = set_.find(Idx);
    return KV ? &KV->second : nullptr;
  }

  const BorTagSet *find(BlockIndex Idx) const {
    const auto *KV = set_.find(Idx);
    return KV ? &KV->second : nullptr;
  }

private:
  DenseMap<BlockIndex, BorTagSet> set_;
};

} // namespace __bsan

#endif // BSAN_GC_H
