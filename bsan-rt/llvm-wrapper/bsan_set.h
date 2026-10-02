#ifndef BSAN_SET_H
#define BSAN_SET_H

#include "bsan.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_dense_map.h"

using __sanitizer::DenseMap;

namespace __bsan {

// A set of borrow tags, implemented as a sorted array.
// This has inline capacity for 2 tags, which covers the
// overwhelming majority of all trees for all allocations.
// We need a custom representation, instead of using
// Vector<BorTag>, because the sanitizer vector does not
// have a copy constructor, and we need to use this as the
// value in a DenseMap.
class BorTagSet {
public:
  static constexpr u32 kInlineCapacity = 2;

  BorTagSet() : size_(0), capacity_(kInlineCapacity), heap_(nullptr) {}

  const BorTag *data() const { return isInline() ? inline_ : heap_; }
  // Mutable access to the underlying array.
  BorTag *data() { return isInline() ? inline_ : heap_; }
  uptr size() const { return size_; }

  void insert(BorTag Tag);
  void erase(BorTag Tag);
  bool contains(BorTag Tag) const;

  // Frees the underlying allocation.
  void reset() {
    if (!isInline())
      InternalFree(heap_);
    size_ = 0;
    capacity_ = kInlineCapacity;
    heap_ = nullptr;
  }

  // Removes all elements of the list without freeing
  // the underlying allocation.
  void clear() { size_ = 0; }

  BorTag &operator[](uptr i) {
    DCHECK_LT(i, size_);
    return data()[i];
  }

  const BorTag &operator[](uptr i) const {
    DCHECK_LT(i, size_);
    return data()[i];
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
    size_ = w;
  }

private:
  u32 size_;
  u32 capacity_;
  union {
    BorTag inline_[kInlineCapacity];
    BorTag *heap_;
  };

  bool isInline() const { return capacity_ <= kInlineCapacity; }

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
  void insert(BlockIndex idx);

  void clear();
  bool contains(Provenance prov);
  bool contains(BlockIndex idx);

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