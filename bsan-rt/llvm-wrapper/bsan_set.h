#ifndef BSAN_GC_H
#define BSAN_GC_H

// We use a variety of custom data structures
// for BorrowSanitizer's garbage collector. Each
// relies directly on `InternalMmapVector`, or
// uses a proxy (e.g. `DenseMap`, which is an
// `InternalMmapVector` underneath).

#include "bsan.h"
#include "sanitizer_common/sanitizer_array_ref.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_dense_map.h"
#include "sanitizer_common/sanitizer_vector.h"

using __sanitizer::ArrayRef;
using __sanitizer::DenseMap;
using __sanitizer::InternalMmapVectorNoCtor;

namespace __bsan {

// A set of borrow tags, implemented as a sorted array.
// We need this representation because the contents of the
// tag set are exposed to the Rust core. We provide a pointer
// to the list and its length, which becomes a slice. Using a
// `DenseMap`, or another C++ representation, could be more efficient
// but it would make the API more cumbersome.
class BorTagSet {
public:
  void insert(BorTag Tag);
  void erase(BorTag Tag);
  bool contains(BorTag Tag) const;

  // Removes all elements of the list without freeing
  // the underlying allocation.
  void clear() { tags_.clear(); }

  // Removes all elements of the list and frees the
  // underlying allocation. This is idempotent.
  void destroy();

  const BorTag *data() const { return tags_.data(); }
  // Mutable access to the underlying array.
  BorTag *data() { return tags_.data(); }
  uptr size() const { return tags_.size(); }

  template <typename Fn> void forEach(Fn fn) const {
    for (uptr i = 0; i < tags_.size(); ++i) {
      fn(tags_[i]);
    }
  }

  // Keep only the tags that satisfy the given predicate.
  template <typename Fn> void retainIf(Fn keep) {
    uptr w = 0;
    for (uptr r = 0; r < tags_.size(); ++r) {
      BorTag tag = tags_[r];
      if (keep(tag)) {
        tags_[w++] = tag;
      }
    }
    tags_.resize(w);
  }

private:
  // Returns the index where this tag exists, or needs
  // to be inserted.
  uptr lowerBound(BorTag Tag) const;
  InternalMmapVectorNoCtor<BorTag> tags_{};
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
    other.drain([&](Block *info, BorTagSet &tags) {
      tags.forEach([&](BorTag tag) { set_[info].insert(tag); });
    });
  }

  // Removes all entries from the set, after executing the
  // given callback for each allocation.
  template <typename Fn> void drain(Fn visit) {
    set_.forEach([&](DenseMap<Block *, BorTagSet>::value_type &KV) {
      visit(KV.first, KV.second);
      KV.second.destroy();
      return true;
    });
    set_.clear();
  }

  // Retain only the provenance values that satisfy the given predicate.
  template <typename Fn> void retainIf(Fn retain) {
    InternalMmapVector<Block *> ToErase;
    set_.forEach([&](DenseMap<Block *, BorTagSet>::value_type &KV) {
      Block *info = KV.first;
      KV.second.retainIf([&](BorTag tag) { return retain(info, tag); });
      if (KV.second.size() == 0) {
        KV.second.destroy();
        ToErase.push_back(info);
      }
      return true;
    });
    for (unsigned Idx = 0; Idx < ToErase.size(); ++Idx)
      set_.erase(ToErase[Idx]);
  }

  BorTagSet *find(Block *Info) {
    auto *KV = set_.find(Info);
    return KV ? &KV->second : nullptr;
  }

  const BorTagSet *find(Block *Info) const {
    const auto *KV = set_.find(Info);
    return KV ? &KV->second : nullptr;
  }

private:
  DenseMap<Block *, BorTagSet> set_;
};

} // namespace __bsan

#endif // BSAN_GC_H
