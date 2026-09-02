#ifndef BSAN_GC_H
#define BSAN_GC_H

// We use a variety of custom data structures
// for BorrowSanitizer's garbage collector. Each
// relies directly on `InternalMmapVector`, or
// uses a proxy (e.g. `DenseMap`, which is an
// `InternalMmapVector` underneath).

#include "bsan.h"
#include "bsan_array_set.h"
#include "sanitizer_common/sanitizer_array_ref.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_dense_map.h"
#include "sanitizer_common/sanitizer_vector.h"

using __sanitizer::ArrayRef;
using __sanitizer::DenseMap;
using __sanitizer::InternalMmapVectorNoCtor;

namespace __bsan {

typedef InternalMmapArraySet<BorTag> BorTagSet;

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
    other.drain([&](AllocInfo *info, BorTagSet &tags) {
      tags.forEach([&](BorTag tag) { set_[info].insert(tag); });
    });
  }

  // Removes all entries from the set, after executing the
  // given callback for each allocation.
  template <typename Fn> void drain(Fn visit) {
    set_.forEach([&](DenseMap<AllocInfo *, BorTagSet>::value_type &KV) {
      visit(KV.first, KV.second);
      KV.second.destroy();
      return true;
    });
    set_.clear();
  }

  // Retain only the provenance values that satisfy the given predicate.
  template <typename Fn> void retainIf(Fn retain) {
    InternalMmapVector<AllocInfo *> ToErase;
    set_.forEach([&](DenseMap<AllocInfo *, BorTagSet>::value_type &KV) {
      AllocInfo *info = KV.first;
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

  BorTagSet *find(AllocInfo *Info) {
    auto *KV = set_.find(Info);
    return KV ? &KV->second : nullptr;
  }

  const BorTagSet *find(AllocInfo *Info) const {
    const auto *KV = set_.find(Info);
    return KV ? &KV->second : nullptr;
  }

private:
  DenseMap<AllocInfo *, BorTagSet> set_;
};

} // namespace __bsan

#endif // BSAN_GC_H
