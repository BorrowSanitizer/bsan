#ifndef BSAN_GC_H
#define BSAN_GC_H

#include "bsan.h"
#include "sanitizer_common/sanitizer_array_ref.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_dense_map.h"
using __sanitizer::ArrayRef;
using __sanitizer::DenseMap;
using __sanitizer::InternalMmapVectorNoCtor;

namespace __bsan {

class ConcreteTagSet {
public:
  void insert(BorTag Tag);
  void erase(BorTag Tag);
  bool contains(BorTag Tag) const;

  void clear() { tags_.clear(); }
  void destroy();

  const BorTag *data() const { return tags_.data(); }
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

  // Removes all entries from the set, after executing the
  // given callback for each allocation.
  template <typename Fn> void drain(Fn visit) {
    set_.forEach([&](DenseMap<AllocInfo *, ConcreteTagSet>::value_type &KV) {
      visit(KV.first, KV.second);
      KV.second.destroy();
      set_.erase(KV.first);
      return true;
    });
  }

  // Retain only the provenance values that satisfy the given predicate.
  template <typename Fn> void retainIf(Fn retain) {
    set_.forEach([&](DenseMap<AllocInfo *, ConcreteTagSet>::value_type &KV) {
      AllocInfo *info = KV.first;
      KV.second.retainIf([&](BorTag tag) { return retain(info, tag); });
      if (KV.second.size() == 0) {
        KV.second.destroy();
        set_.erase(info);
      }
      return true;
    });
  }

  ConcreteTagSet *find(AllocInfo *Info) {
    auto *KV = set_.find(Info);
    return KV ? &KV->second : nullptr;
  }

  const ConcreteTagSet *find(AllocInfo *Info) const {
    const auto *KV = set_.find(Info);
    return KV ? &KV->second : nullptr;
  }

private:
  DenseMap<AllocInfo *, ConcreteTagSet> set_;
};

} // namespace __bsan

#endif // BSAN_GC_H
