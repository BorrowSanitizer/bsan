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
  // Insert (node, tag) without reading node->tag (GC re-queue).
  void insertTag(Node *node, BorTag tag);

  void clear();
  bool contains(Provenance prov);
  // Explicit tag (MergeZeroCounts keeps node and tag separate).
  bool contains(Node *node, BorTag tag);

  void swap(ConcreteProvenanceSet &other) { set_.swap(other.set_); }

  // Removes all entries from the set, after executing the
  // given callback for each allocation.
  template <typename Fn> void drain(Fn visit) {
    set_.forEach([&](DenseMap<Node *, BorTagSet>::value_type &KV) {
      visit(KV.first, KV.second);
      KV.second.destroy();
      set_.erase(KV.first);
      return true;
    });
  }

  // Retain only the provenance values that satisfy the given predicate.
  template <typename Fn> void retainIf(Fn retain) {
    set_.forEach([&](DenseMap<Node *, BorTagSet>::value_type &KV) {
      Node *node = KV.first;
      KV.second.retainIf([&](BorTag tag) { return retain(node, tag); });
      if (KV.second.size() == 0) {
        KV.second.destroy();
        set_.erase(node);
      }
      return true;
    });
  }

  BorTagSet *find(Node *node);
  const BorTagSet *find(Node *node) const;

private:
  DenseMap<Node *, BorTagSet> set_;
};

} // namespace __bsan

#endif // BSAN_GC_H
