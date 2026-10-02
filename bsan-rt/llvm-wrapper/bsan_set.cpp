#include "bsan_set.h"
#include "bsan.h"

namespace __bsan {

uptr BorTagSet::LowerBound(BorTag Tag) const {
  // Binary search over the elements of the array
  uptr lo = 0;
  uptr hi = size();
  while (lo < hi) {
    uptr mid = lo + (hi - lo) / 2;
    if ((*this)[mid] < Tag) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  return lo;
}

bool BorTagSet::contains(BorTag tag) const {
  uptr i = LowerBound(tag);
  return i < size() && (*this)[i] == tag;
}

void BorTagSet::insert(BorTag tag) {
  uptr i = LowerBound(tag);

  if (i < size() && (*this)[i] == tag)
    return;

  EnsureCapacity(size() + 1);

  // Move up every tag after the index,
  // leaving an empty slot for the new tag.
  for (uptr j = size() - 1; j > i; --j) {
    (*this)[j] = (*this)[j - 1];
  }
  (*this)[i] = tag;
}

void BorTagSet::erase(BorTag tag) {
  uptr i = LowerBound(tag);
  if (i >= size() || (*this)[i] != tag) {
    return;
  }
  for (uptr j = i; j + 1 < size(); ++j) {
    (*this)[j] = (*this)[j + 1];
  }
  size_--;
}

void BorTagSet::EnsureCapacity(uptr req_size) {
  if (req_size > capacity_) {
    uptr capacity = capacity_ * 2;
    if (capacity < 16)
      capacity = 16;
    if (capacity < req_size)
      capacity = req_size;
    CHECK_LE(capacity, (u32)-1);

    BorTag *p = (BorTag *)InternalAlloc(capacity * sizeof(BorTag));
    internal_memcpy(p, data(), size_ * sizeof(BorTag));
    if (!isInline())
      InternalFree(heap_);

    heap_ = p;
    capacity_ = capacity;
  }
  size_ = req_size;
}

void ConcreteProvenanceSet::insert(BlockIndex idx) {
  if (!set_.contains(idx)) {
    set_[idx] = BorTagSet();
  }
}

void ConcreteProvenanceSet::insert(Provenance prov) {
  if (CONCRETE(prov.tag)) {
    set_[BLOCK_IDX(prov.block)].insert(prov.tag);
  }
}

void ConcreteProvenanceSet::clear() {
  set_.forEach([](DenseMap<BlockIndex, BorTagSet>::value_type &KV) {
    KV.second.clear();
    return true;
  });
}

bool ConcreteProvenanceSet::contains(BlockIndex idx) {
  return find(idx) != nullptr;
}

bool ConcreteProvenanceSet::contains(Provenance prov) {
  if (auto *tags = find(BLOCK_IDX(prov.block))) {
    return tags->contains(prov.tag);
  }
  return false;
}

ConcreteProvenanceSet::~ConcreteProvenanceSet() {
  set_.forEach([](DenseMap<BlockIndex, BorTagSet>::value_type &KV) {
    KV.second.reset();
    return true;
  });
}

} // namespace __bsan