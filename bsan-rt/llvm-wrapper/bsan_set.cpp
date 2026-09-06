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
  end_--;
}

void BorTagSet::EnsureCapacity(uptr req_size) {
  uptr old_capacity = last_ - begin_;
  uptr old_size = size();
  if (req_size > old_capacity) {
    uptr capacity = old_capacity * 2;
    if (capacity == 0)
      capacity = 16;
    if (capacity < req_size)
      capacity = req_size;

    BorTag *p = (BorTag *)InternalAlloc(capacity * sizeof(BorTag));

    // We only need to free and copy over if the set
    // already contains elements.
    if (old_capacity && capacity) {
      internal_memcpy(p, begin_, old_size * sizeof(BorTag));
      InternalFree(begin_);
    }

    begin_ = p;
    last_ = begin_ + capacity;
  }
  end_ = begin_ + req_size;
}

void ConcreteProvenanceSet::insert(Provenance prov) {
  if (prov.info != nullptr) {
    set_[prov.info].insert(prov.tag);
  }
}

void ConcreteProvenanceSet::remove(Provenance prov) {
  if (prov.info == nullptr) {
    return;
  }
  // Only erase the tag; leave the (possibly now-empty) tag set in place. erase
  // shifts in place and never frees, so this takes no allocator lock and is
  // safe to run while the world is stopped.
  if (auto *tags = find(prov.info)) {
    tags->erase(prov.tag);
  }
}

void ConcreteProvenanceSet::clear() {
  set_.forEach([](DenseMap<AllocInfo *, BorTagSet>::value_type &KV) {
    KV.second.clear();
    return true;
  });
}

bool ConcreteProvenanceSet::contains(Provenance prov) {
  if (auto *tags = find(prov.info)) {
    return tags->contains(prov.tag);
  }
  return false;
}

ConcreteProvenanceSet::~ConcreteProvenanceSet() {
  set_.forEach([](DenseMap<AllocInfo *, BorTagSet>::value_type &KV) {
    KV.second.reset();
    return true;
  });
}

} // namespace __bsan