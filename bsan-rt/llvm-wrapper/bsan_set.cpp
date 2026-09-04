#include "bsan_set.h"
#include "bsan.h"

namespace __bsan {

uptr BorTagSet::LowerBound(BorTag Tag) const {
  // Binary search over the elements of the array
  uptr lo = 0;
  uptr hi = Size();
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

bool BorTagSet::Contains(BorTag tag) const {
  uptr i = LowerBound(tag);
  return i < Size() && (*this)[i] == tag;
}

void BorTagSet::Insert(BorTag tag) {
  uptr i = LowerBound(tag);

  if (i < Size() && (*this)[i] == tag)
    return;

  EnsureCapacity(Size() + 1);

  // Move up every tag after the index,
  // leaving an empty slot for the new tag.
  for (uptr j = Size() - 1; j > i; --j) {
    (*this)[j] = (*this)[j - 1];
  }
  (*this)[i] = tag;
}

void BorTagSet::Erase(BorTag tag) {
  uptr i = LowerBound(tag);
  if (i >= Size() || (*this)[i] != tag) {
    return;
  }
  for (uptr j = i; j + 1 < Size(); ++j) {
    (*this)[j] = (*this)[j + 1];
  }
  end_--;
}

void BorTagSet::EnsureCapacity(uptr req_size) {
  uptr old_capacity = last_ - begin_;
  if (req_size > old_capacity) {
    uptr capacity = old_capacity * 5 / 4; // 25% growth
    if (capacity == 0)
      capacity = 16;
    if (capacity < req_size)
      capacity = req_size;

    BorTag *p = (BorTag *)InternalAlloc(capacity * sizeof(BorTag));

    if (capacity) {
      internal_memcpy(p, begin_, old_capacity * sizeof(BorTag));
      InternalFree(begin_);
    }

    begin_ = p;
    last_ = begin_ + capacity;
  }
  end_ = begin_ + req_size;
}

void ConcreteProvenanceSet::insert(BlockIndex Idx, BorTag Tag) {
  if (Idx != 0) {
    set_[Idx].Insert(Tag);
  }
}

void ConcreteProvenanceSet::remove(BlockIndex Idx, BorTag Tag) {
  if (Idx == 0)
    return;
  if (auto *tags = find(Idx)) {
    tags->Erase(Tag);
  }
}

void ConcreteProvenanceSet::clear() {
  set_.forEach([](DenseMap<BlockIndex, BorTagSet>::value_type &KV) {
    KV.second.Reset();
    return true;
  });
}

bool ConcreteProvenanceSet::contains(BlockIndex Idx, BorTag Tag) {
  if (auto *tags = find(Idx)) {
    return tags->Contains(Tag);
  }
  return false;
}

ConcreteProvenanceSet::~ConcreteProvenanceSet() {
  set_.forEach([](DenseMap<BlockIndex, BorTagSet>::value_type &KV) {
    KV.second.Reset();
    return true;
  });
}

} // namespace __bsan