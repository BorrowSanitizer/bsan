#include "bsan_set.h"
#include "bsan.h"

namespace __bsan {

uptr BorTagSet::lowerBound(BorTag Tag) const {
  // Binary search over the elements of the array
  uptr lo = 0;
  uptr hi = tags_.size();
  while (lo < hi) {
    uptr mid = lo + (hi - lo) / 2;
    if (tags_[mid] < Tag) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  return lo;
}

bool BorTagSet::contains(BorTag tag) const {
  uptr i = lowerBound(tag);
  return i < tags_.size() && tags_[i] == tag;
}

bool BorTagSet::insert(BorTag tag) {
  uptr i = lowerBound(tag);
  if (i < tags_.size() && tags_[i] == tag) {
    return false; // Already present.
  }
  tags_.push_back(tag);
  for (uptr j = tags_.size() - 1; j > i; --j) {
    tags_[j] = tags_[j - 1];
  }
  tags_[i] = tag;
  return true;
}

void BorTagSet::erase(BorTag tag) {
  uptr i = lowerBound(tag);
  if (i >= tags_.size() || tags_[i] != tag) {
    return;
  }
  // Shift the tail down in place, then drop the last slot. Never shrinks the
  // mapping, so this takes no allocator lock and is safe while the world is
  // stopped.
  for (uptr j = i; j + 1 < tags_.size(); ++j) {
    tags_[j] = tags_[j + 1];
  }
  tags_.pop_back();
}

void BorTagSet::destroy() {
  if (tags_.data()) {
    tags_.Destroy();
    // Reset to a valid empty state so the set is safe to reuse (e.g. if its
    // map bucket is repopulated) and so a second Destroy is a no-op.
    tags_.Initialize(0);
  }
}

bool ConcreteProvenanceSet::insert(Provenance prov) {
  if (prov.info == nullptr) {
    return false;
  }
  return set_[prov.info].insert(prov.tag);
}

void ConcreteProvenanceSet::remove(Provenance prov) {
  if (prov.info == nullptr) {
    return;
  }
  // Only erase the tag; leave the (possibly now-empty) tag set in place. Erase
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
    KV.second.destroy();
    return true;
  });
}

} // namespace __bsan