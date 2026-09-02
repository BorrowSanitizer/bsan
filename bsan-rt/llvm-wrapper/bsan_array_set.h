#ifndef BSAN_ARRAY_SET_H
#define BSAN_ARRAY_SET_H

#include "sanitizer_common/sanitizer_common.h"

// A set implemented as a sorted array.
// We need this representation to expose a set of values
// to the Rust core. We provide a pointer  to the list and its length,
// which becomes a slice. Using a `DenseMap`, or another C++ representation,
// could be more efficient, but it would make the API more cumbersome.
template<typename V> class InternalMmapArraySet {
public:
  // Removes all elements of the list without freeing
  // the underlying allocation.
  void clear() { data_.clear(); }

  const V *data() const { return data_.data(); }
  // Mutable access to the underlying array.
  V *data() { return data_.data(); }
  uptr size() const { return data_.size(); }

  template <typename Fn> void forEach(Fn fn) const {
    for (uptr i = 0; i < data_.size(); ++i) {
      fn(data_[i]);
    }
  }

  // Keep only the vals that satisfy the given predicate.
  template <typename Fn> void retainIf(Fn keep) {
    uptr w = 0;
    for (uptr r = 0; r < data_.size(); ++r) {
      V val = data_[r];
      if (keep(val)) {
        data_[w++] = val;
      }
    }
    data_.resize(w);
  }

bool contains(V val) const {
  uptr i = lowerBound(val);
  return i < data_.size() && data_[i] == val;
}

void insert(V val) {
  uptr i = lowerBound(val);
  if (i < data_.size() && data_[i] == val) {
    return; // Already present.
  }
  data_.push_back(val);
  for (uptr j = data_.size() - 1; j > i; --j) {
    data_[j] = data_[j - 1];
  }
  data_[i] = val;
}

void erase(V val) {
  uptr i = lowerBound(val);
  if (i >= data_.size() || data_[i] != val) {
    return;
  }
  // Shift the tail down in place, then drop the last slot. Never shrinks the
  // mapping, so this takes no allocator lock and is safe while the world is
  // stopped.
  for (uptr j = i; j + 1 < data_.size(); ++j) {
    data_[j] = data_[j + 1];
  }
  data_.pop_back();
}

void destroy() {
  if (data_.data()) {
    data_.Destroy();
    // Reset to a valid empty state so the set is safe to reuse (e.g. if its
    // map bucket is repopulated) and so a second Destroy is a no-op.
    data_.Initialize(0);
  }
}
  
private:
  // Returns the index where this val exists, or needs
  // to be inserted.
uptr lowerBound(V val) const {
  // Binary search over the elements of the array
  uptr lo = 0;
  uptr hi = data_.size();
  while (lo < hi) {
    uptr mid = lo + (hi - lo) / 2;
    if (data_[mid] < val) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  return lo;
}

  InternalMmapVectorNoCtor<V> data_{};
};

#endif // BSAN_ARRAY_SET