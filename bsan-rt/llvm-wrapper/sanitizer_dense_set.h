//===- llvm/ADT/DenseSet.h - Dense probed hash table ------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file defines the DenseSet and SmallDenseSet classes.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_DENSESET_H
#define LLVM_ADT_DENSESET_H

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_dense_map.h"
#include "sanitizer_common/sanitizer_dense_map_info.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_type_traits.h"

namespace __sanitizer {

namespace detail {
struct DenseSetEmpty {};

// Use the empty base class trick so we can create a DenseMap where the buckets
// contain only a single item.
template <typename KeyT> class DenseSetPair : public DenseSetEmpty {
  KeyT key;

public:
  KeyT &getFirst() { return key; }
  const KeyT &getFirst() const { return key; }
  DenseSetEmpty &getSecond() { return *this; }
  const DenseSetEmpty &getSecond() const { return *this; }
};

/// Base class for DenseSet
template <typename ValueT, typename MapTy> class DenseSetImpl {
  static_assert(sizeof(typename MapTy::value_type) == sizeof(ValueT),
                "DenseMap buckets unexpectedly large!");
  MapTy TheMap;

public:
  using key_type = ValueT;
  using value_type = ValueT;
  using size_type = unsigned;

  [[nodiscard]] bool empty() const { return TheMap.empty(); }
  [[nodiscard]] size_type size() const { return TheMap.size(); }
  [[nodiscard]] uptr getMemorySize() const { return TheMap.getMemorySize(); }

  /// Grow the DenseSet so that it can contain at least \p NumEntries items
  /// before resizing again.
  void reserve(uptr Size) { TheMap.reserve(Size); }

  void clear() { TheMap.clear(); }

  bool erase(const ValueT &V) { return TheMap.erase(V); }

  void swap(DenseSetImpl &RHS) { TheMap.swap(RHS.TheMap); }

  /// Check if the set contains the given element.
  [[nodiscard]] bool contains(const ValueT &V) const {
    return TheMap.contains(V);
  }

  detail::DenseMapPair<value_type *, bool> insert(const ValueT &V) {
    auto Result = TheMap.try_emplace(V);
    return {&Result.first->getFirst(), Result.second};
  }

  template <class Fn> void forEach(Fn fn) {
    TheMap.forEach([&](typename MapTy::value_type &Bucket) {
      fn(Bucket.getFirst());
      return true;
    });
  }
};

template <typename ValueT, typename ValueInfoT>
using DenseSet = DenseSetImpl<
    ValueT, DenseMap<ValueT, DenseSetEmpty, ValueInfoT, DenseSetPair<ValueT>>>;

} // end namespace detail

/// Implements a dense probed hash-table based set.
template <typename ValueT, typename ValueInfoT = DenseMapInfo<ValueT>>
class DenseSet : public detail::DenseSet<ValueT, ValueInfoT> {
  using BaseT = detail::DenseSet<ValueT, ValueInfoT>;

public:
  using BaseT::BaseT;
};

} // end namespace __sanitizer

#endif