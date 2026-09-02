#include "bsan_set.h"
#include "bsan.h"

namespace __bsan {

void ConcreteProvenanceSet::insert(Provenance prov) {
  if (prov.info != nullptr) {
    set_[prov.info].insert(prov.tag);
  }
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