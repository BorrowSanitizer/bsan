#include "bsan_global.h"
#include "bsan.h"
#include "sanitizer_common/sanitizer_allocator_internal.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_stoptheworld.h"
#include "sanitizer_common/sanitizer_type_traits.h"

using namespace __bsan;

extern "C" {
// Prunes a list of nodes from a tree that correspond to the tags in the list.
// Returns true if every tag has been pruned, indicating that the allocation
// metadata object can also be reclaimed.
SANITIZER_WEAK_ATTRIBUTE
bool __bsan_prune(AllocInfo *Info, const BorTag *tags, uptr len);
// Frees an `AllocInfo` object. The pointer must be nonnull and unreachable
// in shadow memory.
SANITIZER_WEAK_ATTRIBUTE
void __bsan_eject(AllocInfo *Info);
}

namespace __bsan {

void GlobalContext::CollectProvenance(const uptr, BsanThread *const &thread,
                                      void *arg) {
  // Iterate over the shadow stacks for each thread,
  // collecting all provenance values into the snapshot.
  auto *state = static_cast<Snapshot *>(arg);
  if (thread) {
    for (auto prov : thread->shadow_stack()) {
      state->live->insert(prov);
    }
  }
}

void GlobalContext::MergeZeroCounts(const uptr, BsanThread *const &thread,
                                    void *arg) {
  auto *snap = static_cast<Snapshot *>(arg);
  if (!thread) {
    return;
  }
  // If the thread is not in the middle of updating its zero
  // count table, then we can drain its contents for garbage collection.
  if (!thread->ZctBusy()) {
    // Move every unreachable value into the pending set, keeping the reachable
    // ones in this thread's zero count table for a future collection.
    thread->zero_count_set_.retainIf([&](AllocInfo *info, BorTag tag) -> bool {
      Provenance prov = {tag, info};
      if (snap->live->contains(prov)) {
        return true;
      }
      global_ctx()->pending_.insert(prov);
      return false;
    });
    // Record the current generation as the last one
    // when this thread's zero count table was drained.
    thread->drained_gen_ = snap->gen;
  }

  if (thread->drained_gen_ < snap->min_drained) {
    snap->min_drained = thread->drained_gen_;
  }
}

void GlobalContext::SnapshotCallback(const SuspendedThreadsList &, void *arg) {
  ThreadManager &threads = global_ctx()->Threads();
  threads.ForEachThread(CollectProvenance, arg);
  threads.ForEachThread(MergeZeroCounts, arg);
}

void GlobalContext::CollectGarbage(Snapshot &snap) {
  InternalMmapVector<RetiredAlloc> filtered;
  // Eject all retired allocation metadata objects
  // that are confirmed to be unreachable as of the
  // current minimum generation.
  for (uptr i = 0; i < quarantine_.size(); ++i) {
    RetiredAlloc retired = quarantine_[i];
    if (__bsan_eject && retired.retire_gen <= snap.min_drained) {
      __bsan_eject(retired.info);
    } else {
      // If we can't eject this object yet, then
      // make sure it stays in quarantine.
      filtered.push_back(retired);
    }
  }
  quarantine_.swap(filtered);

  pending_.drain([&](AllocInfo *info, const ConcreteTagSet &tags) {
    if (__bsan_prune && __bsan_prune(info, tags.data(), tags.size())) {
      if (__bsan_eject && snap.min_drained == snap.gen) {
        __bsan_eject(info);
      } else {
        quarantine_.push_back({info, snap.gen});
      }
    }
  });
}

void GlobalContext::RequestGC() {
  // Get the current generation count
  uptr gen = atomic_load(&gc_gen, memory_order_acquire);
  // Try and lock the garbage collector
  uptr expected = 0;
  if (atomic_compare_exchange_strong(&gc_lock, &expected, 1,
                                     memory_order_acquire)) {
    // Check the generation count. If it is different from before,
    // then somebody else got here first and already ran the GC.
    uptr current_gen = atomic_load(&gc_gen, memory_order_acquire);
    if (gen == current_gen) {
      ConcreteProvenanceSet live;
      Snapshot state(&live, gen);
      {
        ScopedStopTheWorldLock stopped;
        StopTheWorld(SnapshotCallback, &state);
      }
      CollectGarbage(state);
      atomic_fetch_add(&gc_gen, 1, memory_order_relaxed);
    }
    // Release the lock, allowing the GC to run again.
    atomic_store(&gc_lock, 0, memory_order_release);
  }
}

alignas(64) static char gctx[sizeof(GlobalContext)];
GlobalContext *global_ctx() {
  return reinterpret_cast<GlobalContext *>(&gctx[0]);
}

} // namespace __bsan
