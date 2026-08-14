#include "bsan_global.h"
#include "bsan.h"
#include "bsan_flags.h"
#include "bsan_interface_internal.h"
#include "sanitizer_common/sanitizer_allocator_internal.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_stoptheworld.h"
#include "sanitizer_common/sanitizer_type_traits.h"

using namespace __bsan;

namespace __bsan {

void GlobalContext::CollectProvenance(const ThreadId id,
                                      BsanThread *const &thread, void *arg) {
  // Iterate over the shadow stacks for each thread,
  // collecting all provenance values into the snapshot.
  auto *state = static_cast<Snapshot *>(arg);
  if (thread) {
    for (auto prov : thread->shadow_stack()) {
      state->live->insert(prov);
    }
  }
}

void GlobalContext::MergeZeroCountsCallback(const ThreadId id,
                                            BsanThread *const &thread,
                                            void *arg) {
  auto *snap = static_cast<Snapshot *>(arg);
  if (!thread) {
    return;
  }
  MergeZeroCounts(snap, thread->zct);
}

void GlobalContext::MergeZeroCounts(Snapshot *snap, ZeroCountTable &zct) {
  // If the thread is not in the middle of updating its zero
  // count table, then we can drain its contents for garbage collection.
  if (!zct.isBusy()) {
    // Move every unreachable value into the pending set, keeping the reachable
    // ones in this thread's zero count table for a future collection. Record
    // the current generation as the last one when this thread's zero count
    // table was drained.
    zct.retainIf(snap->gen, [&](AllocInfo *info, BorTag tag) -> bool {
      Provenance prov = {tag, info};
      if (snap->live->contains(prov)) {
        return true;
      }
      global_ctx()->pending_.insert(prov);
      return false;
    });
  }

  // The default value of `min_drained` is the current
  // generation. Its final value will be equal to the
  // minimum generation for any thread, after updating
  // the ZCT (if we were able to access it this time).
  ZeroCountTable::Generation last_drained = zct.lastDrained();
  if (last_drained < snap->min_drained) {
    snap->min_drained = last_drained;
  }
}

void GlobalContext::SnapshotCallback(const SuspendedThreadsList &, void *arg) {
  // The `arg` here is a pointer to a `SnapShot` object.
  ThreadManager &threads = global_ctx()->Threads();
  // For each thread, add all live provenance values to the snapshot.
  threads.ForEachThread(CollectProvenance, arg);
  // For each thread, if a provenance value in the ZCT is not present
  // in the set of live provenance values in the `SnapShot`, then remove
  // it from the ZCT and add it to the global "pending" set of provenance
  // values that need pruning.
  threads.ForEachThread(MergeZeroCountsCallback, arg);
  // We also need to visit the global ZCT, which contains garbage from threads
  // that have exited since the last collection run.
  MergeZeroCounts(static_cast<Snapshot *>(arg), threads.global_zct);
}

void GlobalContext::CollectGarbage(Snapshot &snap) {
  InternalMmapVector<RetiredAlloc> filtered;
  // Eject all retired allocation metadata objects
  // that are confirmed to be unreachable as of the
  // current minimum generation.
  for (uptr i = 0; i < quarantine_.size(); ++i) {
    RetiredAlloc retired = quarantine_[i];
    if (retired.retire_gen <= snap.min_drained) {
      __bsan_eject(retired.info);
    } else {
      // If we can't eject this object yet, then
      // make sure it stays in quarantine.
      filtered.push_back(retired);
    }
  }
  quarantine_.swap(filtered);

  // A pending set of unpruned tags
  ConcreteProvenanceSet still_pending;
  pending_.drain([&](AllocInfo *info, BorTagSet &tags) {
    // If `__bsan_prune` returns true, then the allocation's tree is empty;
    // every single tag was pruned.
    if (__bsan_prune(info, tags.data(), tags.size())) {
      if (snap.min_drained == snap.gen) {
        __bsan_eject(info);
      } else {
        quarantine_.push_back({info, snap.gen});
      }
    } else {
      // The Rust core zeroes out every tag that no longer needs tracking.
      // The remaining nonzero tags are dead nodes that could not be pruned
      // yet; collect them for a future GC pass.
      const BorTag *retained = tags.data();
      for (uptr i = 0; i < tags.size(); ++i) {
        if (retained[i] != 0) {
          still_pending.insert({retained[i], info});
        }
      }
    }
  });
  pending_.swap(still_pending);
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
      // Reset the zct counter
      atomic_store(&__bsan_zct_since_gc, 0, memory_order_release);
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

void GlobalContext::MaybeRequestGC() {
  uptr threshold = flags()->zct_per_gc;
  if (threshold == 0)
    return;
  if (atomic_load(&__bsan_zct_since_gc, memory_order_acquire) < threshold)
    return;
  RequestGC();
}

alignas(64) static char gctx[sizeof(GlobalContext)];
GlobalContext *global_ctx() {
  return reinterpret_cast<GlobalContext *>(&gctx[0]);
}

} // namespace __bsan
