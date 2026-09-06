#include "bsan_global.h"
#include "bsan.h"
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
  Snapshot *snap = static_cast<Snapshot *>(arg);
  // We need access to the internal allocator so that we can add
  // live provenance values to the set within the snapshot. Unlocking
  // it here prevents us from unlocking it again once the closure returns.
  snap->scope->UnlockInternalAllocator();
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
  MergeZeroCounts(snap, threads.global_zct);
}

void GlobalContext::CollectGarbage(Snapshot &snap) {
  ConcreteProvenanceSet still_pending;
  pending_.drain([&](AllocInfo *info, BorTagSet &tags) {
    // If `__bsan_prune` returns true, then the allocation's tree is empty;
    // every single tag was pruned.
    if (__bsan_prune(info, tags.data(), tags.size())) {
      // Insert the allocation into the quarantine.
      // It might already be present. If so, its generation is
      // updated. It is crucial for this to be a hashmap. Otherwise,
      // we will end up double-freeing allocation metadata.
      quarantine_[info] = snap.gen;
    }
  });
  pending_.swap(still_pending);

  DenseMap<AllocInfo *, uptr> quarantined;
  quarantine_.forEach([&](const DenseMap<AllocInfo *, uptr>::value_type &KV) {
    if (KV.second <= snap.min_drained) {
      __bsan_eject(KV.first);
    } else {
      quarantined.try_emplace(KV.first, KV.second);
    }
    return true;
  });
  quarantine_.swap(quarantined);
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
        state.scope = &stopped;
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
