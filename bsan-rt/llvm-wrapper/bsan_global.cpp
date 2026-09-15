#include "bsan_global.h"
#include "bsan.h"
#include "bsan_interface_internal.h"
#include "sanitizer_common/sanitizer_allocator_internal.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_stoptheworld.h"
#include "sanitizer_common/sanitizer_type_traits.h"

using namespace __bsan;
// BorrowSanitizer uses a concurrent,
// epoch-based, deferred reference counting
// garbage collector. Our approach is influenced
// by DEBRA (Brown et al. 2017) and Deutsch & Bobrow's
// original "incremental, automatic garbage collector".
//
// Each thread has a shadow stack and a
// zero-count table (ZCT). The shadow stack
// contains the "roots" for each node in every tree.
// The ZCT contains the subset of the roots that have
// a zero reference count.
//
// Each time the GC is run, we stop the world. We refer
// to an instance of stopping the world as a "generation".
// Each generation, we create a set of all of the values
// on every shadow stack. Then, we visit every thread's ZCT.
// If a value on the ZCT is not present in any of the shadow
// stacks, then we move it into a "pending set" of values that
// may be pruned. The pending set is retained between generations.
//
// In between generations, when a thread updates its ZCT, it sets
// a "busy" flag. If a thread is busy when we stop the world,
// then we cannot drain its zero count table. This means
// that when we restart the world, the pending set might
// contain a value that is still stored within the ZCT of a busy
// thread that we couldn't visit this generation. However, a
// value in the pending set can never enter a ZCT again.
//
// After we create the pending set, we attempt to
// prune its trees. If all nodes in a tree are pruned,
// and that allocation's underlying reference count is zero,
// then it can be "ejected". When a tree is ejected, it moves
// into the "quarantine" zone. A node in the quarantine is still
// possibly referenced by a ZCT belonging to a thread that was
// busy.
//
// After pruning the pending set, we consider the epoch. If every
// thread was visited this time, then we advance the epoch. When
// we do this, we move the contents of the quarantine into the
// "deferred" zone. When doing so, we deallocate everything in
// the deferred zone.
//
// This is necessary because we can reach this condition while a
// thread remains busy. If a busy thread was not busy during a prior
// generation, then its epoch will match, but its zero-count table
// might contain values that are reachable from another ZCT this
// generation. The deferred zone adds an extra "grace period" to
// ensure that any of these ZCT values are also unreachable before
// they enter the deferred zone. In this way, the pending, quarantine,
// and deferred sets are equivalent to the three "limbo bags" used in
// DEBRA.
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
    zct.retainIf([&](AllocInfo *info, BorTag tag) -> bool {
      Provenance prov = {tag, info};
      if (snap->live->contains(prov)) {
        return true;
      }
      global_ctx()->pending_.insert(prov);
      return false;
    });
    zct.epoch = snap->global_epoch;
  }
  Epoch recorded = zct.epoch;
  if (recorded < snap->min_epoch) {
    snap->min_epoch = recorded;
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

void GlobalContext::Retire(AllocInfo *to_retire) {
  quarantine_.insert(to_retire);
}

void GlobalContext::Shift(Snapshot &snap) {
  // Every thread observed the current epoch. We can
  // advance it, and free the oldest collection of objects.
  if (snap.min_epoch == epoch) {
    epoch += 1;
    deferred_.forEach([&](AllocInfo *info) {
      DCHECK(!snap.live->contains(info));
      __bsan_eject(info);
    });
    deferred_.clear();
    quarantine_.forEach([&](AllocInfo *info) { deferred_.insert(info); });
    quarantine_.clear();
  }
}

void GlobalContext::CollectGarbage(Snapshot &snap) {
  ConcreteProvenanceSet still_pending;
  GlobalContext::Shift(snap);
  pending_.drain([&](AllocInfo *info, BorTagSet &tags) {
    for (uptr i = 0; i < tags.size(); ++i) {
      DCHECK(!snap.live->contains({tags[i], info}));
    }
    if (__bsan_prune(info, tags.data(), tags.size())) {
      // Every single node was pruned from the tree,
      // and the allocation's reference count is zero.
      // We can move it to the quarantine.
      Retire(info);
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
      ConcreteProvenanceSet live;
      Snapshot state(&live, epoch);
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
