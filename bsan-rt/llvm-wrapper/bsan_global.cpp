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

void GlobalContext::acquireProvenance(Provenance prov) {
  Lock lock(&global_zct_lock_);
  global_zct_.acquireProvenance(prov);
}

void GlobalContext::acquireProvenance(ZeroCountTable &source) {
  Lock lock(&global_zct_lock_);
  global_zct_.drainFrom(source);
}

void GlobalContext::MergeZeroCounts(Snapshot *snap, ZeroCountTable &zct) {
  if (zct.isBusy()) {
    snap->num_busy_threads++;
    return;
  }
  // If the thread is not in the middle of updating its zero
  // count table, then we can drain its contents for garbage
  // collection.
  zct.retainIf([&](AllocInfo *info, BorTag tag) -> bool {
    Provenance prov = {tag, info};
    if (snap->live.contains(prov)) {
      return true;
    }
    global_ctx()->pending_.insert(prov);
    return false;
  });
}

void GlobalContext::GCCallback(const SuspendedThreadsList &, void *arg) {
  // The data structures used by the GC require the internal allocator.
  // It's much faster than using the `InternalMmap` vector types
  // provided by `sanitizer_common`, since we have a lot of smaller, short
  // lived allocations. We lock the internal allocator prior to stopping
  // the world, so we need to unlock it here, and record that we have done
  // so, to avoid unlocking it again when we restart the world.
  auto *scope = static_cast<ScopedStopTheWorldLock *>(arg);
  scope->UnlockRuntimeAllocators();
  // We store all of the GC-relevant state in a "snapshot". This contains
  // a set of all reachable provenance values, and the number of threads
  // that were busy during this GC run.
  Snapshot snap;
  // Collect all of the provenance values that are reachable from each
  // thread.
  ForEachThread([](BsanThread *thread, Snapshot *snap) {
    for (auto prov : thread->shadow_stack()) {
      snap->live.insert(prov);
    }
  }, &snap);
  // Drain the zero-count tables for each thread, as well
  // as the global zero count table.
  ForEachThread([](BsanThread *thread, Snapshot *snap) { MergeZeroCounts(snap, thread->zct_); }, &snap);
  MergeZeroCounts(&snap, global_ctx()->global_zct_);
  // Only one thread needs to reach `visits_per_gc` to get us here, so every
  // thread's counter starts over from the collection we are about to perform.
  ForEachThread([](BsanThread *thread, Snapshot *) { thread->ResetVisitCount(); }, &snap);
  // Prune all unreachable nodes, destroying
  // allocations that have had their trees fully pruned.
  global_ctx()->CollectGarbage(&snap);
}

void GlobalContext::Retire(AllocInfo *info) {
  CHECK(!quarantine_.contains(info));
  quarantine_[info] = epoch_ + 2;
}

void GlobalContext::Shift(Snapshot *snap) {
  if (snap->num_busy_threads > 0) {
    return;
  }
  epoch_ += 1;
  Vector<AllocInfo *> to_eject;
  quarantine_.forEach([&](auto &KV) {
    if (epoch_ >= KV.getSecond()) {
      to_eject.PushBack(KV.getFirst());
    }
    return true;
  });
  for (unsigned ix = 0; ix < to_eject.Size(); ++ix) {
    __bsan_eject(to_eject[ix]);
    quarantine_.erase(to_eject[ix]);
  }
}

void GlobalContext::CollectGarbage(Snapshot *snap) {
  ConcreteProvenanceSet still_pending;
  pending_.drain([&](AllocInfo *info, BorTagSet &tags) {
    tags.forEach([&](BorTag tag) {
      // None of the borrow tags in the pending set
      // should be live on the stack at this point.
      // They might be live on the heap, with a nonzero
      // reference count, or their underlying allocation
      // could be live on the shadow stack under a different
      // tag, though.
      DCHECK(!snap->live.contains({tag, info}));
    });
    if (__bsan_prune(info, tags.data(), tags.size())) {
      CHECK(snap->live.contains(info));
      // Every tag has been removed from the tree.
      // The reference count for this allocation is zero.
      // However, it is possible that the allocation's
      // metadata still lives somewhere on the shadow
      // stack.
      if (!snap->live.contains(info)) {
        Retire(info);
      }
    } else {
      still_pending.insert(info);
      // The Rust core zeroes out every tag that no longer needs tracking.
      // The remaining nonzero tags are dead nodes that could not be pruned
      // yet; collect them for a future GC pass.
      tags.forEach([&](BorTag tag) {
        if (tag != 0) {
          still_pending.insert({tag, info});
        }
      });
    }
  });
  pending_.swap(still_pending);
}

void GlobalContext::requestGC() {
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
      {
        ScopedStopTheWorldLock stopped;
        StopTheWorld(GCCallback, &stopped);
      }
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
