#include "bsan_global.h"
#include "bsan.h"
#include "bsan_interface_internal.h"
#include "sanitizer_common/sanitizer_allocator_internal.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_mutex.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_type_traits.h"

using namespace __bsan;

namespace __bsan {

void GlobalContext::acquireProvenance(Provenance prov) {
  Lock lock(&global_zct_lock_);
  global_zct_.insert(prov);
}

void GlobalContext::acquireProvenance(ConcreteProvenanceSet &source) {
  Lock lock(&global_zct_lock_);
  global_zct_.takeFrom(source);
}

void GlobalContext::InitGC() { InitAsymmetricBarrier(); }

void GlobalContext::WaitAtSafePoint() {
  BsanThread *thread = CurrentThread();
  if (!thread || !atomic_load(&__bsan_gc_pending, memory_order_acquire))
    return;
  u32 epoch = atomic_load(&gc_epoch_, memory_order_acquire);
  if (!(epoch & 1))
    return;
  thread->setAtSafePoint(epoch);
  while (atomic_load(&gc_epoch_, memory_order_acquire) == epoch)
    FutexWait(&gc_epoch_, epoch);
}

bool GlobalContext::AtSafePoint(ScopedThreadLock &) {
  u32 epoch = atomic_fetch_add(&gc_epoch_, 1, memory_order_acq_rel) + 1;
  atomic_store(&__bsan_gc_pending, 1, memory_order_release);
  // Pairs with the fence that instrumented code executes between clearing
  // `__bsan_gc_safe` and loading `__bsan_gc_pending`. Either that thread
  // sees the GC as pending and polls its safepoint, or we see it as unsafe
  // and wait for it.
  AsymmetricBarrier();
  for (;;) {
    bool all_stopped = true;
    ForEachThread(
        [&](BsanThread *thread, u32 *epoch) {
          if (thread != CurrentThread() && !thread->atSafePoint(*epoch) &&
              !thread->isGCSafe())
            all_stopped = false;
        },
        &epoch);
    if (all_stopped)
      return true;
    internal_sched_yield();
  }
}

void GlobalContext::ClearSafePoint(ScopedThreadLock &) {
  atomic_store(&__bsan_gc_pending, 0, memory_order_release);
  atomic_fetch_add(&gc_epoch_, 1, memory_order_release);
  FutexWake(&gc_epoch_, 0x7fffffff);
}

void GlobalContext::MergeZeroCounts(Snapshot *snap,
                                    ConcreteProvenanceSet &zct) {
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

void GlobalContext::GCCallback(Snapshot *snap) {
  // We store all of the GC-relevant state in a "snapshot". This contains
  // a set of all reachable provenance values, and the number of threads
  // that were busy during this GC run.
  ForEachThread(
      [](BsanThread *thread, Snapshot *snap) {
        // Collect all of the provenance values that are reachable from each
        // thread.
        for (auto prov : thread->shadow_stack()) {
          snap->live.insert(prov);
        }
      },
      snap);

  ForEachThread(
      [](BsanThread *thread, Snapshot *snap) {
        // Drain the zero-count tables for each thread, as well
        // as the global zero count table. This happens in a separate
        // step from scanning the stacks, since we need to know if a
        // provenance value is reachable, globally, before we can remove
        // it from a ZCT.
        MergeZeroCounts(snap, thread->zct_);
      },
      snap);

  MergeZeroCounts(snap, global_ctx()->global_zct_);
  // Prune all unreachable nodes, destroying
  // allocations that have had their trees fully pruned.
  // At the moment, we wait until after restarting the
  // world to actually "eject" allocations that have had
  // all of their nodes pruned. This is because we
  // do not have a dedicated lock for the concurrent
  // bump allocator used to hand out allocation metadata,
  // so a thread might be in the middle of its critical
  // section during this point.
  global_ctx()->CollectGarbage(snap);
}

void GlobalContext::CollectGarbage(Snapshot *snap) {
  ConcreteProvenanceSet still_pending;
  pending_.drain([&](AllocInfo *info, BorTagSet &tags) {
    tags.forEach([&](BorTag tag) {
      // None of the borrow tags in the pending set
      // are live on the stack at this point.
      // They might be live on the heap, with a nonzero
      // reference count, or their underlying allocation
      // could be live on the shadow stack under a different tag,
      DCHECK(!snap->live.contains({tag, info}));
    });
    auto status = __bsan_prune(info, tags.data(), tags.size());
    if (status == EjectStatus::Ejectable) {
      // Every tag has been removed from the tree.
      // The reference count for this allocation is zero.
      if (!snap->live.contains(info)) {
        // The root is no longer present on any
        // of the shadow stacks. We can retire it.
        __bsan_eject(info);
      } else {
        still_pending.insert(info);
      }
      return;
    }
    if (status == EjectStatus::RetainEmpty) {
      // It is possible for an allocation to have been
      // fully pruned but for it to still be alive
      // on the shadow stack. For example, this will
      // happen if an allocation is freed while one
      // of its aliases is within a ZCT. We need to
      // insert the allocation into the pending set,
      // without providing any tags for it.
      still_pending.insert(info);
      return;
    }
    CHECK(status == EjectStatus::RetainNonEmpty);
    // The `RetainNonEmpty` status is also used
    // to indicate that a thread was busy during collection,
    // so it could indicate that a node was a singleton.
    // We want to ensure that it gets added regardless.
    if (!tags.size())
      still_pending.insert(info);
    // Any leftover tags must be kept around
    // for the next cycle.
    tags.forEach([&](BorTag tag) {
      // When we prune a tag, we write
      // zero into the list of tags. This
      // is treated as a special "omnivalid"
      // provenance value, which is filtered
      // out when we try to insert it into
      // the pending set.
      still_pending.insert({tag, info});
    });
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
      Snapshot snap;
      {
        ScopedThreadLock threads;
        if (AtSafePoint(threads)) {
          Lock zct_lock(&global_zct_lock_);
          GCCallback(&snap);
        }
        ClearSafePoint(threads);
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
