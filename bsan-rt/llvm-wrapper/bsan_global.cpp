#include "bsan_global.h"
#include "bsan.h"
#include "bsan_interface_internal.h"
#include "sanitizer_common/sanitizer_allocator_internal.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_type_traits.h"

using namespace __bsan;

namespace __bsan {

void GlobalContext::initGC() {
  InitMembarrier();
}

struct ScopedStopTheWorldLock {
  Lock lock;
  ScopedThreadLock &threads;
  ScopedStopTheWorldLock(ScopedThreadLock &threads)
      : lock(Lock(&global_ctx()->global_zct_lock_)), threads(threads) {
    atomic_store(&__bsan_gc_trigger, 1, memory_order_relaxed);
    Membarrier();
    for (;;) {
      bool all_stopped = true;
      ForEachThread(threads, [&](BsanThread *thread) {
        if (thread != CurrentThread()) {
          if (thread->getGCState(memory_order_acquire) == GCState::kUnsafe) {
            all_stopped = false;
          }
        }
      });
      if (all_stopped)
        break;
      // Yield so that other threads can make progress before
      // we check their status again. Otherwise, we might loop
      // and get the same result as before.
      internal_sched_yield();
    }
  }
  ~ScopedStopTheWorldLock() {
    atomic_store(&__bsan_gc_trigger, 0, memory_order_relaxed);
    ForEachThread(threads, [&](BsanThread *thread) {
      if (thread != CurrentThread())
        thread->resume();
    });
  }
};

void GlobalContext::acquireProvenance(Provenance prov) {
  Lock lock(&global_zct_lock_);
  global_zct_.insert(prov);
}

void GlobalContext::acquireProvenance(ConcreteProvenanceSet &source) {
  Lock lock(&global_zct_lock_);
  global_zct_.takeFrom(source);
}

void GlobalContext::MergeZeroCounts(Snapshot *snap,
                                    ConcreteProvenanceSet &zct) {
  zct.retainIf([&](AllocInfo *info, BorTag tag) -> bool {
    Provenance prov = {tag, info};
    if (snap->live.contains(prov)) {
      return true;
    }
    global_ctx()->pending_.insert(prov);
    return false;
  });
}

void GlobalContext::RunGarbageCollector(Snapshot &snap,
                                        ScopedAllocatorLock &alloc,
                                        ScopedThreadLock &threads) {
  // The data structures used by the GC require the internal allocator.
  // It's much faster than using the `InternalMmap` vector types
  // provided by `sanitizer_common`, since we have a lot of smaller, short
  // lived allocations. We lock the internal allocator prior to stopping
  // the world, so we need to unlock it here, and record that we have done
  // so, to avoid unlocking it again when we restart the world.
  alloc.UnlockRuntimeAllocators();

  ForEachThread(
      threads,
      [](BsanThread *thread, Snapshot *snap) {
        // Collect all of the provenance values that are reachable from each
        // thread.
        for (auto prov : thread->shadow_stack()) {
          snap->live.insert(prov);
        }
      },
      &snap);

  ForEachThread(
      threads,
      [](BsanThread *thread, Snapshot *snap) {
        // Drain the zero-count tables for each thread, as well
        // as the global zero count table. This happens in a separate
        // step from scanning the stacks, since we need to know if a
        // provenance value is reachable, globally, before we can remove
        // it from a ZCT.
        MergeZeroCounts(snap, thread->zct_);
      },
      &snap);

  MergeZeroCounts(&snap, global_ctx()->global_zct_);
  // Only one thread needs to reach `visits_per_gc` to get us here, so every
  // thread's counter starts over from the collection we are about to perform.
  ForEachThread(
      threads,
      [](BsanThread *thread, Snapshot *) { thread->ResetVisitCount(); }, &snap);
  // Prune all unreachable nodes, destroying
  // allocations that have had their trees fully pruned.
  // At the moment, we wait until after restarting the
  // world to actually "eject" allocations that have had
  // all of their nodes pruned. This is because we
  // do not have a dedicated lock for the concurrent
  // bump allocator used to hand out allocation metadata,
  // so a thread might be in the middle of its critical
  // section during this point.
  global_ctx()->CollectGarbage(&snap);
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
      {
        ScopedThreadLock threads;
        {
          ScopedStopTheWorldLock world(threads);
          {
            Snapshot snap;
            {
              ScopedAllocatorLock allocs;
              RunGarbageCollector(snap, allocs, threads);
            }
          }
        }
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
