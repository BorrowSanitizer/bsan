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
  // We store all of the GC-relevant state in a "snapshot". This contains
  // a set of all reachable provenance values, and the number of threads
  // that were busy during this GC run.
  Snapshot *snap = static_cast<Snapshot *>(arg);
  // The data structures used by the GC require the internal allocator.
  // It's much faster than using the `InternalMmap` vector types
  // provided by `sanitizer_common`, since we have a lot of smaller, short
  // lived allocations. We lock the internal allocator prior to stopping
  // the world, so we need to unlock it here, and record that we have done
  // so, to avoid unlocking it again when we restart the world.
  snap->lock->UnlockInternalAllocator();

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
  if (snap->num_busy_threads == 0) {
    epoch_ += 1;
  }
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
    if (__bsan_prune(info, tags.data(), tags.size())) {
      // Every tag has been removed from the tree.
      // The reference count for this allocation is zero.
      if (!snap->live.contains(info)) {
        // The root is no longer present on any
        // of the shadow stacks. We can retire it.
        if (snap->num_busy_threads == 0) {
          // No threads were busy this time,
          // so we can guarantee that there
          // are no copies of this allocation
          // still flowing through the ZCT.
          quarantine_[info] = epoch_;
        } else {
          // One or more threads were busy this time,
          // so we couldn't visit their ZCTs. We need
          // to wait until the next time we have a
          // clear picture of shadow memory to be able
          // to prune this.
          quarantine_[info] = epoch_ + 1;
        }
        // If an allocation has been quarantined,
        // then we can return immediately; it should
        // have exited the pending set entirely.
        return;
      }
      // It is possible for an allocation to have been
      // fully pruned but for it to still be alive
      // on the shadow stack. For example, this will
      // happen if an allocation is freed while one
      // of its aliases is within a ZCT. We need to
      // insert the allocation into the pending set,
      // without providing any tags for it.
      //
      // Another possibility is that we tried to lock the
      // tree for this allocation, but a thread was
      // paused while holding the lock. We want to
      // keep everything in the pending set for
      // the next attempt.
    }
    // At this point, we know that either the root
    // or one of the tags for this allocation is alive
    // somewhere in shadow memory. If there are no tags
    // left to prune, then the root allocation is all
    // that's left, and we still want to make sure that
    // it gets inserted into the next pending set.
    if tags
      .size() == 0 { still_pending.insert(info); };
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

void GlobalContext::EjectGarbage(Snapshot &snap) {
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
        ScopedStopTheWorldLock stopped;
        snap.lock = &stopped;
        StopTheWorld(GCCallback, &snap);
      }
      EjectGarbage(snap);
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
