#ifndef BSAN_GLOBAL_H
#define BSAN_GLOBAL_H

#include "bsan.h"
#include "bsan_set.h"
#include "bsan_thread.h"

namespace __bsan {

struct Snapshot {
public:
  Snapshot() {};
  // The set of borrow tags that are currently
  // reachable from any of the shadow stacks.
  ProvenanceSet live;
};

// Global state associated with the runtime.
struct GlobalContext {
public:
  GlobalContext() { initGC(); }
  Mutex &AtExitMutex() { return at_exit_lock_; }
  Vector<AtExitRecord *> &AtExitStack() { return at_exit_stack_; }

  // Requests for the garbage collector to be invoked. This is
  // a thread safe operation; any series of threads can simultaneously
  // try to start the GC, and only one will succeed.
  void requestGC();
  void acquireProvenance(Provenance prov);
  void acquireProvenance(ProvenanceSet &source);

  void FreeBlock(BlockIndex idx) {
    block_allocator.Free(&this->block_cache_, idx);
  }

private:
  Mutex global_zct_lock_;

  void initGC();

  // When a thread exits, its zero count table needs to be
  // retained so that we can clean up any of the provenance
  // values that it acquired in a future garbage collection pass.
  ProvenanceSet global_zct_;

  // A lock held by the thread that succeeds at invoking
  // the garbage collector. While this lock is held, the
  // GC cannot be started again by another thread.
  atomic_uintptr_t gc_lock{0};

  // The number of times that the garbage collector has
  // successfully been invoked. Every thread reads this value
  // prior to locking the GC. If this value changes after the
  // lock is acquired, then another thread was able to complete
  // the GC between the moment that we decided to run the GC and the
  // moment that we acquired the lock. In that case, we can release
  // the lock without running the GC.
  atomic_uintptr_t gc_gen{0};

  // A set of provenance values with a zero reference count that are
  // ready to be garbage collected. These values are no longer reachable
  // in shadow memory, or within the zero count tables associated with
  // each thread.
  ProvenanceSet pending_;

  // We use a shared, global cache of blocks to handle allocation
  // and deallocation in contexts where a thread has yet to be
  // initialized.
  BlockAllocator::Cache block_cache_;
  void RunGarbageCollector(Snapshot &snap, ScopedThreadLock &threads);
  // Iterates over every thread's zero-count-table, merging its contents into
  // the set of pending provenance values. We only add values to the pending set
  // if they are not present on any shadow stack. Values that we add to the
  // pending set are also removed from their thread's zero-count-table.
  static void MergeZeroCounts(Snapshot *snap, ProvenanceSet &zct);
  // Drains the contents of the pending provenance set, pruning the associated
  // state from the tree for each allocation. Ejects any retired allocation
  // objects that are confirmed to be unreachable.
  void CollectGarbage(Snapshot *snap);

  // Guards `at_exit_stack_`.
  Mutex at_exit_lock_;
  // Exit handlers.
  Vector<AtExitRecord *> at_exit_stack_;
};

/// Returns a pointer to the singleton `GlobalContext` object.
GlobalContext *global_ctx();

} // namespace __bsan
#endif