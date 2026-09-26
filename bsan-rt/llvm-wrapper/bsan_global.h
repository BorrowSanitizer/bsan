#ifndef BSAN_GLOBAL_H
#define BSAN_GLOBAL_H

#include "bsan.h"
#include "bsan_set.h"
#include "bsan_thread.h"
#include "sanitizer_common/sanitizer_stoptheworld.h"

namespace __bsan {

struct ScopedAllocatorLock;
struct Snapshot {
public:
  Snapshot() {};
  // The set of borrow tags that are currently
  // reachable from any of the shadow stacks.
  ConcreteProvenanceSet live;
};

// Global state associated with the runtime.
struct GlobalContext {
public:
  GlobalContext() { }
  Mutex &AtExitMutex() { return at_exit_lock_; }
  Vector<AtExitRecord *> &AtExitStack() { return at_exit_stack_; }

  // Requests for the garbage collector to be invoked. This is
  // a thread safe operation; any series of threads can simultaneously
  // try to start the GC, and only one will succeed.
  void requestGC();
  void acquireProvenance(Provenance prov);
  void acquireProvenance(ConcreteProvenanceSet &source);
  bool isGCRunning(memory_order order);
  void park();

private:
  friend struct ScopedGCLock;
  friend struct ScopedAllocatorLock;
  Mutex global_zct_lock_;

  // Initializes state associated with the garbage collector.
  // This includes the membarrier used to synchronize stopping
  // the world, and the gc trigger page.
  void initGC();

  // When a thread exits, its zero count table needs to be
  // retained, so that we can clean up any of the provenance
  // values that it acquired in a future garbage collection pass.
  ConcreteProvenanceSet global_zct_;

  // A flag indicating that the garbage collector is currently
  // running. This is used by threads exiting native contexts.
  atomic_uint32_t gc_running_{0};

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

  // An atomic flag that is set when the garbage collector has been
  // invoked, and we are waiting on each thread to reach a safepoint
  // or enter a "gc-safe" state.
  atomic_uintptr_t gc_pending_{0};

  // A set of provenance values with a zero reference count that are
  // ready to be garbage collected. These values are no longer reachable
  // in shadow memory, or within the zero count tables associated with
  // each thread.
  ConcreteProvenanceSet pending_;

  void RunGarbageCollector(Snapshot &snap, ScopedAllocatorLock &alloc,
                           ScopedThreadLock &threads);
  // Iterates over every thread's zero-count-table, merging its contents into
  // the set of pending provenance values. We only add values to the pending set
  // if they are not present on any shadow stack. Values that we add to the
  // pending set are also removed from their thread's zero-count-table.
  static void MergeZeroCounts(Snapshot *snap, ConcreteProvenanceSet &zct);
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

struct ScopedAllocatorLock {
  ScopedAllocatorLock() {
    // We need to ensure that every existing thread is blocked
    // from the allocator, and that every new thread is blocked
    // from registering its shadow stack in the global state.
    // If we stop the world when a thread is within either of
    // these critical sections, then our state might be corrupted
    // once we resume.
    LockShadowedAllocator();
    LockRustAllocator();
    InternalAllocatorLock();
  }

  void UnlockRuntimeAllocators() {
    InternalAllocatorUnlock();
    UnlockRustAllocator();
    runtime_alloc_locked_ = false;
  }

  ~ScopedAllocatorLock() {
    if (runtime_alloc_locked_) {
      InternalAllocatorUnlock();
      UnlockRustAllocator();
    }
    UnlockShadowedAllocator();
  }

  ScopedAllocatorLock &operator=(const ScopedAllocatorLock &) = delete;
  ScopedAllocatorLock(const ScopedAllocatorLock &) = delete;

private:
  bool runtime_alloc_locked_ = true;
};

} // namespace __bsan
#endif