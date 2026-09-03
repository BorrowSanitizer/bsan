#ifndef BSAN_GLOBAL_H
#define BSAN_GLOBAL_H

#include "bsan.h"
#include "bsan_set.h"
#include "bsan_thread.h"
#include "sanitizer_common/sanitizer_stoptheworld.h"

namespace __bsan {

struct Snapshot {
public:
  Snapshot(ConcreteProvenanceSet *live, uptr gen)
      : live(live), gen(gen), min_drained(gen) {};
  // The set of borrow tags that are currently
  // reachable from any of the shadow stacks.
  ConcreteProvenanceSet *live;
  // The current generation
  uptr gen;
  // The minimum generation recorded by any live thread.
  uptr min_drained;
};

// Global state associated with the runtime.
struct GlobalContext {
public:
  ThreadManager &Threads() { return threads_; }
  Mutex &AtExitMutex() { return at_exit_lock_; }
  Vector<AtExitRecord *> &AtExitStack() { return at_exit_stack_; }

  // Requests for the garbage collector to be invoked. This is
  // a thread safe operation; any series of threads can simultaneously
  // try to start the GC, and only one will succeed.
  void RequestGC();

private:
  friend struct ScopedStopTheWorldLock;
  ThreadManager threads_;

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
  ConcreteProvenanceSet pending_;

  // A callback passed to `StopTheWorld` that takes a "snapshot" of the state
  // associated with each thread and uses it to populate the set of pending
  // provenance values.
  static void SnapshotCallback(const SuspendedThreadsList &, void *arg);

  // Iterates over every thread's shadow stack, creating a set of all reachable
  // provenance values. The last argument is a pointer to the
  // `ConcreteProvenanceSet` being populated.
  static void CollectProvenance(const ThreadId id, BsanThread *const &thread,
                                void *arg);

  // Iterates over every thread's zero-count-table, merging its contents into
  // the set of pending provenance values. We only add values to the pending set
  // if they are not present on any shadow stack. Values that we add to the
  // pending set are also removed from their thread's zero-count-table.
  static void MergeZeroCountsCallback(const ThreadId id,
                                      BsanThread *const &thread, void *arg);
  static void MergeZeroCounts(Snapshot *snap, ZeroCountTable &zct);

  // Drains the contents of the pending provenance set, pruning the associated
  // state from the tree for each allocation. Ejects any retired allocation
  // objects that are confirmed to be unreachable. This happens after the world
  // has restarted.
  void CollectGarbage(Snapshot &snap);

  // Allocations that are unreachable and have had all of their nodes pruned,
  // but that cannot be ejected yet, because they might still be stored within a
  // thread's zero count table. Maps each allocation to the generation when it
  // was retired.
  DenseMap<Block *, uptr> quarantine_{};

  // Guards `at_exit_stack_`.
  Mutex at_exit_lock_;
  // Exit handlers.
  Vector<AtExitRecord *> at_exit_stack_;
};

/// Returns a pointer to the singleton `GlobalContext` object.
GlobalContext *global_ctx();

struct ScopedStopTheWorldLock {
  ScopedStopTheWorldLock() {
    // We need to ensure that every existing thread is blocked
    // from the allocator, and that every new thread is blocked
    // from registering its shadow stack in the global state.
    // If we stop the world when a thread is within either of
    // these critical sections, then our state might be corrupted
    // once we resume.
    global_ctx()->Threads().LockThreads();
    LockAllocator();
    InternalAllocatorLock();
  }

  ~ScopedStopTheWorldLock() {
    InternalAllocatorUnlock();
    UnlockAllocator();
    global_ctx()->Threads().UnlockThreads();
  }

  ScopedStopTheWorldLock &operator=(const ScopedStopTheWorldLock &) = delete;
  ScopedStopTheWorldLock(const ScopedStopTheWorldLock &) = delete;
};

} // namespace __bsan
#endif