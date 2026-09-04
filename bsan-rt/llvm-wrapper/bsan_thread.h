#ifndef BSAN_THREAD_H
#define BSAN_THREAD_H
#include "bsan.h"
#include "bsan_allocator.h"
#include "bsan_set.h"
#include "sanitizer_common/sanitizer_array_ref.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_posix.h"

using namespace __sanitizer;

namespace __bsan {

struct ZeroCountTable {
  typedef uptr Generation;
  ~ZeroCountTable() {}

private:
  // A flag indicating that we are currently adding a value to the zero count
  // table for this thread. If this flag is set when we stop the world, then we
  // will skip merging its zero count table into the set of pending provenance
  // values to garbage collect. We will still examine this thread's
  // shadow stack to exclude reachable provenance values.
  atomic_uint8_t busy_{};

  Generation drained_gen_ = 0;

  // Whenever we modify this zero-count table, we need to
  // ensure that we are only doing so from the context of another table.
  struct GCBarrier {
    ZeroCountTable &zct;
    GCBarrier(ZeroCountTable &zct) : zct(zct) {
      atomic_store(&zct.busy_, 1, memory_order_release);
    }
    ~GCBarrier() { atomic_store(&zct.busy_, 0, memory_order_release); }
  };

  ConcreteProvenanceSet zct_;

  // Adds a provenance value with a zero reference count
  // to this table.
public:
  void acquireProvenance(Provenance Prov) {
    // We use a release order here so that each of these
    // stores is ordered before the "acquire" load used
    // to check the value in `IsBusy`.
    GCBarrier barrier(*this);
    zct_.insert(BLOCK_IDX(Prov.info), Prov.tag);
  }

  void drainFrom(ZeroCountTable &other) {
    GCBarrier other_barrier(other);
    GCBarrier this_barrier(*this);
    zct_.takeFrom(other.zct_);
  }

  template <typename Fn> void retainIf(Generation gen, Fn retain) {
    drained_gen_ = gen;
    zct_.retainIf(retain);
  }

  Generation lastDrained() { return drained_gen_; }

  bool isBusy() { return atomic_load(&busy_, memory_order_acquire) == 1; }
};

class BsanThread {
public:
  // Allocates, but does not initialize an instance of the thread state
  // object within a thread-local variable.
  static BsanThread *Create(thread_callback_t start_routine, void *arg);

  // Destroys an instance of `BsanThread` stored at the given address,
  // which is a thread-local allocation.
  static void Destroy(void *tsd);

  // Initializes the object, allocating its shadow stack.
  // This must be called from the thread itself, before it
  // executes its start routine.
  void Init();

  // This function is passed as the argument to `pthread_create`.
  // It configures signal handling and then executes the start routine.
  static void *StartCallback(void *arg);

  // Every thread, including the main thread, has an associated
  // state. The main thread does not have a start_routine.
  bool IsMainThread() const { return start_routine_ == nullptr; }

  // Returns the top of the "real" stack associated with this thread.
  uptr stack_top() const { return stack_top_; }

  // Returns the bottom of the "real" stack associated with this thread.
  uptr stack_bottom() const { return stack_bottom_; }

  // Returns the bottom of the "shadow" stack associated with this thread.
  uptr shadow_stack_bottom() const { return (uptr)shadow_stack_bottom_; }

  // Returns the top of the "shadow" stack associated with this thread.
  uptr shadow_stack_top() const {
    return (uptr)shadow_stack_bottom_ + shadow_stack_size_;
  }

  ArrayRef<Provenance> shadow_stack() const {
    Provenance *cursor = shadow_stack_cursor();
    Provenance *top = (Provenance *)(shadow_stack_top());
    if (cursor == nullptr || cursor > top) {
      return {};
    }
    return ArrayRef<Provenance>(cursor, top - cursor);
  }

  // Returns the current value of this thread's shadow stack pointer.
  Provenance *shadow_stack_cursor() const {
    return shadow_stack_ptr_ ? *shadow_stack_ptr_ : nullptr;
  }

  // The remaining number of times that TSD destructors will
  // execute for this thread. This is initialized to the maximum value,
  // and then decremented every time the destructor runs.
  int destructor_iterations_;

  // A unique ID for this thread.
  uptr id;

  // Signal handler settings.
  __sanitizer_sigset_t starting_sigset_;

  BsanThreadLocalMallocStorage &malloc_storage() { return malloc_storage_; }

  ZeroCountTable zct;

  BlockIndex AllocBlock() { return block_allocator.Alloc(&this->block_cache_); }
  void FreeBlock(BlockIndex idx) {
    block_allocator.Free(&this->block_cache_, idx);
  }

private:
  friend struct GlobalContext;

  // Executes the start routine.
  thread_return_t Start();

  thread_callback_t start_routine_;
  void *arg_;

  uptr stack_top_;
  uptr stack_bottom_;

  void *shadow_stack_bottom_;
  uptr shadow_stack_size_;

  BsanThreadLocalMallocStorage malloc_storage_;

  // This thread's block-index cache for the `Block` metadata slab.
  BlockAllocator::Cache block_cache_;

  // The address of this thread's thread-local allocation
  // containing the current value of its shadow stack
  // pointer (`__bsan_shadow_stack`).
  Provenance **shadow_stack_ptr_;
};

BsanThread *CurrentThread();
void SetCurrentThread(BsanThread *t);

struct SANITIZER_MUTEX ThreadManager {
public:
  // Initializes a thread, making its state accessible
  // to global processes (e.g. the garbage collector)
  void RegisterThread(BsanThread *thread);

  // Removes a thread's global entry. This prevents the thread
  // from being visited by the garbage collector, so it needs to
  // happen before we deinitialize any of the other states associated
  // with this thread.
  void DeregisterThread(BsanThread *thread);

  void LockThreads() SANITIZER_ACQUIRE() { mtx_.Lock(); }
  void UnlockThreads() SANITIZER_RELEASE() { mtx_.Unlock(); }

  // Executes the provided callback for every thread.
  // This can only be called when the world has been stopped.
  template <class Fn> void ForEachThread(Fn fn, void *arg) {
    threads.forEach([&](const auto &KV) {
      fn(KV.getFirst(), KV.getSecond(), arg);
      return true;
    });
  }

private:
  friend struct GlobalContext;
  // Locks the map.
  Mutex mtx_;
  using ThreadStateMap = DenseMap<ThreadId, BsanThread *>;
  // A hashmap from each thread's `ThreadId`
  // to its state object.
  ThreadStateMap threads;
  // When a thread exits, its zero count table needs to be
  // retained, so that we can clean up any of the provenance
  // values that it acquired in a future garbage collection pass.
  ZeroCountTable global_zct;
  // We use an atomic counter to generate new `ThreadIds`.
  // We create a new ID every time a thread is registered.
  atomic_uintptr_t thread_id_ctr{0};
};

} // namespace __bsan
#endif // BSAN_THREAD_H
