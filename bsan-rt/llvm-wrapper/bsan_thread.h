#ifndef BSAN_THREAD_H
#define BSAN_THREAD_H
#include "bsan.h"
#include "bsan_allocator.h"
#include "bsan_set.h"
#include "sanitizer_common/sanitizer_array_ref.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_posix.h"
#include "sanitizer_common/sanitizer_thread_arg_retval.h"

using namespace __sanitizer;

namespace __bsan {

class BsanThread;
class BsanThreadContext final : public ThreadContextBase {
public:
  explicit BsanThreadContext(int tid)
      : ThreadContextBase(tid), announced(false),
        destructor_iterations(GetPthreadDestructorIterations()),
        thread(nullptr) {}
  bool announced;
  u8 destructor_iterations;
  BsanThread *thread;
  void OnCreated(void *arg) override;
  void OnFinished() override;
};

// BsanThreadContext objects are never freed, so we need many of them.
COMPILER_CHECK(sizeof(BsanThreadContext) <= 256);

class BsanThread {
public:
  template <typename T>
  static BsanThread *Create(const T &data, u32 parent_tid, bool detached) {
    return Create(&data, sizeof(data), parent_tid, detached);
  }
  static BsanThread *Create(u32 parent_tid, bool detached) {
    return Create(nullptr, 0, parent_tid, detached);
  }

  // A destructor called when this thread's context is deinitialized.
  // A pointer to the context is stored in a thread-local variable.
  static void TSDDtor(void *tsd);

  // Destroys an instance of `BsanThread` stored at the given address,
  // which is a thread-local allocation.
  void Destroy();

  // Initializes the object, allocating its shadow stack.
  // This must be called from the thread itself, before it
  // executes its start routine.
  void Init();

  // This function is passed as the argument to `pthread_create`.
  // It configures signal handling and then executes the start routine.
  static void *StartCallback(void *arg);

  void ThreadStart(ThreadID os_id);

  template <typename T> void GetStartData(T &data) const {
    GetStartData(&data, sizeof(data));
  }

  u32 tid() { return context_->tid; }
  BsanThreadContext *context() { return context_; }
  void set_context(BsanThreadContext *context) { context_ = context; }

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

  // Zeroes this thread's tree-node visit counter. This writes to another
  // thread's thread-local storage, so it can only be called when the world
  // has been stopped.
  void ResetVisitCount() {
    if (visits_ptr_)
      *visits_ptr_ = 0;
  }

  // Signal handler settings.
  __sanitizer_sigset_t starting_sigset_;

  // The base of this thread's alternate signal stack.
  // This is needed when deadly signal handlers run on a thread whose
  // stack has overflowed.
  void *altstack_base_ = nullptr;

  AllocatorCache *allocator_cache() { return &allocator_cache_; }

  RustAllocatorCache *rust_allocator_cache() { return &rust_allocator_cache_; }

  uptr os_id;
  void acquireProvenance(Provenance prov) { zct_.insert(prov); }

  void exitUnsafeMode();
  bool enterUnsafeMode();

  GCState getGCState(memory_order order);
  GCState setGCState(GCState state, memory_order order);

private:
  friend struct BsanThreadContext;
  friend struct GlobalContext;
  static BsanThread *Create(const void *start_data, uptr data_size,
                            u32 parent_tid, bool detached);

  void GetStartData(void *out, uptr out_size) const;

  BsanThreadContext *context_;

  ConcreteProvenanceSet zct_;

  // Executes the start routine.
  thread_return_t Start();

  thread_callback_t start_routine_;
  void *arg_;

  uptr stack_top_;
  uptr stack_bottom_;

  void *shadow_stack_bottom_;
  uptr shadow_stack_size_;

  // Per-thread caches for each allocator. These are zero-initialized,
  // since `BsanThread` is allocated via mmap().
  AllocatorCache allocator_cache_;
  RustAllocatorCache rust_allocator_cache_;

  // The address of this thread's thread-local allocation
  // containing the current value of its shadow stack
  // pointer (`__bsan_shadow_stack`).
  Provenance **shadow_stack_ptr_;

  // The address of this thread's thread-local visit counter
  // (`__bsan_visits_since_gc`), so that the GC can reset it when it stops
  // the world.
  uptr *visits_ptr_;
  atomic_uint32_t gc_state_{kUnsafe};

  char start_data_[];
};

BsanThread *CurrentThread();
void SetCurrentThread(BsanThread *t);
u32 GetCurrentTidOrInvalid();
BsanThread *CreateMainThread();
void EnsureMainThreadIDIsCorrect();

ThreadRegistry &GetThreadRegistry();
ThreadArgRetval &GetThreadArgRetval();

BsanThreadContext *GetThreadContextByTidLocked(u32 tid);

void LockThreads() SANITIZER_NO_THREAD_SAFETY_ANALYSIS;
void UnlockThreads() SANITIZER_NO_THREAD_SAFETY_ANALYSIS;

struct ScopedThreadLock {
  ScopedThreadLock() { LockThreads(); }
  ~ScopedThreadLock() { UnlockThreads(); }
  ScopedThreadLock &operator=(const ScopedThreadLock &) = delete;
  ScopedThreadLock(const ScopedThreadLock &) = delete;
};

struct GCUnsafeScope {
  GCUnsafeScope() { CurrentThread()->enterUnsafeMode(); }
  ~GCUnsafeScope() { CurrentThread()->exitUnsafeMode(); }
};

template <typename Fn, typename... Args>
inline void ForEachThread(ScopedThreadLock &threads, Fn callback,
                          Args... args) {
  auto invoke = [&](auto &&thread) { callback(thread, args...); };
  using Invoke = decltype(invoke);
  GetThreadRegistry().RunCallbackForEachThreadLocked(
      [](ThreadContextBase *tctx_base, void *arg) {
        if (tctx_base->status == ThreadStatusRunning) {
          BsanThreadContext *tctx = static_cast<BsanThreadContext *>(tctx_base);
          (*static_cast<Invoke *>(arg))(tctx->thread);
        }
      },
      &invoke);
}
} // namespace __bsan
#endif // BSAN_THREAD_H
