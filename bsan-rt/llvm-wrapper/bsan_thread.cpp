#include "bsan_thread.h"
#include "bsan.h"
#include "bsan_global.h"
#include "bsan_interface_internal.h"
#include "sanitizer_common/sanitizer_atomic.h"

using namespace __sanitizer;
using namespace __bsan;

namespace __bsan {

void BsanThreadContext::OnCreated(void *arg) {
  thread = static_cast<BsanThread *>(arg);
  thread->set_context(this);
}

void BsanThreadContext::OnFinished() {
  // Drop the link to the AsanThread object.
  thread = nullptr;
}

static ThreadRegistry *bsan_thread_registry;
static ThreadArgRetval *thread_data;

static Mutex mu_for_thread_context;

static LowLevelAllocator allocator_for_thread_context;

static ThreadContextBase *GetBsanThreadContext(u32 tid) {
  Lock lock(&mu_for_thread_context);
  return new (allocator_for_thread_context) BsanThreadContext(tid);
}

static void InitThreads() {
  static bool initialized;
  // Don't worry about thread_safety - this should be called when there is
  // a single thread.
  if (LIKELY(initialized))
    return;
  // Never reuse BSan threads: we store pointer to BsanThreadContext
  // in TSD and can't reliably tell when no more TSD destructors will
  // be called. It would be wrong to reuse BsanThreadContext for another
  // thread before all TSD destructors will be called for it.

  // MIPS requires aligned address
  alignas(alignof(ThreadRegistry)) static char
      thread_registry_placeholder[sizeof(ThreadRegistry)];
  alignas(alignof(ThreadArgRetval)) static char
      thread_data_placeholder[sizeof(ThreadArgRetval)];

  bsan_thread_registry =
      new (thread_registry_placeholder) ThreadRegistry(GetBsanThreadContext);
  thread_data = new (thread_data_placeholder) ThreadArgRetval();
  initialized = true;
}

ThreadRegistry &GetThreadRegistry() {
  InitThreads();
  return *bsan_thread_registry;
}

ThreadArgRetval &GetThreadArgRetval() {
  InitThreads();
  return *thread_data;
}

BsanThreadContext *GetThreadContextByTidLocked(u32 tid) {
  return static_cast<BsanThreadContext *>(
      GetThreadRegistry().GetThreadLocked(tid));
}

BsanThread *CurrentThread() {
  BsanThreadContext *context = reinterpret_cast<BsanThreadContext *>(TSDGet());
  if (!context) {
    return nullptr;
  }
  return context->thread;
}

void SetCurrentThread(BsanThread *t) {
  CHECK(t->context());
  // Make sure we do not reset the current BsanThread.
  CHECK_EQ(0, TSDGet());
  TSDSet(t->context());
  CHECK_EQ(t->context(), TSDGet());
}

u32 GetCurrentTidOrInvalid() {
  BsanThread *t = CurrentThread();
  return t ? t->tid() : kInvalidTid;
}

void EnsureMainThreadIDIsCorrect() {
  if (GetCurrentTidOrInvalid() == kMainTid)
    CurrentThread()->os_id = GetTid();
}

BsanThread *BsanThread::Create(const void *start_data, uptr data_size,
                               u32 parent_tid, bool detached) {
  uptr PageSize = GetPageSizeCached();
  uptr size = RoundUpTo(sizeof(BsanThread), PageSize);
  BsanThread *thread = (BsanThread *)MmapOrDie(size, __func__);
  if (data_size) {
    uptr availible_size = (uptr)thread + size - (uptr)(thread->start_data_);
    CHECK_LE(data_size, availible_size);
    internal_memcpy(thread->start_data_, start_data, data_size);
  }
  GetThreadRegistry().CreateThread(0, detached, parent_tid, thread);
  return thread;
}

void BsanThread::ThreadStart(ThreadID os_id) {
  Init();
  GetThreadRegistry().StartThread(tid(), os_id, ThreadType::Regular, nullptr);
  if (common_flags()->use_sigaltstack)
    altstack_base_ = SetAlternateSignalStack();
}

void BsanThread::GetStartData(void *out, uptr out_size) const {
  internal_memcpy(out, start_data_, out_size);
}

BsanThread *CreateMainThread() {
  BsanThread *main_thread = BsanThread::Create(
      /* parent_tid */ kMainTid,
      /* detached */ true);
  SetCurrentThread(main_thread);
  main_thread->ThreadStart(internal_getpid());
  return main_thread;
}

void BsanThread::Init() {
  bool is_main_thread = this->tid() == kMainTid;
  GetThreadStackTopAndBottom(is_main_thread, &stack_top_, &stack_bottom_);
  shadow_stack_size_ = stack_top_ - stack_bottom_;
  shadow_stack_bottom_ = MmapOrDie(shadow_stack_size_, __func__);
  __bsan_shadow_stack =
      (Provenance *)(((uptr)shadow_stack_bottom_) + shadow_stack_size_);
  // We record the address of the thread-local shadow stack pointer so
  // that the GC can accurately read the initialized contents of the
  // shadow stack when it stops the world.
  shadow_stack_ptr_ = &__bsan_shadow_stack;
  // Likewise, we record the address of the thread-local visit counter so that
  // the GC can zero it for every thread once any one of them has reached the
  // collection threshold.
  visits_ptr_ = &__bsan_visits_since_gc;
}

void BsanThread::TSDDtor(void *tsd) {
  BsanThreadContext *context = (BsanThreadContext *)tsd;
  if (context->thread)
    context->thread->Destroy();
}

void BsanThread::Destroy() {
  int tid = this->tid();
  bool was_running =
      (GetThreadRegistry().FinishThread(tid) == ThreadStatusRunning);
  if (was_running) {
    if (BsanThread *thread = CurrentThread())
      CHECK_EQ(this, thread);
    this->malloc_storage().CommitBack();
    if (common_flags()->use_sigaltstack)
      UnsetAlternateSignalStack(altstack_base_);
    global_ctx()->acquireProvenance(zct);
    zct.~ZeroCountTable();
    UnmapOrDie(shadow_stack_bottom_, shadow_stack_size_);
  } else {
    CHECK_NE(this, CurrentThread());
  }
  uptr size = RoundUpTo(sizeof(BsanThread), GetPageSizeCached());
  UnmapOrDie(this, size);
}

void LockThreads() {
  GetThreadRegistry().Lock();
  GetThreadArgRetval().Lock();
}

void UnlockThreads() {
  GetThreadArgRetval().Unlock();
  GetThreadRegistry().Unlock();
}

} // namespace __bsan
