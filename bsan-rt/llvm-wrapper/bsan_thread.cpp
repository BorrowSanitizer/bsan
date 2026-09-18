#include "bsan_thread.h"
#include "bsan.h"
#include "bsan_global.h"
#include "bsan_interface_internal.h"
#include "sanitizer_common/sanitizer_atomic.h"

using namespace __sanitizer;
using namespace __bsan;

namespace __bsan {

BsanThread *CurrentThread() { return (BsanThread *)TSDGet(); }

void SetCurrentThread(BsanThread *t) { TSDSet((void *)t); }

BsanThread *BsanThread::Create(thread_callback_t start_routine, void *arg) {
  uptr PageSize = GetPageSizeCached();
  uptr size = RoundUpTo(sizeof(BsanThread), PageSize);
  BsanThread *thread = (BsanThread *)MmapOrDie(size, __func__);
  thread->start_routine_ = start_routine;
  thread->arg_ = arg;
  thread->destructor_iterations_ = GetPthreadDestructorIterations();
  global_ctx()->Threads().RegisterThread(thread);
  return thread;
}

void BsanThread::Init() {
  GetThreadStackTopAndBottom(IsMainThread(), &stack_top_, &stack_bottom_);
  shadow_stack_size_ = stack_top_ - stack_bottom_;
  shadow_stack_bottom_ = MmapOrDie(shadow_stack_size_, __func__);
  __bsan_shadow_stack =
      (Provenance *)(((uptr)shadow_stack_bottom_) + shadow_stack_size_);
  // We record the address of the thread-local shadow stack pointer so
  // that the GC can accurately read the initialized contents of the
  // shadow stack when it stops the world.
  shadow_stack_ptr_ = &__bsan_shadow_stack;
  if (common_flags()->use_sigaltstack)
    altstack_base_ = SetAlternateSignalStack();
}

void BsanThread::Destroy(void *tsd) {
  BsanThread *t = (BsanThread *)tsd;
  global_ctx()->Threads().DeregisterThread(t);
  t->malloc_storage().CommitBack();
  t->zct_.~ZeroCountTable();
  if (common_flags()->use_sigaltstack)
    UnsetAlternateSignalStack(t->altstack_base_);
  UnmapOrDie(t->shadow_stack_bottom_, t->shadow_stack_size_);
  uptr size = RoundUpTo(sizeof(BsanThread), GetPageSizeCached());
  UnmapOrDie(t, size);
}

thread_return_t BsanThread::Start() {
  if (!start_routine_) {
    return 0;
  }
  return start_routine_(arg_);
}

void *BsanThread::StartCallback(void *arg) {
  BsanThread *t = (BsanThread *)arg;
  SetCurrentThread(t);
  t->Init();
#if SANITIZER_LINUX
  SetSigProcMask(&t->starting_sigset_, nullptr);
#endif
  return t->Start();
}

void ThreadManager::RegisterThread(BsanThread *thread) {
  Lock l(&mtx_);
  uptr tid = atomic_fetch_add(&thread_id_ctr, 1, memory_order_relaxed);
  threads[tid] = thread;
  thread->id = tid;
}

void ThreadManager::DeregisterThread(BsanThread *thread) {
  Lock l(&mtx_);
  global_zct_.drainFrom(thread->zct_);
  threads.erase(thread->id);
}

void ThreadManager::acquireProvenance(Provenance prov) {
  Lock l(&mtx_);
  global_zct_.acquireProvenance(prov);
}
} // namespace __bsan
