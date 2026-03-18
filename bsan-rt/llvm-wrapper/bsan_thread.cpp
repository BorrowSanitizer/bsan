#include "bsan_thread.h"
#include "sanitizer_common/sanitizer_atomic.h"

using namespace __sanitizer;
using namespace __bsan;

SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL void *__BSAN_PROV_STACK = nullptr;

extern atomic_uintptr_t THREAD_ID_CTR;

BsanThread *BsanThread::Create(thread_callback_t start_routine, void *arg) {
  uptr PageSize = GetPageSizeCached();
  uptr size = RoundUpTo(sizeof(BsanThread), PageSize);
  BsanThread *thread = (BsanThread *)MmapOrDie(size, __func__);
  thread->start_routine_ = start_routine;
  thread->arg_ = arg;
  thread->destructor_iterations_ = GetPthreadDestructorIterations();
  thread->id = atomic_fetch_add(&THREAD_ID_CTR, 1, memory_order_relaxed);
  return thread;
}

void BsanThread::Init() {
  GetThreadStackTopAndBottom(IsMainThread(), &stack_top_, &stack_bottom_);
  prov_stack_size_ = stack_top_ - stack_bottom_;
  prov_stack_ = MmapOrDie(prov_stack_size_, __func__);
  __BSAN_PROV_STACK = (void *)(((u8 *)prov_stack_) + prov_stack_size_);
}

void BsanThread::TSDDtor(void *tsd) {
  BsanThread *t = (BsanThread *)tsd;
  t->Destroy();
}

void BsanThread::Destroy() {
  UnmapOrDie(prov_stack_, prov_stack_size_);
  uptr size = RoundUpTo(sizeof(BsanThread), GetPageSizeCached());
  UnmapOrDie(this, size);
}

thread_return_t BsanThread::ThreadStart() {
  if (!start_routine_) {
    return 0;
  }
  return start_routine_(arg_);
}
