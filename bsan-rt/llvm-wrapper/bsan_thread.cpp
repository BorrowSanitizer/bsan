#include "bsan_thread.h"

using namespace __sanitizer;
using namespace __bsan;

SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL void *__BSAN_PROV_STACK = nullptr;

BsanThread *BsanThread::Create(thread_callback_t start_routine, void *arg) {
  uptr PageSize = GetPageSizeCached();
  uptr size = RoundUpTo(sizeof(BsanThread), PageSize);
  BsanThread *thread = (BsanThread *)MmapOrDie(size, __func__);
  thread->start_routine_ = start_routine;
  thread->arg_ = arg;
  thread->destructor_iterations_ = GetPthreadDestructorIterations();
  return thread;
}

void BsanThread::Init() {
  GetThreadStackTopAndBottom(IsMainThread(), &stack_top_, &stack_bottom_);
  this->prov_stack_size = this->stack_top_ - this->stack_bottom_;
  this->prov_stack = (uptr *)MmapOrDie(this->prov_stack_size, __func__);
  __BSAN_PROV_STACK = this->prov_stack + this->prov_stack_size;
}

void BsanThread::TSDDtor(void *tsd) {
  BsanThread *t = (BsanThread *)tsd;
  t->Destroy();
}

void BsanThread::Destroy() {
  UnmapOrDie(this->prov_stack, this->prov_stack_size);
  uptr size = RoundUpTo(sizeof(BsanThread), GetPageSizeCached());
  UnmapOrDie(this, size);
}

thread_return_t BsanThread::ThreadStart() {
  if (!start_routine_) {
    return 0;
  }
  return start_routine_(arg_);
}
