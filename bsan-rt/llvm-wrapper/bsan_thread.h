#ifndef BSAN_THREAD_H
#define BSAN_THREAD_H
#include "bsan_allocator.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_posix.h"

using namespace __sanitizer;
namespace __bsan {

typedef uptr ThreadId;

class BsanThread {
public:
  static BsanThread *Create(thread_callback_t start_routine, void *arg);
  static void TSDDtor(void *tsd);
  void Destroy();
  void Init(); // Should be called from the thread itself.
  thread_return_t ThreadStart();
  bool IsMainThread() { return start_routine_ == nullptr; }
  uptr stack_top() { return stack_top_; }
  uptr stack_bottom() { return stack_bottom_; }
  int destructor_iterations_;
  ThreadId id;
  __sanitizer_sigset_t starting_sigset_;
  BsanThreadLocalMallocStorage &malloc_storage() { return malloc_storage_; }

private:
  uptr stack_top_;
  uptr stack_bottom_;
  thread_callback_t start_routine_;
  void *arg_;

  void *prov_stack_;
  uptr prov_stack_size_;
  BsanThreadLocalMallocStorage malloc_storage_;
};

BsanThread *GetCurrentThread();
void SetCurrentThread(BsanThread *t);

} // namespace __bsan
#endif // BSAN_THREAD_H
