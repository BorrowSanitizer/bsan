#ifndef BSAN_THREAD_H
#define BSAN_THREAD_H

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_posix.h"

using namespace __sanitizer;
namespace __bsan {

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
  __sanitizer_sigset_t starting_sigset_;

private:
  thread_callback_t start_routine_;
  void *arg_;
};

BsanThread *GetCurrentThread();
void SetCurrentThread(BsanThread *t);

} // namespace __bsan
#endif // BSAN_THREAD_H
