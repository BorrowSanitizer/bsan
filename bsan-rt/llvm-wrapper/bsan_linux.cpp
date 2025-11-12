#include "bsan.h"
#include "bsan_thread.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_linux.h"
#include "sanitizer_common/sanitizer_platform.h"
#include <pthread.h>
#include <signal.h>

namespace __bsan {

static pthread_key_t TSD_KEY;
static bool TSD_KEY_INITED = false;

void BsanTSDInit() {
  CHECK(!TSD_KEY_INITED);
  TSD_KEY_INITED = true;
  CHECK_EQ(0, pthread_key_create(&TSD_KEY, BsanTSDDtor));
}

BsanThread *GetCurrentThread() { return (BsanThread *)__BSAN_CURR_THREAD; }

void SetCurrentThread(BsanThread *t) {
  // Make sure we do not reset the current BsanThread.
  CHECK_EQ(0, __BSAN_CURR_THREAD);
  __BSAN_CURR_THREAD = t;
  // Make sure that BsanTSDDtor gets called at the end.
  CHECK(TSD_KEY_INITED);
  pthread_setspecific(TSD_KEY, (void *)t);
}

void BsanTSDDtor(void *tsd) {
  BsanThread *t = (BsanThread *)tsd;
  if (t->destructor_iterations_ > 1) {
    t->destructor_iterations_--;
    CHECK_EQ(0, pthread_setspecific(TSD_KEY, tsd));
    return;
  }
  ScopedBlockSignals block(nullptr);
  __BSAN_CURR_THREAD = nullptr;
  // Make sure that signal handler can not see a stale current thread pointer.
  atomic_signal_fence(memory_order_seq_cst);
  BsanThread::TSDDtor(tsd);
}

} // namespace __bsan