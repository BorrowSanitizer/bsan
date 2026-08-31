#include "sanitizer_common/sanitizer_platform.h"
#if SANITIZER_LINUX | SANITIZER_APPLE

#include "bsan.h"
#include "bsan_thread.h"
#include <pthread.h>

namespace __bsan {

static pthread_key_t TSD_KEY;
static bool TSD_KEY_INITED = false;

void PlatformSetCurrentThread(BsanThread *t) {
  // Make sure that `Destroy` gets called at the end.
  CHECK(TSD_KEY_INITED);
  pthread_setspecific(TSD_KEY, (void *)t);
}

void DestroyTSD(void *tsd) {
  BsanThread *t = (BsanThread *)tsd;
  if (t->destructor_iterations_ > 1) {
    t->destructor_iterations_--;
    CHECK_EQ(0, pthread_setspecific(TSD_KEY, tsd));
    return;
  }
#if SANITIZER_LINUX
  ScopedBlockSignals block(nullptr);
#endif
  ClearCurrentThread();
  // Make sure that signal handler can not see a stale current thread pointer.
  atomic_signal_fence(memory_order_seq_cst);
  BsanThread::Destroy(tsd);
}

void InitializeTSD() {
  CHECK(!TSD_KEY_INITED);
  TSD_KEY_INITED = true;
  CHECK_EQ(0, pthread_key_create(&TSD_KEY, DestroyTSD));
}

} // namespace __bsan
#endif // SANITIZER_LINUX | SANITIZER_APPLE