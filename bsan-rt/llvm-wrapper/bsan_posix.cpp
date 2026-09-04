#include "sanitizer_common/sanitizer_platform.h"
#if SANITIZER_LINUX

#include "bsan.h"
#include "bsan_thread.h"
#include <pthread.h>

namespace __bsan {

static pthread_key_t TSD_KEY;
static bool TSD_KEY_INITED = false;

void TSDSet(void *t) {
  // Make sure that `Destroy` gets called at the end.
  CHECK(TSD_KEY_INITED);
  pthread_setspecific(TSD_KEY, t);
}

void *TSDGet() {
  // Make sure that `Destroy` gets called at the end.
  CHECK(TSD_KEY_INITED);
  return pthread_getspecific(TSD_KEY);
}

void PlatformTSDDtor(void *tsd) {
  BsanThread *t = (BsanThread *)tsd;
  if (t->destructor_iterations_ > 1) {
    t->destructor_iterations_--;
    CHECK_EQ(0, pthread_setspecific(TSD_KEY, tsd));
    return;
  }
#if SANITIZER_LINUX
  ScopedBlockSignals block(nullptr);
#endif
  TSDSet(nullptr);
  // Make sure that signal handler can not see a stale current thread pointer.
  atomic_signal_fence(memory_order_seq_cst);
  BsanThread::Destroy(tsd);
}

void InitializeTSD(void (*destructor)(void *tsd)) {
  CHECK(!TSD_KEY_INITED);
  TSD_KEY_INITED = true;
  CHECK_EQ(0, pthread_key_create(&TSD_KEY, destructor));
}

} // namespace __bsan
#endif // SANITIZER_LINUX