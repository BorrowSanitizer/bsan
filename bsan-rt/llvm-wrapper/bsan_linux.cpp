#include "sanitizer_common/sanitizer_platform.h"
#if SANITIZER_LINUX

#include "bsan.h"
#include "bsan_thread.h"
#include <linux/membarrier.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

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
  BsanThreadContext *context = (BsanThreadContext *)tsd;
  if (context->destructor_iterations > 1) {
    context->destructor_iterations--;
    CHECK_EQ(0, pthread_setspecific(TSD_KEY, tsd));
    return;
  }
  BlockSignals();
  BsanThread::TSDDtor(tsd);
}

void InitializeTSD(void (*destructor)(void *tsd)) {
  CHECK(!TSD_KEY_INITED);
  TSD_KEY_INITED = true;
  CHECK_EQ(0, pthread_key_create(&TSD_KEY, destructor));
}

} // namespace __bsan
#endif // SANITIZER_LINUX