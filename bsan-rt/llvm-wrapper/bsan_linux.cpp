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

void InitMembarrier() {
  // We're using the "private expedited" variant here, which effects
  // only the threads spawned by this process. This needs to be
  // preregistered: "A process must register its intent to use the private
  // expedited command prior to using it."
  syscall(SYS_membarrier, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0);
}

void Membarrier() {
  // Within a given thread, every read or write that
  // happens before this barrier will become globally visible.
  syscall(SYS_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0);
}

} // namespace __bsan
#endif // SANITIZER_LINUX