#include "bsan.h"
#include "bsan_thread.h"
#include "sanitizer_common/sanitizer_linux.h"
#if SANITIZER_APPLE

namespace __bsan {

void SetCurrentThread(BsanThread *t) {
  // Make sure we do not reset the current BsanThread.
  CHECK_EQ(0, bsan_thread);
  bsan_thread = t;
}

void DestroyTSD(void *tsd) {

}

void InitializeTSD() {

}

} // namespace __bsan

#endif // SANITIZER_APPLE