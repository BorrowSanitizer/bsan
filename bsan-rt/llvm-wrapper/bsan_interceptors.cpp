#include "bsan.h"
#include "bsan_interface.h"
#include "bsan_thread.h"
#include "interception/interception.h"
#include "sanitizer_common/sanitizer_linux.h"

using namespace __sanitizer;
using namespace __bsan;

#define ENSURE_BSAN_INITED()                                                   \
  do {                                                                         \
    CHECK(!BSAN_INIT_RUNNING);                                              \
    if (!BSAN_INITED) {                                                        \
      __bsan_init();                                                           \
    }                                                                          \
  } while (0)

extern "C" int pthread_attr_init(void *attr);
extern "C" int pthread_attr_destroy(void *attr);

static void *BsanThreadStartFunc(void *arg) {
  BsanThread *t = (BsanThread *)arg;
  SetCurrentThread(t);
  t->Init();
  SetSigProcMask(&t->starting_sigset_, nullptr);
  return t->ThreadStart();
}

INTERCEPTOR(int, pthread_create, void *th, void *attr,
            void *(*callback)(void *), void *param) {
  ENSURE_BSAN_INITED();
  __sanitizer_pthread_attr_t myattr;
  if (!attr) {
    pthread_attr_init(&myattr);
    attr = &myattr;
  }
  BsanThread *t = BsanThread::Create(callback, param);
  ScopedBlockSignals block(&t->starting_sigset_);
  int res = REAL(pthread_create)(th, attr, BsanThreadStartFunc, t);

  if (attr == &myattr) {
    pthread_attr_destroy(&myattr);
  }
  return res;
}

namespace __bsan {

void InitializeInterceptors() {
  __interception::DoesNotSupportStaticLinking();
  INTERCEPT_FUNCTION(pthread_create);
}

} // namespace __bsan
