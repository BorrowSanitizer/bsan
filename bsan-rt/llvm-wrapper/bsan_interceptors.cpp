#include "bsan.h"
#include "bsan_interface_internal.h"
#include "bsan_thread.h"
#include "interception/interception.h"
#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_allocator_dlsym.h"
#include "sanitizer_common/sanitizer_allocator_interface.h"
#include "sanitizer_common/sanitizer_linux.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_vector.h"

using namespace __sanitizer;
using namespace __bsan;

DECLARE_REAL(void *, malloc, SIZE_T)
DECLARE_REAL(void, free, void *)

extern "C" int pthread_attr_init(void *attr);
extern "C" int pthread_attr_destroy(void *attr);

struct DlsymAlloc : public DlSymAllocator<DlsymAlloc> {
  static bool UseImpl() { return !bsan_inited; }
};

#define INST_CALLER(f) CallerIsInstrumented((void *)f)

#define ENSURE_BSAN_INITED()                                                   \
  do {                                                                         \
    CHECK(!bsan_init_running);                                                 \
    if (!bsan_inited) {                                                        \
      __bsan_init();                                                           \
    }                                                                          \
  } while (0)

struct InterceptorContext {
  Mutex AtExitLock;
  Vector<struct BSanAtExitRecord *> AtExitStack;
  InterceptorContext() : AtExitStack() {}
};

alignas(64) static char ictx[sizeof(InterceptorContext)];
InterceptorContext *interceptor_ctx() {
  return reinterpret_cast<InterceptorContext *>(&ictx[0]);
}

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

extern "C" void *__bsan_crt_malloc(SIZE_T size) {
  if (DlsymAlloc::Use())
    return DlsymAlloc::Allocate(size);
  return REAL(malloc)(size);
}

INTERCEPTOR(void *, malloc, SIZE_T size) {
  GET_SPAN;
  if (DlsymAlloc::Use())
    return DlsymAlloc::Allocate(size);
  void *ptr = REAL(malloc)(size);
  if (INST_CALLER(malloc)) {
    Provenance *RetSlot = GetSlot(0);
    BorTag Tag = NewBorTag();
    *RetSlot = {Tag, __bsan_alloc(ptr, size, Tag, span)};
  }
  return ptr;
}

extern "C" void __bsan_crt_free(void *ptr) {
  if (UNLIKELY(!ptr))
    return;
  if (DlsymAlloc::PointerIsMine(ptr))
    return DlsymAlloc::Free(ptr);
  REAL(free)(ptr);
}

INTERCEPTOR(void, free, void *ptr) {
  GET_SPAN_PC_BP;
  if (UNLIKELY(!ptr))
    return;
  if (DlsymAlloc::PointerIsMine(ptr))
    return DlsymAlloc::Free(ptr);
  if (INST_CALLER(free)) {
    Provenance *Slot = GetSlot(0);
    __bsan_dealloc(ptr, Slot->Tag, Slot->Info, span);
    HANDLE_ERROR(pc, bp);
  }
  return REAL(free)(ptr);
}

INTERCEPTOR(void *, calloc, SIZE_T nmemb, SIZE_T size) {
  uptr span = GET_CALLER_PC();
  if (DlsymAlloc::Use())
    return DlsymAlloc::Callocate(nmemb, size);
  void *ptr = REAL(calloc)(nmemb, size);
  Provenance *RetSlot = GetSlot(0);
  if (INST_CALLER(calloc)) {
    BorTag Tag = NewBorTag();
    *RetSlot = {Tag, __bsan_alloc(ptr, nmemb * size, Tag, span)};
  }
  return ptr;
}

INTERCEPTOR(void *, realloc, void *ptr, SIZE_T size) {
  GET_SPAN_PC_BP;
  if (DlsymAlloc::Use() || DlsymAlloc::PointerIsMine(ptr))
    return DlsymAlloc::Realloc(ptr, size);
  bool is_inst = INST_CALLER(realloc);
  if (is_inst) {
    Provenance *Slot = GetSlot(0);
    __bsan_dealloc(ptr, Slot->Tag, Slot->Info, span);
    HANDLE_ERROR(pc, bp);
  }
  void *nptr = REAL(realloc)(ptr, size);
  if (is_inst) {
    Provenance *RetSlot = GetSlot(0);
    BorTag Tag = NewBorTag();
    *RetSlot = {Tag, __bsan_alloc(nptr, size, Tag, span)};
  }
  return nptr;
}

extern "C" {

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_memset(void *dest, int c, uptr n) {
  if (!bsan_inited || bsan_init_running) {
    internal_memset(dest, c, n);
  } else {
    ENSURE_BSAN_INITED();
    internal_memset(dest, c, n);
    __bsan_shadow_clear(dest, n);
  }
}

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_memmove(void *dest, const void *src,
                                                  uptr n) {
  if (!bsan_inited || bsan_init_running) {
    internal_memmove(dest, src, n);
  } else {
    ENSURE_BSAN_INITED();
    __bsan_shadow_transfer(dest, src, n);
    internal_memmove(dest, src, n);
  }
}

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_memcpy(void *dest, const void *src,
                                                 uptr n) {
  if (!bsan_inited || bsan_init_running) {
    internal_memcpy(dest, src, n);
  } else {
    ENSURE_BSAN_INITED();
    internal_memcpy(dest, src, n);
    __bsan_shadow_transfer(dest, src, n);
  }
}

} // extern "C"

struct BSanAtExitRecord {
  void (*func)(void *arg);
  void *arg;
};

void BSanAtExitWrapper() {
  BSanAtExitRecord *r;
  {
    Lock l(&interceptor_ctx()->AtExitLock);

    uptr element = interceptor_ctx()->AtExitStack.Size() - 1;
    r = interceptor_ctx()->AtExitStack[element];
    interceptor_ctx()->AtExitStack.PopBack();
  }

  ClearSlot(0);
  ((void (*)())r->func)();
  InternalFree(r);
}

void BSanCxaAtExitWrapper(void *arg) {
  ClearSlot(0);
  BSanAtExitRecord *r = (BSanAtExitRecord *)arg;
  // libc before 2.27 had race which caused occasional double handler execution
  // https://sourceware.org/ml/libc-alpha/2017-08/msg01204.html
  if (!r->func)
    return;
  r->func(r->arg);
  r->func = nullptr;
}

static int setup_at_exit_wrapper(void (*f)(), void *arg, void *dso);

// Unpoison argument shadow for C++ module destructors.
INTERCEPTOR(int, __cxa_thread_atexit_impl, void (*func)(void *), void *arg,
            void *dso_handle) {
  if (bsan_init_running)
    return REAL(__cxa_thread_atexit_impl)(func, arg, dso_handle);
  return setup_at_exit_wrapper((void (*)())func, arg, dso_handle);
}

// Unpoison argument shadow for C++ module destructors.
INTERCEPTOR(int, __cxa_atexit, void (*func)(void *), void *arg,
            void *dso_handle) {
  if (bsan_init_running)
    return REAL(__cxa_atexit)(func, arg, dso_handle);
  return setup_at_exit_wrapper((void (*)())func, arg, dso_handle);
}

// Unpoison argument shadow for C++ module destructors.
INTERCEPTOR(int, atexit, void (*func)()) {
  // Avoid calling real atexit as it is unreachable on at least on Linux.
  if (bsan_init_running)
    return REAL(__cxa_atexit)((void (*)(void *a))func, 0, 0);
  return setup_at_exit_wrapper((void (*)())func, 0, 0);
}

static int setup_at_exit_wrapper(void (*f)(), void *arg, void *dso) {
  ENSURE_BSAN_INITED();
  BSanAtExitRecord *r =
      (BSanAtExitRecord *)InternalAlloc(sizeof(BSanAtExitRecord));
  r->func = (void (*)(void *a))f;
  r->arg = arg;
  int res;
  if (!dso) {
    // NetBSD does not preserve the 2nd argument if dso is equal to 0
    // Store ctx in a local stack-like structure

    Lock l(&interceptor_ctx()->AtExitLock);

    res = REAL(__cxa_atexit)((void (*)(void *a))BSanAtExitWrapper, 0, 0);
    if (!res) {
      interceptor_ctx()->AtExitStack.PushBack(r);
    }
  } else {
    res = REAL(__cxa_atexit)(BSanCxaAtExitWrapper, r, dso);
  }
  return res;
}

namespace __bsan {

void InitializeInterceptors() {
  __interception::DoesNotSupportStaticLinking();
  INTERCEPT_FUNCTION(pthread_create);
  INTERCEPT_FUNCTION(free);
  INTERCEPT_FUNCTION(malloc);
  INTERCEPT_FUNCTION(calloc);
  INTERCEPT_FUNCTION(realloc);
  INTERCEPT_FUNCTION(atexit);
  INTERCEPT_FUNCTION(__cxa_atexit);
  INTERCEPT_FUNCTION(__cxa_thread_atexit_impl);
}

} // namespace __bsan