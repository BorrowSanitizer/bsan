#include "bsan.h"
#include "bsan_thread.h"
#include "interception/interception.h"
#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_allocator_dlsym.h"
#include "sanitizer_common/sanitizer_allocator_interface.h"
#include "sanitizer_common/sanitizer_linux.h"

using namespace __sanitizer;
using namespace __bsan;

DECLARE_REAL(void *, malloc, SIZE_T)
DECLARE_REAL(void, free, void *)

bool inst_caller(uptr bp) {
  bp = bp ? *((uptr *)bp) : bp;
  bool is_inst = bp == BSAN_TLS_MARKER;
  if (is_inst) {
    BSAN_TLS_MARKER = 0;
  }
  return is_inst;
}

#define INST_CALLER() inst_caller(GET_CURRENT_FRAME())

#define ENSURE_BSAN_INITED()                                                   \
  do {                                                                         \
    CHECK(!BSAN_INIT_RUNNING);                                                 \
    if (!BSAN_INITED) {                                                        \
      __bsan_init();                                                           \
    }                                                                          \
  } while (0)

extern "C" int pthread_attr_init(void *attr);
extern "C" int pthread_attr_destroy(void *attr);

struct DlsymAlloc : public DlSymAllocator<DlsymAlloc> {
  static bool UseImpl() { return !BSAN_INITED; }
};

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

extern "C" void *__crt_malloc(SIZE_T size) {
  if (DlsymAlloc::Use())
    return DlsymAlloc::Allocate(size);
  return REAL(malloc)(size);
}

INTERCEPTOR(void *, malloc, SIZE_T size) {
  if (DlsymAlloc::Use())
    return DlsymAlloc::Allocate(size);
  void *ptr = REAL(malloc)(size);
  if (INST_CALLER()) {
    Provenance *RetSlot = GetRetValSlot(0);
    BorTag Tag = __bsan_new_bor_tag();
    *RetSlot = {Tag, __bsan_alloc(ptr, size, Tag)};
  }
  return ptr;
}

extern "C" void __crt_free(void *ptr) {
  if (UNLIKELY(!ptr))
    return;
  if (DlsymAlloc::PointerIsMine(ptr))
    return DlsymAlloc::Free(ptr);
  REAL(free)(ptr);
}

INTERCEPTOR(void, free, void *ptr) {
  if (UNLIKELY(!ptr))
    return;
  if (DlsymAlloc::PointerIsMine(ptr))
    return DlsymAlloc::Free(ptr);
  if (INST_CALLER()) {
    Provenance *Slot = GetArgSlot(0);
    __bsan_dealloc(ptr, Slot->Tag, Slot->Info);
  }
  return REAL(free)(ptr);
}

INTERCEPTOR(void *, calloc, SIZE_T nmemb, SIZE_T size) {
  if (DlsymAlloc::Use())
    return DlsymAlloc::Callocate(nmemb, size);
  void *ptr = REAL(calloc)(nmemb, size);
  Provenance *RetSlot = GetRetValSlot(0);
  if (INST_CALLER()) {
    BorTag Tag = __bsan_new_bor_tag();
    *RetSlot = {Tag, __bsan_alloc(ptr, nmemb * size, Tag)};
  } else {
    *RetSlot = {0, nullptr};
  }
  return ptr;
}

INTERCEPTOR(void *, realloc, void *ptr, SIZE_T size) {
  if (DlsymAlloc::Use() || DlsymAlloc::PointerIsMine(ptr))
    return DlsymAlloc::Realloc(ptr, size);
  bool is_inst = INST_CALLER();
  if (is_inst) {
    Provenance *Slot = GetArgSlot(0);
    __bsan_dealloc(ptr, Slot->Tag, Slot->Info);
  }
  void *nptr = REAL(realloc)(ptr, size);
  Provenance *RetSlot = GetRetValSlot(0);
  if (is_inst) {
    BorTag Tag = __bsan_new_bor_tag();
    *RetSlot = {Tag, __bsan_alloc(nptr, size, Tag)};
  } else {
    *RetSlot = {0, nullptr};
  }
  return nptr;
}

extern "C" {

SANITIZER_INTERFACE_ATTRIBUTE void *__bsan_memset(void *dest, int c, uptr n) {
  if (!BSAN_INITED)
    return internal_memset(dest, c, n);
  if (BSAN_INIT_RUNNING)
    return internal_memset(dest, c, n);
  ENSURE_BSAN_INITED();
  void *res = internal_memset(dest, c, n);
  __bsan_shadow_clear(dest, n);
  return res;
}

SANITIZER_INTERFACE_ATTRIBUTE void *__bsan_memmove(void *dest, const void *src,
                                                   uptr n) {
  if (!BSAN_INITED)
    return internal_memmove(dest, src, n);
  if (BSAN_INIT_RUNNING)
    return internal_memmove(dest, src, n);
  ENSURE_BSAN_INITED();
  __bsan_shadow_transfer(dest, src, n);
  void *res = internal_memmove(dest, src, n);
  return res;
}

SANITIZER_INTERFACE_ATTRIBUTE void *__bsan_memcpy(void *dest, const void *src,
                                                  uptr n) {
  if (!BSAN_INITED)
    return internal_memcpy(dest, src, n);
  if (BSAN_INIT_RUNNING)
    return internal_memcpy(dest, src, n);
  ENSURE_BSAN_INITED();
  void *res = internal_memcpy(dest, src, n);
  __bsan_shadow_transfer(dest, src, n);
  return res;
}

} // extern "C"

namespace __bsan {

void InitializeInterceptors() {
  __interception::DoesNotSupportStaticLinking();
  INTERCEPT_FUNCTION(pthread_create);
  INTERCEPT_FUNCTION(free);
  INTERCEPT_FUNCTION(malloc);
  INTERCEPT_FUNCTION(calloc);
  INTERCEPT_FUNCTION(realloc);
}

} // namespace __bsan
