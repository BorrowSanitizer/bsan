#define SANITIZER_COMMON_NO_REDEFINE_BUILTINS

#include "bsan.h"
#include "bsan_interface_internal.h"
#include "bsan_thread.h"
#include "interception/interception.h"
#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_allocator_dlsym.h"
#include "sanitizer_common/sanitizer_allocator_interface.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_errno.h"
#include "sanitizer_common/sanitizer_errno_codes.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_linux.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_platform_interceptors.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_vector.h"

using namespace __sanitizer;
using namespace __bsan;

namespace __bsan {
THREADLOCAL int block_interception;
bool BlockInterception() { return block_interception; }
int OnExit() { return 0; }
} // namespace __bsan

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

struct LocalInterceptorContext {
  bool block_interception;
};

struct GlobalInterceptorContext {
  Mutex AtExitLock;
  Vector<struct BSanAtExitRecord *> AtExitStack;
  GlobalInterceptorContext() : AtExitStack() {}
};

alignas(64) static char ictx[sizeof(GlobalInterceptorContext)];
GlobalInterceptorContext *global_interceptor_ctx() {
  return reinterpret_cast<GlobalInterceptorContext *>(&ictx[0]);
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
  bool already_in_scope = BlockInterception();
  InterceptorBarrier barrier;
  void *ptr = REAL(malloc)(size);
  if (!already_in_scope && INST_CALLER(malloc)) {
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
  bool already_in_scope = BlockInterception();
  InterceptorBarrier barrier;
  if (!already_in_scope && INST_CALLER(free)) {
    Provenance *Slot = GetSlot(0);
    __bsan_dealloc(ptr, Slot->Tag, Slot->Info, span);
    HANDLE_ERROR_PC_BP(pc, bp);
  }
  return REAL(free)(ptr);
}

INTERCEPTOR(void *, calloc, SIZE_T nmemb, SIZE_T size) {
  uptr span = GET_CALLER_PC();
  if (DlsymAlloc::Use())
    return DlsymAlloc::Callocate(nmemb, size);
  bool already_in_scope = BlockInterception();
  InterceptorBarrier barrier;
  void *ptr = REAL(calloc)(nmemb, size);
  if (!already_in_scope && INST_CALLER(calloc)) {
    Provenance *RetSlot = GetSlot(0);
    BorTag Tag = NewBorTag();
    *RetSlot = {Tag, __bsan_alloc(ptr, nmemb * size, Tag, span)};
  }
  return ptr;
}

INTERCEPTOR(void *, realloc, void *ptr, SIZE_T size) {
  GET_SPAN_PC_BP;
  if (DlsymAlloc::Use() || DlsymAlloc::PointerIsMine(ptr))
    return DlsymAlloc::Realloc(ptr, size);
  bool already_in_scope = BlockInterception();
  InterceptorBarrier barrier;
  bool is_inst = !already_in_scope && INST_CALLER(realloc);
  if (is_inst) {
    Provenance *Slot = GetSlot(0);
    __bsan_dealloc(ptr, Slot->Tag, Slot->Info, span);
    HANDLE_ERROR_PC_BP(pc, bp);
  }
  void *nptr = REAL(realloc)(ptr, size);
  __bsan_shadow_transfer(nptr, ptr, size);
  if (is_inst) {
    Provenance *RetSlot = GetSlot(0);
    BorTag Tag = NewBorTag();
    *RetSlot = {Tag, __bsan_alloc(nptr, size, Tag, span)};
  }
  return nptr;
}

extern "C" {

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_memset(void *dest, int c, uptr n) {
  if (!bsan_inited || bsan_init_running || BlockInterception()) {
    internal_memset(dest, c, n);
  } else {
    ENSURE_BSAN_INITED();
    internal_memset(dest, c, n);
    __bsan_shadow_clear(dest, n);
  }
}

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_memmove(void *dest, const void *src,
                                                  uptr n) {
  if (!bsan_inited || bsan_init_running || BlockInterception()) {
    internal_memmove(dest, src, n);
  } else {
    ENSURE_BSAN_INITED();
    InterceptorBarrier barrier;
    __bsan_shadow_transfer(dest, src, n);
    internal_memmove(dest, src, n);
  }
}

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_memcpy(void *dest, const void *src,
                                                 uptr n) {
  if (!bsan_inited || bsan_init_running || BlockInterception()) {
    internal_memcpy(dest, src, n);
  } else {
    ENSURE_BSAN_INITED();
    internal_memcpy(dest, src, n);
    InterceptorBarrier barrier;
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
    Lock l(&global_interceptor_ctx()->AtExitLock);

    uptr element = global_interceptor_ctx()->AtExitStack.Size() - 1;
    r = global_interceptor_ctx()->AtExitStack[element];
    global_interceptor_ctx()->AtExitStack.PopBack();
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

    Lock l(&global_interceptor_ctx()->AtExitLock);

    res = REAL(__cxa_atexit)((void (*)(void *a))BSanAtExitWrapper, 0, 0);
    if (!res) {
      global_interceptor_ctx()->AtExitStack.PushBack(r);
    }
  } else {
    res = REAL(__cxa_atexit)(BSanCxaAtExitWrapper, r, dso);
  }
  return res;
}

#define BSAN_INTERCEPT_FUNC(name)                                              \
  do {                                                                         \
    if (!INTERCEPT_FUNCTION(name))                                             \
      VReport(1, "BorrowSanitizer: failed to intercept '%s'\n", #name);        \
  } while (0)

#define BSAN_INTERCEPT_FUNC_VER(name, ver)                                     \
  do {                                                                         \
    if (!INTERCEPT_FUNCTION_VER(name, ver))                                    \
      VReport(1, "BorrowSanitizer: failed to intercept '%s@@%s'\n", #name,     \
              ver);                                                            \
  } while (0)

#define BSAN_INTERCEPT_FUNC_VER_UNVERSIONED_FALLBACK(name, ver)                \
  do {                                                                         \
    if (!INTERCEPT_FUNCTION_VER(name, ver) && !INTERCEPT_FUNCTION(name))       \
      VReport(1, "BorrowSanitizer: failed to intercept '%s@@%s' or '%s'\n",    \
              #name, ver, #name);                                              \
  } while (0)

#define COMMON_INTERCEPT_FUNCTION(name) BSAN_INTERCEPT_FUNC(name)

#define COMMON_INTERCEPT_FUNCTION_VER(name, ver)                               \
  BSAN_INTERCEPT_FUNC_VER(name, ver)

#define COMMON_INTERCEPT_FUNCTION_VER_UNVERSIONED_FALLBACK(name, ver)          \
  BSAN_INTERCEPT_FUNC_VER_UNVERSIONED_FALLBACK(name, ver)

#define COMMON_INTERCEPTOR_UNPOISON_PARAM(count)                               \
  do {                                                                         \
  } while (false)

#define COMMON_INTERCEPTOR_WRITE_RANGE(ctx, ptr, size)                         \
  do {                                                                         \
  } while (false)

#define COMMON_INTERCEPTOR_READ_RANGE(ctx, ptr, size)                          \
  do {                                                                         \
  } while (false)

#define COMMON_INTERCEPTOR_INITIALIZE_RANGE(ptr, size)                         \
  do {                                                                         \
  } while (false)

#define COMMON_INTERCEPTOR_ENTER(ctx, func, ...)                               \
  if (bsan_init_running)                                                       \
    return REAL(func)(__VA_ARGS__);                                            \
  ENSURE_BSAN_INITED();                                                        \
  LocalInterceptorContext bsan_ctx = {BlockInterception()};                    \
  ctx = (void *)&bsan_ctx;                                                     \
  (void)ctx;                                                                   \
  InterceptorBarrier barrier;

#define COMMON_INTERCEPTOR_DIR_ACQUIRE(ctx, path)                              \
  do {                                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_FD_ACQUIRE(ctx, fd)                                 \
  do {                                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_FD_RELEASE(ctx, fd)                                 \
  do {                                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_FD_SOCKET_ACCEPT(ctx, fd, newfd)                    \
  do {                                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_SET_THREAD_NAME(ctx, name)                          \
  do {                                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_SET_PTHREAD_NAME(ctx, thread, name)                 \
  do {                                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_BLOCK_REAL(name) REAL(name)
#define COMMON_INTERCEPTOR_ON_EXIT(ctx) OnExit()

#define COMMON_INTERCEPTOR_LIBRARY_LOADED(filename, handle)                    \
  do {                                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_NOTHING_IS_INITIALIZED (!bsan_inited)

#define COMMON_INTERCEPTOR_GET_TLS_RANGE(begin, end) *begin = *end = 0;

#define COMMON_INTERCEPTOR_MEMSET_IMPL(ctx, block, c, size)                    \
  {                                                                            \
    (void)ctx;                                                                 \
    __bsan_memset(block, c, size);                                             \
    return block;                                                              \
  }
#define COMMON_INTERCEPTOR_MEMMOVE_IMPL(ctx, to, from, size)                   \
  {                                                                            \
    (void)ctx;                                                                 \
    __bsan_memmove(to, from, size);                                            \
    return to;                                                                 \
  }
#define COMMON_INTERCEPTOR_MEMCPY_IMPL(ctx, to, from, size)                    \
  {                                                                            \
    (void)ctx;                                                                 \
    __bsan_memcpy(to, from, size);                                             \
    return to;                                                                 \
  }

#define COMMON_INTERCEPTOR_COPY_STRING(ctx, to, from, size)                    \
  do {                                                                         \
  } while (false)

#define COMMON_INTERCEPTOR_MMAP_IMPL(ctx, mmap, addr, length, prot, flags, fd, \
                                     offset)                                   \
  do {                                                                         \
    return REAL(mmap)(addr, length, prot, flags, fd, offset);                  \
  } while (false)

// clang-format off
#include "sanitizer_common/sanitizer_common_interceptors_memintrinsics.inc"
#include "sanitizer_common/sanitizer_common_interceptors.inc"
// clang-format on

#define SIGNAL_INTERCEPTOR_ENTER() ENSURE_BSAN_INITED()

#include "sanitizer_common/sanitizer_signal_interceptors.inc"

#define COMMON_SYSCALL_PRE_READ_RANGE(p, s)                                    \
  do {                                                                         \
  } while (false)
#define COMMON_SYSCALL_PRE_WRITE_RANGE(p, s)                                   \
  do {                                                                         \
  } while (false)
#define COMMON_SYSCALL_POST_READ_RANGE(p, s)                                   \
  do {                                                                         \
  } while (false)
#define COMMON_SYSCALL_POST_WRITE_RANGE(p, s)                                  \
  do {                                                                         \
  } while (false)

// clang-format off
#include "sanitizer_common/sanitizer_common_syscalls.inc"
#include "sanitizer_common/sanitizer_syscalls_netbsd.inc"
// clang-format on

namespace __bsan {

void InitializeInterceptors() {
  static int inited = 0;
  CHECK_EQ(inited, 0);
  __interception::DoesNotSupportStaticLinking();

  new (global_interceptor_ctx()) GlobalInterceptorContext();

  InitializeCommonInterceptors();
  InitializeSignalInterceptors();

  INTERCEPT_FUNCTION(pthread_create);
  INTERCEPT_FUNCTION(free);
  INTERCEPT_FUNCTION(malloc);
  INTERCEPT_FUNCTION(calloc);
  INTERCEPT_FUNCTION(realloc);
  INTERCEPT_FUNCTION(atexit);
  INTERCEPT_FUNCTION(__cxa_atexit);

  inited = 1;
}

} // namespace __bsan
