#define SANITIZER_COMMON_NO_REDEFINE_BUILTINS

#include "bsan.h"
#include "bsan_global.h"
#include "bsan_interface_internal.h"
#include "bsan_shadow.h"
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
  int res = REAL(pthread_create)(th, attr, BsanThread::StartCallback, t);

  if (attr == &myattr) {
    pthread_attr_destroy(&myattr);
  }
  return res;
}

INTERCEPTOR(int, pthread_join, void *thread, void **retval) {
  return REAL(pthread_join)(thread, retval);
}

extern "C" void *__bsan_crt_malloc(SIZE_T size) {
  if (DlsymAlloc::Use())
    return DlsymAlloc::Allocate(size);
  return REAL(malloc)(size);
}

INTERCEPTOR(void *, malloc, SIZE_T size) {
  if (DlsymAlloc::Use())
    return DlsymAlloc::Allocate(size);
  GET_SPAN;
  bool already_in_scope = BlockInterception();
  InterceptorBarrier barrier;
  void *ptr = bsan_malloc(size);
  if (!already_in_scope && INST_CALLER(malloc)) {
    Provenance *RetSlot = GetRetValSlot(0);
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
  if (UNLIKELY(!ptr))
    return;
  if (DlsymAlloc::PointerIsMine(ptr))
    return DlsymAlloc::Free(ptr);
  GET_SPAN_PC_BP;
  bool already_in_scope = BlockInterception();
  InterceptorBarrier barrier;
  if (!already_in_scope && INST_CALLER(free)) {
    Provenance *slot = GetParamSlot(0);
    __bsan_dealloc(ptr, slot->tag, slot->info, span, false);
    HANDLE_ERROR_PC_BP(pc, bp);
  }
  return bsan_deallocate(ptr);
}

INTERCEPTOR(void *, calloc, SIZE_T nmemb, SIZE_T size) {
  if (DlsymAlloc::Use())
    return DlsymAlloc::Callocate(nmemb, size);
  GET_SPAN;
  bool already_in_scope = BlockInterception();
  InterceptorBarrier barrier;
  void *ptr = bsan_calloc(nmemb, size);
  if (!already_in_scope && INST_CALLER(calloc)) {
    Provenance *RetSlot = GetRetValSlot(0);
    BorTag Tag = NewBorTag();
    *RetSlot = {Tag, __bsan_alloc(ptr, nmemb * size, Tag, span)};
  }
  return ptr;
}

INTERCEPTOR(void *, realloc, void *ptr, SIZE_T size) {
  if (DlsymAlloc::Use() || DlsymAlloc::PointerIsMine(ptr))
    return DlsymAlloc::Realloc(ptr, size);
  GET_SPAN_PC_BP;
  bool already_in_scope = BlockInterception();
  InterceptorBarrier barrier;
  bool is_inst = !already_in_scope && INST_CALLER(realloc);
  if (is_inst) {
    Provenance *slot = GetParamSlot(0);
    __bsan_dealloc(ptr, slot->tag, slot->info, span, false);
    HANDLE_ERROR_PC_BP(pc, bp);
  }
  void *nptr = bsan_realloc(ptr, size);
  if (is_inst) {
    Provenance *RetSlot = GetRetValSlot(0);
    BorTag Tag = NewBorTag();
    *RetSlot = {Tag, __bsan_alloc(nptr, size, Tag, span)};
  }
  return nptr;
}

static Provenance BsanAllocateMeta(void *ptr, SIZE_T size, uptr span) {
  BorTag tag = NewBorTag();
  AllocInfo *info = __bsan_alloc(ptr, size, tag, span);
  return {tag, info};
}

static void *BsanAllocateMetaIntoStack(void *ptr, SIZE_T size, bool is_inst,
                                       uptr span, uptr slot_idx) {
  if (is_inst) {
    Provenance *slot = GetRetValSlot(slot_idx);
    Provenance prov = BsanAllocateMeta(ptr, size, span);
    *slot = BsanAllocateMeta(ptr, size, span);
    CurrentThread()->AcquireProvenance(prov);
  } else {
    ClearSlot(slot_idx);
  }
  return ptr;
}

static void *BsanAllocateMetaIntoHeap(void *ptr, SIZE_T size, bool is_inst,
                                      uptr span, void *dest) {
  if (is_inst) {
    WriteShadow(dest, BsanAllocateMeta(ptr, size, span));
  } else {
    ClearShadow(dest, sizeof(void *));
  }
  return ptr;
}

INTERCEPTOR(void *, aligned_alloc, SIZE_T alignment, SIZE_T size) {
  GET_SPAN;
  if (DlsymAlloc::Use())
    return DlsymAlloc::Allocate(size, alignment);
  bool already_in_scope = BlockInterception();
  InterceptorBarrier barrier;
  void *ptr = bsan_aligned_alloc(alignment, size);
  bool is_inst = !already_in_scope && INST_CALLER(aligned_alloc);
  return BsanAllocateMetaIntoStack(ptr, size, is_inst, span, 0);
}

INTERCEPTOR(void *, memalign, SIZE_T alignment, SIZE_T size) {
  GET_SPAN;
  if (DlsymAlloc::Use())
    return DlsymAlloc::Allocate(size, alignment);
  bool already_in_scope = BlockInterception();
  InterceptorBarrier barrier;
  void *ptr = bsan_memalign(alignment, size);
  bool is_inst = !already_in_scope && INST_CALLER(memalign);
  return BsanAllocateMetaIntoStack(ptr, size, is_inst, span, 0);
}

INTERCEPTOR(void *, __libc_memalign, SIZE_T alignment, SIZE_T size) {
  GET_SPAN;
  if (DlsymAlloc::Use())
    return DlsymAlloc::Allocate(size, alignment);
  bool already_in_scope = BlockInterception();
  InterceptorBarrier barrier;
  void *ptr = bsan_memalign(alignment, size);
  bool is_inst = !already_in_scope && INST_CALLER(__libc_memalign);
  return BsanAllocateMetaIntoStack(ptr, size, is_inst, span, 0);
}

INTERCEPTOR(void *, valloc, SIZE_T size) {
  GET_SPAN;
  if (DlsymAlloc::Use())
    return DlsymAlloc::Allocate(size, GetPageSizeCached());
  bool already_in_scope = BlockInterception();
  InterceptorBarrier barrier;
  void *ptr = bsan_valloc(size);
  bool is_inst = !already_in_scope && INST_CALLER(valloc);
  return BsanAllocateMetaIntoStack(ptr, size, is_inst, span, 0);
}

INTERCEPTOR(void *, pvalloc, SIZE_T size) {
  GET_SPAN;
  if (DlsymAlloc::Use())
    return DlsymAlloc::Allocate(RoundUpTo(size, GetPageSizeCached()),
                                GetPageSizeCached());
  bool already_in_scope = BlockInterception();
  InterceptorBarrier barrier;
  void *ptr = bsan_pvalloc(size);
  bool is_inst = !already_in_scope && INST_CALLER(pvalloc);
  return BsanAllocateMetaIntoStack(ptr, size, is_inst, span, 0);
}

INTERCEPTOR(int, posix_memalign, void **memptr, SIZE_T alignment, SIZE_T size) {
  GET_SPAN;
  if (DlsymAlloc::Use()) {
    void *ptr = DlsymAlloc::Allocate(size, alignment);
    if (UNLIKELY(!ptr))
      return errno_ENOMEM;
    *memptr = ptr;
    return 0;
  }
  bool already_in_scope = BlockInterception();
  InterceptorBarrier barrier;
  bool is_inst = !already_in_scope && INST_CALLER(posix_memalign);
  int res = bsan_posix_memalign(memptr, alignment, size);
  if (!res && is_inst) {
    BsanAllocateMetaIntoHeap(*memptr, size, is_inst, span, memptr);
  }
  return res;
}

extern "C" {

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_memset(void *dest, int c, uptr n) {
  if (!bsan_inited || bsan_init_running || BlockInterception()) {
    internal_memset(dest, c, n);
  } else {
    ENSURE_BSAN_INITED();
    internal_memset(dest, c, n);
    ClearShadow(dest, n);
  }
}

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_memmove(void *dest, const void *src,
                                                  uptr n) {
  if (!bsan_inited || bsan_init_running || BlockInterception()) {
    internal_memmove(dest, src, n);
  } else {
    ENSURE_BSAN_INITED();
    internal_memmove(dest, src, n);
    MoveShadow(dest, src, n);
  }
}

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_memcpy(void *dest, const void *src,
                                                 uptr n) {
  if (!bsan_inited || bsan_init_running || BlockInterception()) {
    internal_memcpy(dest, src, n);
  } else {
    ENSURE_BSAN_INITED();
    internal_memcpy(dest, src, n);
    CopyShadow(dest, src, n);
  }
}

} // extern "C"

void BSanAtExitWrapper() {
  AtExitRecord *r;
  {
    Lock l(&global_ctx()->AtExitMutex());

    Vector<AtExitRecord *> &stack = global_ctx()->AtExitStack();
    uptr element = stack.Size() - 1;
    r = stack[element];
    stack.PopBack();
  }

  ClearSlot(0);
  ((void (*)())r->func)();
  InternalFree(r);
}

void BSanCxaAtExitWrapper(void *arg) {
  ClearSlot(0);
  AtExitRecord *r = (AtExitRecord *)arg;
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
  auto *r = (AtExitRecord *)InternalAlloc(sizeof(AtExitRecord));
  r->func = (void (*)(void *a))f;
  r->arg = arg;
  int res;
  if (!dso) {
    // NetBSD does not preserve the 2nd argument if dso is equal to 0
    // Store ctx in a local stack-like structure

    Lock l(&global_ctx()->AtExitMutex());

    res = REAL(__cxa_atexit)((void (*)(void *a))BSanAtExitWrapper, 0, 0);
    if (!res) {
      global_ctx()->AtExitStack().PushBack(r);
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
  __bsan_shadow_clear(ptr, size)

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
#define COMMON_SYSCALL_POST_WRITE_RANGE(p, s) __bsan_shadow_clear(p, s)

// clang-format off
#include "sanitizer_common/sanitizer_common_syscalls.inc"
#include "sanitizer_common/sanitizer_syscalls_netbsd.inc"
// clang-format on

namespace __bsan {

void InitializeInterceptors() {
  static int inited = 0;
  CHECK_EQ(inited, 0);
  __interception::DoesNotSupportStaticLinking();

  InitializeCommonInterceptors();
  InitializeSignalInterceptors();

  INTERCEPT_FUNCTION(pthread_create);
  INTERCEPT_FUNCTION(pthread_join);
  INTERCEPT_FUNCTION(free);
  INTERCEPT_FUNCTION(malloc);
  INTERCEPT_FUNCTION(calloc);
  INTERCEPT_FUNCTION(realloc);
  INTERCEPT_FUNCTION(aligned_alloc);
  INTERCEPT_FUNCTION(memalign);
  INTERCEPT_FUNCTION(__libc_memalign);
  INTERCEPT_FUNCTION(valloc);
  INTERCEPT_FUNCTION(pvalloc);
  INTERCEPT_FUNCTION(posix_memalign);
  INTERCEPT_FUNCTION(atexit);
  INTERCEPT_FUNCTION(__cxa_atexit);

  inited = 1;
}

} // namespace __bsan

// DEFINE_INTERNAL_PTHREAD_FUNCTIONS.
namespace __sanitizer {
int internal_pthread_create(void *th, void *attr, void *(*callback)(void *),
                            void *param) {
  InterceptorBarrier barrier;
  return REAL(pthread_create)(th, attr, callback, param);
}
int internal_pthread_join(void *th, void **ret) {
  InterceptorBarrier barrier;
  return REAL(pthread_join)(th, ret);
}
} // namespace __sanitizer
