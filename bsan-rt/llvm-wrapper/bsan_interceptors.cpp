#define SANITIZER_COMMON_NO_REDEFINE_BUILTINS

#include "bsan_interceptors.h"
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

DECLARE_REAL_AND_INTERCEPTOR(void *, malloc, usize size)
DECLARE_REAL_AND_INTERCEPTOR(void, free, void *ptr)
DECLARE_REAL(void *, memcpy, void *dest, const void *src, SIZE_T n)
DECLARE_REAL(void *, memset, void *dest, int c, SIZE_T n)
DECLARE_REAL(void *, memmove, void *dest, const void *src, SIZE_T n)

extern "C" int pthread_attr_init(void *attr);
extern "C" int pthread_attr_destroy(void *attr);

struct DlsymAlloc : public DlSymAllocator<DlsymAlloc> {
  static bool UseImpl() { return !BsanInited(); }
};

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

#if SANITIZER_LINUX
  ScopedBlockSignals block(&t->starting_sigset_);
#endif

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
  Provenance prov = {tag, info};
  CurrentThread()->zct.acquireProvenance(prov);
  return prov;
}

static void *BsanAllocateMetaIntoStack(void *ptr, SIZE_T size, bool is_inst,
                                       uptr span, uptr slot_idx) {
  if (is_inst) {
    Provenance *slot = GetRetValSlot(slot_idx);
    Provenance prov = BsanAllocateMeta(ptr, size, span);
    *slot = prov;
  } else {
    ClearRetValSlot(slot_idx);
  }
  return ptr;
}

static void *BsanAllocateMetaIntoHeap(void *ptr, SIZE_T size, bool is_inst,
                                      uptr span, void *dest) {
  if (is_inst) {
    Provenance prov = BsanAllocateMeta(ptr, size, span);
    WriteShadow(dest, prov);
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

#if SANITIZER_LINUX
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
#endif

#if SANITIZER_LINUX
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
#endif

#if SANITIZER_LINUX
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
#endif

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
  if (!BsanInited()) {
    REAL(memset)(dest, c, n);
    return;
  }
  if (BlockInterception()) {
    REAL(memset)(dest, c, n);
    return;
  }
  REAL(memset)(dest, c, n);
  ClearShadow(dest, n);
}

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_memmove(void *dest, const void *src,
                                                  uptr n) {
  if (!BsanInited()) {
    REAL(memmove)(dest, src, n);
    return;
  }
  if (BlockInterception()) {
    REAL(memmove)(dest, src, n);
    return;
  }
  REAL(memmove)(dest, src, n);
  MoveShadow(dest, src, n);
}

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_memcpy(void *dest, const void *src,
                                                 uptr n) {
  if (!BsanInited()) {
    REAL(memcpy)(dest, src, n);
    return;
  }
  if (BlockInterception()) {
    REAL(memcpy)(dest, src, n);
    return;
  }
  REAL(memcpy)(dest, src, n);
  CopyShadow(dest, src, n);
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

  ClearParamSlot(0);
  ((void (*)())r->func)();
  InternalFree(r);
}

void BSanCxaAtExitWrapper(void *arg) {
  ClearParamSlot(0);
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
  if (!BsanInited())
    return REAL(__cxa_atexit)(func, arg, dso_handle);
  return setup_at_exit_wrapper((void (*)())func, arg, dso_handle);
}

// Unpoison argument shadow for C++ module destructors.
INTERCEPTOR(int, atexit, void (*func)()) {
  // Avoid calling real atexit as it is unreachable on at least on Linux.
  if (!BsanInited())
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
  do {                                                                         \
    if (!TryBsanInitFromRtl()) {                                               \
      return REAL(func)(__VA_ARGS__);                                          \
    }                                                                          \
  } while (false);                                                             \
  BSAN_INTERCEPTOR_ENTER(ctx, func);

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
#define COMMON_INTERCEPTOR_NOTHING_IS_INITIALIZED (!BsanInited())

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
  __interception::DoesNotSupportStaticLinking();

  InitializeCommonInterceptors();
  InitializeSignalInterceptors();

  BSAN_INTERCEPT_FUNC(pthread_create);
  BSAN_INTERCEPT_FUNC(pthread_join);
  BSAN_INTERCEPT_FUNC(free);
  BSAN_INTERCEPT_FUNC(malloc);
  BSAN_INTERCEPT_FUNC(calloc);
  BSAN_INTERCEPT_FUNC(realloc);
  BSAN_INTERCEPT_FUNC(aligned_alloc);
  BSAN_INTERCEPT_FUNC(memalign);
  BSAN_INTERCEPT_FUNC(__libc_memalign);
  BSAN_INTERCEPT_FUNC(valloc);
  BSAN_INTERCEPT_FUNC(pvalloc);
  BSAN_INTERCEPT_FUNC(posix_memalign);
  BSAN_INTERCEPT_FUNC(atexit);
  BSAN_INTERCEPT_FUNC(__cxa_atexit);
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
