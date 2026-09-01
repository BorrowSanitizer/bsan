#ifndef BSAN_INTERCEPTORS_H
#define BSAN_INTERCEPTORS_H

#define INST_CALLER(f) CallerIsInstrumented((void *)f)

#define ENSURE_BSAN_INITED()                                                   \
  do {                                                                         \
    BsanInitFromRtl();                                                         \
  } while (false)

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

#define BSAN_INTERCEPTOR_ENTER(ctx, func)                                      \
  LocalInterceptorContext bsan_ctx = {BlockInterception()};                    \
  ctx = (void *)&bsan_ctx;                                                     \
  (void)ctx;                                                                   \
  InterceptorBarrier barrier;

#endif // BSAN_INTERCEPTORS_H