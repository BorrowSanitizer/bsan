#include "bsan_signal.h"
#include "bsan_thread.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_errno.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_linux.h"
#include "sanitizer_common/sanitizer_mutex.h"
#include "sanitizer_common/sanitizer_posix.h"

#include <signal.h>
#include <ucontext.h>

namespace __sanitizer {
// Defined by the `sigaction` interceptor (sanitizer_signal_interceptors.inc).
int real_sigaction(int signum, const void *act, void *oldact);
} // namespace __sanitizer

// Per-thread state that instrumented code uses to pass the provenance of a
// call's arguments from caller to callee. Defined in bsan.cpp. Saved and
// restored around signal handlers by `ScopedProvenanceStateBackup`.
extern THREADLOCAL void *__bsan_marker;
extern THREADLOCAL uptr __bsan_var_arg_overflow;
extern THREADLOCAL u8 __bsan_var_arg_tag_tls[kTLSSizeBytes];
extern THREADLOCAL u8 __bsan_var_arg_info_tls[kTLSSizeBytes];
extern THREADLOCAL u8 __bsan_param_tag_tls[kTLSSizeBytes];
extern THREADLOCAL u8 __bsan_param_info_tls[kTLSSizeBytes];

namespace __bsan {

// There are 64 available signals in Linux
static constexpr int kMaxSignals = 65;
static constexpr int kSigSetMask = 2;              // SIG_SETMASK
static constexpr unsigned kSaRestart = 0x10000000; // SA_RESTART

// The action that the program most recently installed for each signal.
// Writers hold `actions_mu`. The trampoline reads an action without a lock,
// since it can interrupt a writer.
//
// Each action is guarded by a sequence lock: `seq` is odd while the action is
// being written, and otherwise even.
struct UserAction {
  atomic_uint32_t seq;
  __sanitizer_sigaction act;
};
static UserAction user_actions[kMaxSignals];
static StaticSpinMutex actions_mu;

static void LoadUserAction(int signo, __sanitizer_sigaction *out) {
  UserAction &ua = user_actions[signo];
  while (true) {
    u32 seq = atomic_load(&ua.seq, memory_order_acquire);
    if (seq & 1) {
      proc_yield(1);
      continue;
    }
    internal_memcpy(out, &ua.act, sizeof(*out));
    atomic_thread_fence(memory_order_acquire);
    if (atomic_load(&ua.seq, memory_order_relaxed) == seq)
      return;
  }
}

// Requires `actions_mu`, with every signal blocked on this thread. Otherwise,
// the trampoline could interrupt the write and spin forever on an odd `seq`.
static void StoreUserAction(int signo, const __sanitizer_sigaction *act) {
  UserAction &ua = user_actions[signo];
  u32 seq = atomic_load(&ua.seq, memory_order_relaxed);
  atomic_store(&ua.seq, seq + 1, memory_order_relaxed);
  atomic_thread_fence(memory_order_release);
  internal_memcpy(&ua.act, act, sizeof(*act));
  atomic_store(&ua.seq, seq + 2, memory_order_release);
}

THREADLOCAL atomic_uint32_t bsan_runtime_depth;
THREADLOCAL atomic_uint32_t bsan_signals_pending;

// A signal that arrived while its thread was inside the runtime. We keep a
// copy of the action that was installed when it arrived, so that it is
// delivered as it would have been without the delay, even if the program
// changes the action in the meantime, or the kernel resets it because of
// `SA_RESETHAND`.
struct PendingSignal {
  bool armed;
  __sanitizer_sigaction act;
  siginfo_t info;
  ucontext_t uc;
};

// Like the kernel, we keep at most one pending instance of each signal.
struct SignalContext {
  PendingSignal signals[kMaxSignals];
};

// Allocated the first time that one of this thread's signals is deferred.
static THREADLOCAL SignalContext *signal_ctx;

void FreeSignalContext() {
  if (signal_ctx) {
    UnmapOrDie(signal_ctx, sizeof(SignalContext));
    signal_ctx = nullptr;
  }
}

static bool IsSyncSignal(int signo, const siginfo_t *info) {
  if (info->si_code == SI_TIMER)
    return false;
  return signo == SIGSEGV || signo == SIGBUS || signo == SIGILL ||
         signo == SIGTRAP || signo == SIGABRT || signo == SIGFPE ||
         signo == SIGPIPE || signo == SIGSYS;
}

// Pushes the provenance in the given argument arrays onto the shadow stack,
// below `*cursor`, so that the GC treats it as a root.
static void PushArgumentRoots(Provenance **cursor, Provenance *limit,
                              const u8 *tags, const u8 *blocks) {
  const BorTag *arg_tags = reinterpret_cast<const BorTag *>(tags);
  Block *const *arg_blocks = reinterpret_cast<Block *const *>(blocks);
  for (uptr i = 0; i < kTLSSizeBytes / kMinProvAlignment; i++) {
    BorTag tag = STRIP_TAG_OFFSET(arg_tags[i]);
    if (!CONCRETE(tag) || !arg_blocks[i] || *cursor <= limit)
      continue;
    *--*cursor = {tag, arg_blocks[i]};
  }
}

// Saves the per-thread state that instrumented code uses to pass provenance
// between functions, and restores it when the scope exits. A handler can
// interrupt instrumented code after it has stored the provenance of a call's
// arguments, but before the callee has read them. The handler's own
// instrumented functions overwrite this state, starting with its entry point,
// which clears the parameter arrays since it is called from uninstrumented
// code. MSan does the same for its own per-thread state.
//
// The GC does not scan these arrays, and the saved copy is out of its sight,
// so we also push the saved provenance onto the shadow stack. The handler's
// frames are allocated below it, and it is popped when the shadow stack
// pointer is restored.
// Some of it may be stale, which only means that the GC keeps it alive until
// the handler returns.
struct ScopedProvenanceStateBackup {
  void *marker;
  uptr var_arg_overflow;
  Provenance *shadow_stack;
  alignas(kMinProvAlignment) u8 var_arg_tag[kTLSSizeBytes];
  alignas(kMinProvAlignment) u8 var_arg_info[kTLSSizeBytes];
  alignas(kMinProvAlignment) u8 param_tag[kTLSSizeBytes];
  alignas(kMinProvAlignment) u8 param_info[kTLSSizeBytes];

  ScopedProvenanceStateBackup() {
    marker = __bsan_marker;
    var_arg_overflow = __bsan_var_arg_overflow;
    shadow_stack = __bsan_shadow_stack;
    internal_memcpy(var_arg_tag, __bsan_var_arg_tag_tls, kTLSSizeBytes);
    internal_memcpy(var_arg_info, __bsan_var_arg_info_tls, kTLSSizeBytes);
    internal_memcpy(param_tag, __bsan_param_tag_tls, kTLSSizeBytes);
    internal_memcpy(param_info, __bsan_param_info_tls, kTLSSizeBytes);
    BsanThread *thread = CurrentThread();
    Provenance *limit = thread ? thread->shadowRootsLimit() : nullptr;
    if (thread && shadow_stack > limit) {
      // Leave at least half of the remaining shadow stack to the handler.
      Provenance *cursor = shadow_stack;
      Provenance *push_limit = limit + (shadow_stack - limit) / 2;
      PushArgumentRoots(&cursor, push_limit, param_tag, param_info);
      PushArgumentRoots(&cursor, push_limit, var_arg_tag, var_arg_info);
      // The roots must be in place before the GC can see the new cursor.
      atomic_signal_fence(memory_order_seq_cst);
      __bsan_shadow_stack = cursor;
    }
  }
  ~ScopedProvenanceStateBackup() {
    __bsan_marker = marker;
    __bsan_var_arg_overflow = var_arg_overflow;
    __bsan_shadow_stack = shadow_stack;
    internal_memcpy(__bsan_var_arg_tag_tls, var_arg_tag, kTLSSizeBytes);
    internal_memcpy(__bsan_var_arg_info_tls, var_arg_info, kTLSSizeBytes);
    internal_memcpy(__bsan_param_tag_tls, param_tag, kTLSSizeBytes);
    internal_memcpy(__bsan_param_info_tls, param_info, kTLSSizeBytes);
  }
};

static void CallUserHandler(int signo, const __sanitizer_sigaction &act,
                            void *info, void *uc) {
  ScopedProvenanceStateBackup backup;
  if (act.sa_flags & sa_siginfo)
    act.sigaction(signo, (__sanitizer_siginfo *)info, uc);
  else
    act.handler(signo);
}

// Copies `src` into `dst`. On x86-64, the floating-point state is stored
// outside of `ucontext_t`, within the kernel's signal frame, which no longer
// exists when a deferred signal is delivered. We copy its legacy part into
// the copy's own storage. The extended state (e.g. AVX) is not copied.
static void CopyUcontext(ucontext_t *dst, const ucontext_t *src) {
  internal_memcpy(dst, src, sizeof(*dst));
#if defined(__x86_64__)
  if (src->uc_mcontext.fpregs) {
    internal_memcpy(&dst->__fpregs_mem, src->uc_mcontext.fpregs,
                    sizeof(dst->__fpregs_mem));
    dst->uc_mcontext.fpregs = &dst->__fpregs_mem;
  }
#endif
}

// Returns the stack pointer of the code that the signal interrupted.
static uptr InterruptedStackPointer(const ucontext_t *uc) {
#if defined(__aarch64__)
  return uc->uc_mcontext.sp;
#elif defined(__x86_64__)
  return uc->uc_mcontext.gregs[REG_RSP];
#else
#error "Unsupported architecture"
#endif
}

// Called by the trampoline when this thread is inside the runtime.
static void DeferSignal(int signo, const __sanitizer_sigaction &act,
                        const siginfo_t *info, const ucontext_t *uc) {
  if (!signal_ctx) {
    // Another signal can interrupt us here, defer itself, and allocate the
    // context first. It finishes before we continue, so we keep its context.
    SignalContext *ctx =
        (SignalContext *)MmapOrDie(sizeof(SignalContext), "SignalContext");
    if (signal_ctx)
      UnmapOrDie(ctx, sizeof(SignalContext));
    else
      signal_ctx = ctx;
  }
  PendingSignal &pending = signal_ctx->signals[signo];
  if (pending.armed)
    return;
  // Arm the slot before filling it in. If the same signal interrupts us here
  // (with `SA_NODEFER`), it is dropped instead of overwriting the slot.
  pending.armed = true;
  atomic_signal_fence(memory_order_seq_cst);
  pending.act = act;
  internal_memcpy(&pending.info, info, sizeof(pending.info));
  CopyUcontext(&pending.uc, uc);
  atomic_signal_fence(memory_order_seq_cst);
  atomic_store(&bsan_signals_pending, 1, memory_order_relaxed);
}

// Installed in place of every handler that the user program installs.
static void SignalTrampoline(int signo, __sanitizer_siginfo *info, void *uc) {
  int saved_errno = errno;
  __sanitizer_sigaction act;
  LoadUserAction(signo, &act);
  // The program can replace its handler with `SIG_DFL` or `SIG_IGN` before
  // we load the user action in the previous line. There is no handler to
  // call in this case, so we drop the signal.
  uptr cb = (uptr)act.handler;
  if (cb != sig_dfl && cb != sig_ign) {
    const siginfo_t *si = (const siginfo_t *)info;
    // We can only defer a signal for a thread that has been registered,
    // since its pending-signal storage is freed when it is unregistered.
    bool defer = atomic_load(&bsan_runtime_depth, memory_order_relaxed) &&
                 !IsSyncSignal(signo, si) && CurrentThread();
    if (defer) {
      DeferSignal(signo, act, si, (const ucontext_t *)uc);
    } else {
      // A thread only waits for the GC within `BsanThread::poll`, which
      // defers asynchronous signals. If a handler ran here, it would move
      // the thread out of waiting while the GC is running.
      if (BsanThread *thread = CurrentThread()) {
        CHECK(IsSyncSignal(signo, si) ||
              thread->getGCState(memory_order_relaxed) != GCState::kWaiting);
        // On an alternate signal stack, the handler cannot publish a stack
        // pointer that bounds the frames that it interrupted, so we publish
        // theirs. Otherwise, a GC during the handler would miss them.
        if (!thread->ownsAddress((uptr)__builtin_frame_address(0)))
          thread->publishStackPointer(
              InterruptedStackPointer((const ucontext_t *)uc),
              memory_order_relaxed);
      }
      CallUserHandler(signo, act, info, uc);
    }
  }
  errno = saved_errno;
}

// Returns the lowest pending signal that `mask` does not block, or 0.
static int NextPendingSignal(__sanitizer_sigset_t *mask) {
  for (int signo = 1; signo < kMaxSignals; signo++)
    if (signal_ctx->signals[signo].armed && !internal_sigismember(mask, signo))
      return signo;
  return 0;
}

static bool AnySignalArmed() {
  for (int signo = 1; signo < kMaxSignals; signo++)
    if (signal_ctx->signals[signo].armed)
      return true;
  return false;
}

static void SigOrSet(__sanitizer_sigset_t *dst, const __sanitizer_sigset_t *a,
                     const __sanitizer_sigset_t *b) {
  for (uptr i = 0; i < ARRAY_SIZE(dst->val); i++)
    dst->val[i] = a->val[i] | b->val[i];
}

// Adds `signo` to `set`, using the same layout as `internal_sigdelset`.
static void SigAddSet(__sanitizer_sigset_t *set, int signo) {
  __sanitizer_kernel_sigset_t *k_set = (__sanitizer_kernel_sigset_t *)set;
  const uptr bits = sizeof(k_set->sig[0]) * 8;
  k_set->sig[(signo - 1) / bits] |= (uptr)1 << ((signo - 1) % bits);
}

// Delivers pending signals the way the kernel would have: each handler runs
// with the thread's mask plus the handler's `sa_mask`, and its own signal
// unless `SA_NODEFER` was set. A signal that the thread's current mask
// blocks stays pending. This happens when another pending signal's handler
// is running further up the stack, and it is delivered once that handler
// returns.
//
// The handler receives a copy of the `siginfo` and `ucontext` that the
// kernel passed to the trampoline. The `ucontext` describes the interrupted
// runtime code, not the program's code, and changes to it have no effect.
void ProcessPendingSignals() {
  if (!signal_ctx) {
    atomic_store(&bsan_signals_pending, 0, memory_order_relaxed);
    return;
  }
  int saved_errno = errno;
  // Block every signal while we read and update the pending set. Signals
  // are only unblocked while a handler runs.
  __sanitizer_sigset_t all, mask;
  internal_sigfillset(&all);
  internal_sigprocmask(kSigSetMask, &all, &mask);
  while (int signo = NextPendingSignal(&mask)) {
    PendingSignal &slot = signal_ctx->signals[signo];
    // Copy the signal out of its slot, so the slot can hold a new instance
    // of the signal while the handler runs.
    __sanitizer_sigaction act = slot.act;
    siginfo_t info;
    ucontext_t uc;
    internal_memcpy(&info, &slot.info, sizeof(info));
    internal_memcpy(&uc, &slot.uc, sizeof(uc));
#if defined(__x86_64__)
    if (slot.uc.uc_mcontext.fpregs)
      uc.uc_mcontext.fpregs = &uc.__fpregs_mem;
#endif
    slot.armed = false;

    __sanitizer_sigset_t handler_mask;
    SigOrSet(&handler_mask, &mask, &act.sa_mask);
    if (!(act.sa_flags & SA_NODEFER))
      SigAddSet(&handler_mask, signo);
    internal_sigprocmask(kSigSetMask, &handler_mask, nullptr);
    CallUserHandler(signo, act, &info, &uc);
    internal_sigprocmask(kSigSetMask, &all, nullptr);
  }
  // Signals that are still blocked stay pending, and we try again when the
  // runtime is next exited. If a handler exited with `longjmp`, the flag is
  // still set, so the signals after it are delivered then too.
  if (!AnySignalArmed())
    atomic_store(&bsan_signals_pending, 0, memory_order_relaxed);
  internal_sigprocmask(kSigSetMask, &mask, nullptr);
  errno = saved_errno;
}

int SigactionImpl(int signo, const __sanitizer_sigaction *act,
                  __sanitizer_sigaction *oldact) {
  if (signo <= 0 || signo >= kMaxSignals)
    return real_sigaction(signo, act, oldact);

  __sanitizer_sigset_t all, saved_mask;
  // Temporarily block other incoming signals
  internal_sigfillset(&all);
  internal_sigprocmask(kSigSetMask, &all, &saved_mask);
  int res;
  {
    SpinMutexLock lock(&actions_mu);
    __sanitizer_sigaction prev = user_actions[signo].act;
    __sanitizer_sigaction new_act;
    if (act) {
      // Record the program's action before installing the trampoline, so the
      // trampoline never runs without it.
      StoreUserAction(signo, act);
      new_act = *act;
      uptr cb = (uptr)act->handler;
      if (cb != sig_dfl && cb != sig_ign) {
        new_act.sigaction = SignalTrampoline;
        new_act.sa_flags |= sa_siginfo;
      }
    }
    res = real_sigaction(signo, act ? &new_act : nullptr, oldact);
    if (res != 0 && act) {
      StoreUserAction(signo, &prev);
    }
    // If the previous action was our trampoline, then report the program's
    // handler instead. Everything else in `oldact` is what the program
    // installed, except for `SA_SIGINFO`, which the trampoline always sets.
    if (res == 0 && oldact &&
        (uptr)oldact->sigaction == (uptr)SignalTrampoline) {
      oldact->sigaction = prev.sigaction;
      oldact->sa_flags =
          (oldact->sa_flags & ~sa_siginfo) | (prev.sa_flags & sa_siginfo);
    }
  }
  internal_sigprocmask(kSigSetMask, &saved_mask, nullptr);
  return res;
}

uptr SignalImpl(int signo, uptr handler) {
  if (signo <= 0 || signo >= kMaxSignals) {
    errno = errno_EINVAL;
    return sig_err;
  }
  // Like glibc's `signal`, which has BSD semantics: the signal is blocked
  // while its handler runs, and interrupted system calls are restarted.
  __sanitizer_sigaction act, old;
  internal_memset(&act, 0, sizeof(act));
  act.handler = (__sanitizer_sighandler_ptr)handler;
  internal_sigemptyset(&act.sa_mask);
  SigAddSet(&act.sa_mask, signo);
  act.sa_flags = kSaRestart;
  if (SigactionImpl(signo, &act, &old) != 0)
    return sig_err;
  return (uptr)old.handler;
}

} // namespace __bsan
