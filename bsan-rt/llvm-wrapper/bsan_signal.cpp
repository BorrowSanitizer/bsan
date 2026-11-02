#include "bsan_signal.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_errno.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_linux.h"
#include "sanitizer_common/sanitizer_mutex.h"
#include "sanitizer_common/sanitizer_posix.h"

namespace __sanitizer {
// Defined by the `sigaction` interceptor (sanitizer_signal_interceptors.inc).
int real_sigaction(int signum, const void *act, void *oldact);
} // namespace __sanitizer

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
    if (act.sa_flags & sa_siginfo)
      act.sigaction(signo, info, uc);
    else
      act.handler(signo);
  }
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

// Adds `signo` to `set`, using the same layout as `internal_sigdelset`.
static void SigAddSet(__sanitizer_sigset_t *set, int signo) {
  __sanitizer_kernel_sigset_t *k_set = (__sanitizer_kernel_sigset_t *)set;
  const uptr bits = sizeof(k_set->sig[0]) * 8;
  k_set->sig[(signo - 1) / bits] |= (uptr)1 << ((signo - 1) % bits);
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
