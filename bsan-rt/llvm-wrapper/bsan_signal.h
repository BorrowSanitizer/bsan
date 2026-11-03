#ifndef BSAN_SIGNAL_H
#define BSAN_SIGNAL_H

#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_platform_limits_posix.h"

using namespace __sanitizer;

namespace __bsan {

// Implement the `sigaction` and `signal` interceptors. Instead of installing
// the program's handler, we record it and install a trampoline that calls it,
// so that the runtime controls when the program's handler runs. The program
// still sees its own handler through `oldact` and the return value of
// `signal`, never the trampoline.
int SigactionImpl(int signo, const __sanitizer_sigaction *act,
                  __sanitizer_sigaction *oldact);
uptr SignalImpl(int signo, uptr handler);

// The program's handler for an asynchronous signal must not run while its
// thread is inside the runtime, since the runtime is not reentrant. Such a
// signal is recorded as pending and delivered when the **outermost**
// `RuntimeScope` exits.
//
// Since both variables are only accessed by their own thread and signal
// handlers, relaxed atomics with signal fences are sufficient.
extern THREADLOCAL atomic_uint32_t bsan_runtime_depth;
extern THREADLOCAL atomic_uint32_t bsan_signals_pending;

// Delivers this thread's pending signals. Called when the outermost
// `RuntimeScope` exits.
void ProcessPendingSignals();

// Releases this thread's pending-signal storage when the thread exits.
void FreeSignalContext();

// Marks a scope in which this thread is inside the runtime. Every runtime
// entry point that touches shared or per-thread runtime state begins with one.
//
// It must not be held during a call that may block, since a blocking call may
// rely on the signal handler running, and since the handler waits for the scope
// to exit, the program will hang. Waiting for the GC is the exception: the GC
// finishes once every other thread is stopped or in uninstrumented code, and
// no thread needs one of our handlers to run to get there, since a thread
// that waits for one either blocks in uninstrumented code or loops through a
// safepoint.
struct RuntimeScope {
  RuntimeScope() {
    u32 depth = atomic_load(&bsan_runtime_depth, memory_order_relaxed);
    atomic_store(&bsan_runtime_depth, depth + 1, memory_order_relaxed);
    atomic_signal_fence(memory_order_seq_cst);
  }
  ~RuntimeScope() {
    atomic_signal_fence(memory_order_seq_cst);
    // Leave the runtime before delivering, so that a handler which exits with
    // `longjmp` does not leave the depth raised.
    u32 depth = atomic_load(&bsan_runtime_depth, memory_order_relaxed) - 1;
    atomic_store(&bsan_runtime_depth, depth, memory_order_relaxed);
    atomic_signal_fence(memory_order_seq_cst);
    if (depth == 0 &&
        UNLIKELY(atomic_load(&bsan_signals_pending, memory_order_relaxed)))
      ProcessPendingSignals();
  }
};

} // namespace __bsan

#endif // BSAN_SIGNAL_H
