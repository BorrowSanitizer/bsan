#ifndef BSAN_H
#define BSAN_H
#include "bsan_allocator.h"
#include "bsan_shadow.h"
#include "sanitizer_common/sanitizer_addrhashmap.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_dense_map.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_mutex.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_procmaps.h"
#include "sanitizer_common/sanitizer_report_decorator.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_suppressions.h"
#include "sanitizer_common/sanitizer_thread_registry.h"
#include "sanitizer_common/sanitizer_tls_get_addr.h"
#include "sanitizer_common/sanitizer_vector.h"

using __sanitizer::AddrHashMap;
using __sanitizer::atomic_uintptr_t;
using __sanitizer::DenseMap;
using __sanitizer::Mutex;
using __sanitizer::StackTrace;
using __sanitizer::u32;
using __sanitizer::u64;
using __sanitizer::u8;
using __sanitizer::uptr;
using __sanitizer::Vector;

// The immediate caller PC of a runtime hook, captured at the retag/access
// site. Symbolized lazily at display time as the error's origin note; the
// primary error location comes from the live unwind in `HANDLE_ERROR`.
typedef uptr Span;
typedef uptr BorTag;

struct AllocInfo;

struct Provenance {
  BorTag tag;
  AllocInfo *info;
  bool isConcrete() { return tag > 2; }
};

struct AtExitRecord {
  void (*func)(void *arg);
  void *arg;
};

const Provenance OMNIVALID = {0, nullptr};

static constexpr uptr kParamTLSSizeProv = 100;
static constexpr uptr kVarArgTLSSizeBytes = 800;
static constexpr uptr kMinProvAlignment = 8;

extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL Provenance
    *__bsan_shadow_stack;

extern SANITIZER_INTERFACE_ATTRIBUTE atomic_uint32_t __bsan_gc_trigger;

extern SANITIZER_INTERFACE_ATTRIBUTE atomic_uintptr_t __bsan_bor_tag_ctr;

// Tree-node visits accumulated by the Rust runtime on this thread since the
// last GC.
extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL uptr __bsan_visits_since_gc;

namespace __bsan {

typedef uptr ThreadId;
enum GCState : u32 {
  // This thread is executing uninstrumented
  // code. The garbage collector can ignore it.
  // It will be paused at the boundary if it
  // reaches instrumented code again.
  kSafe = 0,
  // This thread is executing instrumented code
  // We need to wait until it reaches a safepoint
  // before we can pause its execution.
  kUnsafe = 1,
  // This thread is currently waiting for the GC
  // to finish.
  kWaiting = 2
};

// A flag that will block interceptors from being activated
// for operations occuring in this thread.
extern THREADLOCAL int block_interception;

// Creates a scope in which interception will be disabled.
struct InterceptorBarrier {
  InterceptorBarrier() { ++block_interception; }
  ~InterceptorBarrier() { --block_interception; }
};

// Should interceptors be blocked?
bool BlockInterception();

// Is the runtime initialized?
bool BsanInited();

// Initialize the runtime
void BsanInitFromRtl();

// Attempt to initialize the runtime.
bool TryBsanInitFromRtl();

// Wrappers for TLS / TSD
void InitializeTSD(void (*destructor)(void *tsd));
void *TSDGet();
void TSDSet(void *tsd);
void PlatformTSDDtor(void *tsd);

/// Creates a new borrow tag.
BorTag NewBorTag();

/// Marks a provenance value as potentially
/// viable for garbage collection.
void AcquireProvenance(Provenance prov);

/// Enables interception.
void InitializeInterceptors();

u32 GetStackTraceLen();
void PrintStackTrace(StackTrace &stack);
uptr FindUserFramePc(uptr pc, uptr bp);

Provenance *GetParamSlot(uptr Idx);
Provenance *GetRetValSlot(uptr Idx);
void ClearParamSlot(uptr Idx);
void ClearRetValSlot(uptr Idx);

bool CallerIsInstrumented(void *sym);

void InitMembarrier();
void Membarrier();

} // namespace __bsan

extern "C" {
// Formats and prints the pending UB error stored by handle_error, using
// user_frame_pc as the primary source location (0 = fall back to the original
// trigger span).
void __bsan_format_pending_ub(uptr user_frame_pc);
}

namespace __bsan {

// Capture the immediate caller PC of the runtime hook as the span.
#define GET_SPAN uptr span = GET_CALLER_PC();

#define GET_SPAN_PC_BP                                                         \
  GET_SPAN;                                                                    \
  GET_CURRENT_PC_BP;

#define HANDLE_ERROR(had_error)                                                \
  if (UNLIKELY(had_error)) {                                                   \
    uptr pc = StackTrace::GetCurrentPc();                                      \
    uptr bp = GET_CURRENT_FRAME();                                             \
    ScopedErrorReportLock::Lock();                                             \
    __bsan_format_pending_ub(__bsan::FindUserFramePc(pc, bp));                 \
    UNINITIALIZED BufferedStackTrace stack;                                    \
    stack.Unwind(pc, bp, nullptr, true, __bsan::GetStackTraceLen());           \
    PrintStackTrace(stack);                                                    \
    Die();                                                                     \
  }

#define HANDLE_ERROR_PC_BP(had_error, pc, bp)                                  \
  if (UNLIKELY(had_error)) {                                                   \
    ScopedErrorReportLock::Lock();                                             \
    __bsan_format_pending_ub(__bsan::FindUserFramePc(pc, bp));                 \
    UNINITIALIZED BufferedStackTrace stack;                                    \
    stack.Unwind(pc, bp, nullptr, true, __bsan::GetStackTraceLen());           \
    PrintStackTrace(stack);                                                    \
    Die();                                                                     \
  }

} // namespace __bsan
#endif // BSAN_H
