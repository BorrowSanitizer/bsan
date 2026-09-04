#ifndef BSAN_H
#define BSAN_H
#include "bsan_allocator.h"
#include "bsan_dense_slab.h"
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

struct Provenance {
  BorTag tag;
  Block *info;
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

extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL uptr __bsan_had_error;

extern SANITIZER_INTERFACE_ATTRIBUTE atomic_uintptr_t __bsan_bor_tag_ctr;

// Tree-node visits accumulated by the Rust runtime since the last GC request.
extern SANITIZER_INTERFACE_ATTRIBUTE atomic_uintptr_t __bsan_visits_since_gc;

namespace __bsan {

typedef DenseSlabAlloc<kMetadataSpace> BlockAllocator;
extern BlockAllocator block_allocator;

#define BLOCK_IDX(ptr) (block_allocator.IndexOf(ptr))
#define BLOCK_PTR(idx) (block_allocator.Map(idx))

typedef uptr ThreadId;

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

#define HANDLE_ERROR                                                           \
  if (UNLIKELY(__bsan_had_error)) {                                            \
    uptr pc = StackTrace::GetCurrentPc();                                      \
    uptr bp = GET_CURRENT_FRAME();                                             \
    __bsan_format_pending_ub(__bsan::FindUserFramePc(pc, bp));                 \
    UNINITIALIZED BufferedStackTrace stack;                                    \
    stack.Unwind(pc, bp, nullptr, true, __bsan::GetStackTraceLen());           \
    PrintStackTrace(stack);                                                    \
    Die();                                                                     \
  }

#define HANDLE_ERROR_PC_BP(pc, bp)                                             \
  if (UNLIKELY(__bsan_had_error)) {                                            \
    __bsan_format_pending_ub(__bsan::FindUserFramePc(pc, bp));                 \
    UNINITIALIZED BufferedStackTrace stack;                                    \
    stack.Unwind(pc, bp, nullptr, true, __bsan::GetStackTraceLen());           \
    PrintStackTrace(stack);                                                    \
    Die();                                                                     \
  }

} // namespace __bsan
#endif // BSAN_H
