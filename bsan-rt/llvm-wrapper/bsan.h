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

typedef uptr Span;
typedef uptr BorTag;

struct AllocInfo;

struct Provenance {
  BorTag tag;
  AllocInfo *info;
};

struct AtExitRecord {
  void (*func)(void *arg);
  void *arg;
};

const Provenance OMNIVALID = {0, nullptr};

static constexpr uptr kMinProvAlignment = 8;

extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL Provenance
    *__bsan_shadow_stack;

extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL uptr __bsan_had_error;

extern SANITIZER_INTERFACE_ATTRIBUTE atomic_uintptr_t __bsan_bor_tag_ctr;

// Tree-node visits accumulated by the Rust runtime since the last GC request.
extern SANITIZER_INTERFACE_ATTRIBUTE atomic_uintptr_t __bsan_visits_since_gc;

namespace __bsan {

typedef uptr ThreadId;

// A pointer to the state object for the current thread.
extern THREADLOCAL void *bsan_thread;

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
extern bool bsan_inited;

// Is the initializer for the runtime executing?
extern bool bsan_init_running;

/// Creates a new borrow tag.
BorTag NewBorTag();

/// Initializes the destructor
/// for per-thread state.
void InitializeTSD();

/// Enables interception.
void InitializeInterceptors();

u32 GetStackTraceLen();
void PrintStackTrace(StackTrace &stack);

Provenance *GetParamSlot(uptr Idx);
Provenance *GetRetValSlot(uptr Idx);
void ClearSlot(uptr Idx);
bool CallerIsInstrumented(void *sym);

#define GET_SPAN uptr span = GET_CALLER_PC();

#define GET_SPAN_PC_BP                                                         \
  GET_SPAN;                                                                    \
  GET_CURRENT_PC_BP;

#define HANDLE_ERROR                                                           \
  if (UNLIKELY(__bsan_had_error)) {                                            \
    uptr pc = StackTrace::GetCurrentPc();                                      \
    uptr bp = GET_CURRENT_FRAME();                                             \
    UNINITIALIZED BufferedStackTrace stack;                                    \
    stack.Unwind(pc, bp, nullptr, true, __bsan::GetStackTraceLen());           \
    PrintStackTrace(stack);                                                    \
    Die();                                                                     \
  }

#define HANDLE_ERROR_PC_BP(pc, bp)                                             \
  if (UNLIKELY(__bsan_had_error)) {                                            \
    UNINITIALIZED BufferedStackTrace stack;                                    \
    stack.Unwind(pc, bp, nullptr, true, __bsan::GetStackTraceLen());           \
    PrintStackTrace(stack);                                                    \
    Die();                                                                     \
  }

} // namespace __bsan
#endif // BSAN_H
