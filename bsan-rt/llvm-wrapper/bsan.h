#ifndef BSAN_H
#define BSAN_H
#include "bsan_shadow.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_stacktrace.h"

using __sanitizer::atomic_uintptr_t;
using __sanitizer::StackTrace;
using __sanitizer::u32;
using __sanitizer::u64;
using __sanitizer::u8;
using __sanitizer::uptr;

// Number of raw caller PCs captured per span. Must be deep enough to reach
// user code through nested stdlib wrappers
constexpr uptr kSpanMaxFrames = 4;

// Raw caller-PC chain captured at a retag/access site, innermost first.
// pcs[0] is the immediate caller of the runtime hook; deeper entries let
// display-time symbolization skip library code and report the user call
// site instead. Unused entries are 0.
struct Span {
  uptr pcs[kSpanMaxFrames];
};
typedef uptr BorTag;
typedef uptr ThreadId;

struct AllocInfo;
struct Provenance {
  BorTag Tag;
  AllocInfo *Info;
};

const Provenance OMNIVALID = {0, nullptr};

static constexpr uptr kMinProvAlignment = 8;

extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL Provenance
    *__bsan_shadow_stack;

extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL uptr __bsan_had_error;

// represents the number of provenance values that correspond to the variadic
// arguments being passed to the current function
extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL uptr __bsan_var_arg_ctr;

extern SANITIZER_INTERFACE_ATTRIBUTE atomic_uintptr_t __bsan_bor_tag_ctr;

namespace __bsan {

extern THREADLOCAL void *bsan_thread;
extern bool bsan_inited;
extern bool bsan_init_running;
extern bool bsan_deinit_running;
extern bool bsan_deinited;
extern atomic_uintptr_t thread_id;

extern THREADLOCAL int block_interception;

struct InterceptorBarrier {
  InterceptorBarrier() { ++block_interception; }
  ~InterceptorBarrier() { --block_interception; }
};

bool BlockInterception();

BorTag NewBorTag();

void InitializeGC();
void DeinitializeGC();

void InitializeTSD();
void InitializeInterceptors();

u32 GetStackTraceLen();
void PrintStackTrace(StackTrace &stack);

Provenance *GetSlot(uptr Idx);
void ClearSlot(uptr Idx);
bool CallerIsInstrumented(void *sym);

// Capture the raw caller-PC chain with one fast (frame-pointer) unwind.
// trace[0] is the hook itself, so store trace[1..] into the span. Falls back
// to GET_CALLER_PC() alone if the unwind produced nothing.
#define GET_SPAN                                                               \
  Span span = {};                                                              \
  {                                                                            \
    uptr __pc = StackTrace::GetCurrentPc();                                    \
    uptr __bp = GET_CURRENT_FRAME();                                           \
    UNINITIALIZED BufferedStackTrace __mini;                                   \
    __mini.Unwind(__pc, __bp, nullptr, true, kSpanMaxFrames + 1);              \
    for (uptr __i = 1; __i < __mini.size && __i <= kSpanMaxFrames; ++__i)      \
      span.pcs[__i - 1] = __mini.trace[__i];                                   \
    if (!span.pcs[0])                                                          \
      span.pcs[0] = GET_CALLER_PC();                                           \
  }

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
