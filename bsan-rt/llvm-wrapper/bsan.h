#ifndef BSAN_H
#define BSAN_H
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_stacktrace.h"

using __sanitizer::atomic_uintptr_t;
using __sanitizer::StackTrace;
using __sanitizer::u32;
using __sanitizer::u64;
using __sanitizer::u8;
using __sanitizer::uptr;

typedef uptr Span;
typedef uptr BorTag;
typedef uptr ThreadId;

struct AllocInfo;
struct Provenance {
  BorTag Tag;
  AllocInfo *Info;
};

const Provenance OMNIVALID = {0, nullptr};

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