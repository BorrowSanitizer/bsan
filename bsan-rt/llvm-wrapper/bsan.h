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

extern THREADLOCAL uptr __BSAN_HAD_ERROR;

typedef uptr Span;
typedef uptr BorTag;
typedef uptr ThreadId;

struct AllocInfo;
struct Provenance {
  BorTag Tag;
  AllocInfo *Info;
};

const Provenance WILDCARD = {0, nullptr};

extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL Provenance
    *__bsan_shadow_stack;

namespace __bsan {

extern THREADLOCAL void *bsan_thread;
extern bool bsan_inited;
extern bool bsan_init_running;
extern bool bsan_deinit_running;
extern atomic_uintptr_t thread_id;

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
  uptr pc = StackTrace::GetCurrentPc();                                        \
  uptr bp = GET_CURRENT_FRAME();

#define HANDLE_ERROR(pc, bp)                                                   \
  if (__BSAN_HAD_ERROR) {                                                      \
    UNINITIALIZED BufferedStackTrace stack;                                    \
    stack.Unwind(pc, bp, nullptr, true, __bsan::GetStackTraceLen());           \
    PrintStackTrace(stack);                                                    \
    Die();                                                                     \
  }

} // namespace __bsan
#endif // BSAN_H