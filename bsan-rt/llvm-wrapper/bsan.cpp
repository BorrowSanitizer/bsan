#include "bsan.h"
#include "bsan_thread.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_stacktrace.h"

using namespace __sanitizer;
using namespace __bsan;

bool bsan_inited = false;
bool bsan_init_is_running;
bool bsan_deinit_is_running;

extern "C" {
void __bsan_internal_init();
void __bsan_internal_deinit();
}

static void BsanInit() {
  AvoidCVE_2016_2143();
  __bsan_internal_init();
  __sanitizer::InitializePlatformEarly();
}

static void BsanDeinit() { __bsan_internal_deinit(); }

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_init() {
  CHECK(!bsan_init_is_running);
  if (bsan_inited)
    return;
  bsan_init_is_running = true;
  BsanInit();
  InitializeInterceptors();
  SetCommonFlagsDefaults();
  {
    CommonFlags cf;
    cf.CopyFrom(*common_flags());
    cf.external_symbolizer_path = GetEnv("BSAN_SYMBOLIZER_PATH");
    OverrideCommonFlags(cf);
  }

  BsanTSDInit();
  BsanThread *main_thread = BsanThread::Create(nullptr, nullptr);
  SetCurrentThread(main_thread);
  main_thread->Init();

  bsan_init_is_running = false;
  bsan_inited = true;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_deinit() {
  CHECK(!bsan_deinit_is_running);
  if (!bsan_inited)
    return;
  bsan_deinit_is_running = true;
  BsanDeinit();
  bsan_deinit_is_running = false;
  bsan_inited = false;
}

void __sanitizer::BufferedStackTrace::UnwindImpl(uptr pc, uptr bp,
                                                 void *context,
                                                 bool request_fast,
                                                 u32 max_depth) {
  BsanThread *t = GetCurrentThread();
  if (!t) {
    // The thread is still being created, or has already been destroyed.
    size = 0;
    return;
  }
  Unwind(max_depth, pc, bp, context, t->stack_top(), t->stack_bottom(),
         request_fast);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_printCurrentStackTrace() {
  // Capture current stack trace
  GET_CURRENT_PC_BP; // This macro defines 'pc' and 'bp' variables
  BufferedStackTrace stack;
  stack.Unwind(pc, bp, /*context=*/nullptr, /*request_fast=*/true,
               /*max_depth=*/kStackTraceMax);

  // Print error message
  // Report("%s\n", msg);

  // Print stack trace
  stack.Print();
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_printStackTrace(u32 stackId) {
  StackTrace stack = StackDepotGet(stackId);
  CHECK(stack.trace);
  stack.Print();
}

// Get the top frame PC address from the current PC
// Returns the previous instruction PC (adjusted for return addresses)
extern "C" SANITIZER_INTERFACE_ATTRIBUTE uptr __bsan_GetTopFramePC(uptr pc) {
  return StackTrace::GetPreviousInstructionPc(pc);
}

// FIXME: this function should only be used internally and does not need to be
// visible in the binary. But we need to make it availabel to bsan-rt-core
extern "C" SANITIZER_INTERFACE_ATTRIBUTE u32
__bsan_StackDepotPut(uptr pc, uptr bp, u32 max_depth) {
  BufferedStackTrace stack;
  stack.Unwind(pc, bp, /*context=*/nullptr, /*request_fast=*/true,
               /*max_depth=*/max_depth);
  return StackDepotPut(stack);
}