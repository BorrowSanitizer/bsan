#include "bsan.h"
#include "bsan_thread.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_symbolizer.h"

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
    const char *symbolizer_path = GetEnv("BSAN_SYMBOLIZER");
    if (symbolizer_path) {
      CommonFlags cf;
      cf.CopyFrom(*common_flags());
      cf.external_symbolizer_path = symbolizer_path;
      OverrideCommonFlags(cf);
    }
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

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_print_current_stack_trace() {
  // Capture current stack trace
  GET_CURRENT_PC_BP; // This macro defines 'pc' and 'bp' variables
  BufferedStackTrace stack;
  stack.Unwind(pc, bp, /*context=*/nullptr, /*request_fast=*/true,
               /*max_depth=*/kStackTraceMax);
  stack.Print();
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_print_stack_trace(u32 stackId) {
  StackTrace stack = StackDepotGet(stackId);
  CHECK(stack.trace);
  stack.Print();
}

// Get the top frame PC address from the current PC
// Returns the previous instruction PC (adjusted for return addresses)
extern "C" SANITIZER_INTERFACE_ATTRIBUTE uptr __bsan_get_top_frame_pc(uptr pc) {
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

// Symbolize a single PC into file:line:column, writing the file path into
// the provided buffer. Returns 1 on success, 0 otherwise.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE u32 __bsan_symbolize_pc(
    uptr pc, char *file_buf, uptr file_buf_len, u32 *line, u32 *column) {
  __sanitizer::Symbolizer *sym = __sanitizer::Symbolizer::GetOrInit();
  if (!sym) {
    return 0;
  }
  __sanitizer::SymbolizedStack *res = sym->SymbolizePC(pc);
  if (!res) {
    return 0;
  }
  const char *fname = res->info.file;
  if (!fname) {
    res->ClearAll();
    return 0;
  }

  __sanitizer::internal_strlcpy(file_buf, fname, file_buf_len);
  if (line)
    *line = res->info.line;
  if (column)
    *column = res->info.column;
  res->ClearAll();
  return 1;
}

// Read the line from the source file at path into the buffer.
// Returns 1 on success, 0 otherwise.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE u32
__bsan_read_src_line(const char *path, u32 line, char *buf, uptr buf_len) {
  fd_t fd = internal_open(path, 0, 0);
  if (fd < 0) {
    return 0;
  }

  uptr file_size = internal_filesize(fd);
  if (file_size == 0) {
    internal_close(fd);
    return 0;
  }

  // alloc file content buffer
  char *content = (char *)InternalAlloc(file_size + 1);
  if (!content) {
    internal_close(fd);
    return 0;
  }

  // read whole file in lieu of no std::getline
  uptr bytes_read = internal_read(fd, content, file_size);
  internal_close(fd);

  if (bytes_read != file_size) {
    InternalFree(content);
    return 0;
  }
  content[file_size] = '\0';

  // find line
  u32 current_line = 1;
  char *line_start = content;
  char *p = content;

  while (*p && current_line < line) {
    if (*p == '\n') {
      current_line++;
      line_start = p + 1;
    }
    p++;
  }

  // write line to buffer
  if (current_line == line) {
    uptr i = 0;
    while (line_start[i] && line_start[i] != '\n' && line_start[i] != '\r' &&
           i < buf_len - 1) {
      buf[i] = line_start[i];
      i++;
    }
    buf[i] = '\0';
    InternalFree(content);
    return 1;
  }

  InternalFree(content);
  return 0;
}