#include "bsan.h"
#include "bsan_thread.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
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
THREADLOCAL uptr bsan_tls_marker = 0;

const Provenance WILDCARD = {0, nullptr};

SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL Provenance __BSAN_PARAM_TLS[100];
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL Provenance __BSAN_RETVAL_TLS[100];

namespace __bsan {
Provenance *GetArgSlot(uptr Idx) { return &__BSAN_PARAM_TLS[Idx]; }
Provenance *GetRetValSlot(uptr Idx) { return &__BSAN_RETVAL_TLS[Idx]; }
} // namespace __bsan

uptr unwind(uptr bp, uptr len) {
  if (!bp || len == 0) {
    return bp;
  } else {
    return unwind(*(uptr *)bp, len - 1);
  }
}

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

/// When we call a possibly uninstrumented function, we store our frame
/// pointer in a thread-local variable, marking the "boundary" between
/// instrumented and uninstrumented code. Once we enter a function that may have
/// been called from uninstrumented code, we check to see if our caller's frame
/// pointer matches this boundary marker to determine whether we can trust our
/// thread-local provenance arrays.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE uptr __bsan_mark_tls(uptr len) {
  uptr prev_pc = bsan_tls_marker;
  bsan_tls_marker = unwind(GET_CURRENT_FRAME(), 1);
  return prev_pc;
}

/// Clears the parameter provenance array if the frame pointer of the
/// caller of the current function does not match the boundary marker,
/// indicating that we crossed into uninstrumented code. If it does match the
/// boundary marker, then we reset the boundary marker to null, signaling that
/// when we are back within the caller, we can trust the provenance array for
/// the return value.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_validate_param_tls(uptr len) {
  uptr marker = unwind(GET_CURRENT_FRAME(), 2);
  if (marker == bsan_tls_marker) {
    bsan_tls_marker = 0;
  } else {
    for (uptr i = 0; i < len; ++i) {
      *GetArgSlot(i) = WILDCARD;
    }
  }
}

/// Ensures that the provenance array for the return value is valid.
/// If the boundary marker is null, then we called an instrumented function, so
/// we can trust that the contents of the array is valid. Otherwise, we need to
/// fill it with wildcard provenance values for each pointer being returned. We
/// also need to restore the boundary marker to the value it had before the
/// function that was called.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_validate_retval_tls(uptr len, uptr prev_marker) {
  if (bsan_tls_marker) {
    for (uptr i = 0; i < len; ++i) {
      *GetRetValSlot(i) = WILDCARD;
    }
  }
  bsan_tls_marker = prev_marker;
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

// Read the entire file at path into the buffer.
// Returns the number of bytes read on success, 0 otherwise.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE uptr
__bsan_read_file(const char *path, char **file_buf, uptr *file_buf_len) {
  char *file = nullptr;
  uptr file_len = 0;
  uptr bytes_read = 0;
  error_t err;

  if (!ReadFileToBuffer(path, &file, &file_len, &bytes_read, (uptr)-1, &err)) {
    return 0;
  }
  if (bytes_read == 0) {
    UnmapOrDie(file, file_len);
    return 0;
  }

  *file_buf = file;
  *file_buf_len = file_len;
  return bytes_read;
}

// Free the buffer allocated by __bsan_read_file
extern "C" void __bsan_free_buffer(char *buf, uptr size) {
  if (buf && size > 0) {
    UnmapOrDie(buf, size);
  }
}

// Weak (de)init
extern "C" SANITIZER_WEAK_ATTRIBUTE void __bsan_internal_init() {}
extern "C" SANITIZER_WEAK_ATTRIBUTE void __bsan_internal_deinit() {}
extern "C" SANITIZER_WEAK_ATTRIBUTE void __bsan_local_init() {}
extern "C" SANITIZER_WEAK_ATTRIBUTE void __bsan_local_deinit() {}

// Weak tagging operations
extern "C" SANITIZER_WEAK_ATTRIBUTE BorTag
__bsan_retag(void *object_addr, usize access_size, u64 perm, BorTag bor_tag,
             AllocInfo *alloc_info, const usize im_data[2], usize im_len) {
  return bor_tag;
}
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_pop_frame(const Provenance *frame_start, usize protected_) {}
extern "C" SANITIZER_WEAK_ATTRIBUTE void __bsan_read(void *ptr,
                                                     usize access_size,
                                                     BorTag bor_tag,
                                                     AllocInfo *alloc_info) {}
extern "C" SANITIZER_WEAK_ATTRIBUTE void __bsan_write(void *ptr,
                                                      usize access_size,
                                                      BorTag bor_tag,
                                                      AllocInfo *alloc_info) {}
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_dealloc_stack(void *ptr, BorTag bor_tag, AllocInfo *alloc_info) {}

extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_shadow_copy(void *src, void *dest, usize access_size) {}
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_shadow_clear(void *dest, usize access_size) {}

extern "C" SANITIZER_WEAK_ATTRIBUTE AllocInfo *__bsan_reserve_stack_slot() {
  return nullptr;
}
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_destroy_stack_slot(AllocInfo *slot) {}
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_alloc_stack(void *base_addr, usize size, BorTag bor_tag,
                   AllocInfo *alloc_info) {}

extern "C" SANITIZER_WEAK_ATTRIBUTE AllocInfo*
__bsan_alloc(void *base_addr, usize size, BorTag bor_tag) {
    return nullptr;
}
// Weak Debugging
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_assert_null(BorTag bor_tag, AllocInfo *alloc_info) {}
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_assert_wildcard(BorTag bor_tag, AllocInfo *alloc_info) {}
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_assert_valid(BorTag bor_tag, AllocInfo *alloc_info) {}
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_assert_invalid(BorTag bor_tag, AllocInfo *alloc_info) {}
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_print(BorTag bor_tag, AllocInfo *alloc_info) {}
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_print_borrow_state(BorTag bor_tag, AllocInfo *alloc_info) {}
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_tree_size(BorTag bor_tag, AllocInfo *alloc_info) {}
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_print_diff(BorTag bor_tag, AllocInfo *alloc_info) {}
