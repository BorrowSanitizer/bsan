#include "bsan.h"
#include "bsan_thread.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_stacktrace_printer.h"
#include "sanitizer_common/sanitizer_symbolizer.h"

using namespace __sanitizer;
using namespace __bsan;

#define TLS_SIZE 100

SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL Provenance __BSAN_PARAM_TLS[TLS_SIZE];
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL Provenance
    __BSAN_RETVAL_TLS[TLS_SIZE];
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL void *__BSAN_TLS_MARKER = nullptr;

bool BSAN_INITED = false;
bool BSAN_INIT_RUNNING;
bool BSAN_DEINIT_RUNNING;

const Provenance WILDCARD = {0, nullptr};
const Provenance INVALID = {1, nullptr};

namespace __bsan {

Provenance *GetArgSlot(uptr Idx) { return &__BSAN_PARAM_TLS[Idx]; }
Provenance *GetRetValSlot(uptr Idx) { return &__BSAN_RETVAL_TLS[Idx]; }

void ClearArgSlot(uptr Idx) { __BSAN_PARAM_TLS[Idx] = WILDCARD; }
void ClearRetValSlot(uptr Idx) { __BSAN_RETVAL_TLS[Idx] = WILDCARD; }

void PrintStackTrace(StackTrace &stack) {
  Printf("stack backtrace:\n");
  if (GetEnv("BSAN_SYMBOLIZER") == nullptr) {
    for (uptr i = 1; i < stack.size; ++i) {
      Printf("%ld: %p\n", (i - 1), (void *)stack.trace[i]);
    }
    Printf("\nwarning: Symbolizer not found. Please add llvm-symbolizer"
           " to your PATH or set BSAN_SYMBOLIZER for source code info "
           "(recommended).\n");
    return;
  }
  InternalScopedString frame_desc;
  for (uptr i = 1; i < stack.size; ++i) {
    uptr pc = stack.trace[i];
    SymbolizedStackHolder symbolized_stack(
        Symbolizer::GetOrInit()->SymbolizePC(pc));
    const SymbolizedStack *frame = symbolized_stack.get();
    if (frame) {
      StackTracePrinter::GetOrInit()->RenderFrame(
          &frame_desc, "%f\n      at %S", i, frame->info.address, &frame->info,
          common_flags()->symbolize_vs_style,
          common_flags()->strip_path_prefix);
      Printf("%ld: %s\n", (i - 1), frame_desc.data());
      frame_desc.clear();
    }
  }
}

} // namespace __bsan

NOINLINE void __sanitizer::BufferedStackTrace::UnwindImpl(uptr pc, uptr bp,
                                                          void *context,
                                                          bool request_fast,
                                                          u32 max_depth) {
  ENABLE_FRAME_POINTER;

  BsanThread *t = GetCurrentThread();
  if (!t) {
    // The thread is still being created, or has already been destroyed.
    size = 0;
    return;
  }
  Unwind(max_depth, pc, bp, context, t->stack_top(), t->stack_bottom(),
         request_fast);
}

extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE void __bsan_init() {
  CHECK(!BSAN_INIT_RUNNING);
  if (BSAN_INITED)
    return;
  BSAN_INIT_RUNNING = true;
  AvoidCVE_2016_2143();
  __bsan_internal_init();
  InitializePlatformEarly();
  InitializeInterceptors();
  SetCommonFlagsDefaults();

  const char *symbolizer_path = GetEnv("BSAN_SYMBOLIZER");
  if (!symbolizer_path || symbolizer_path[0] == '\0') {
    symbolizer_path = FindPathToBinary("llvm-symbolizer");
  }

  if (symbolizer_path && symbolizer_path[0] != '\0') {
    SetEnv("BSAN_SYMBOLIZER", symbolizer_path);
    CommonFlags cf;
    cf.CopyFrom(*common_flags());
    cf.external_symbolizer_path = symbolizer_path;
    OverrideCommonFlags(cf);
  }

  BsanTSDInit();
  BsanThread *main_thread = BsanThread::Create(nullptr, nullptr);
  SetCurrentThread(main_thread);
  main_thread->Init();
  BSAN_INIT_RUNNING = false;
  BSAN_INITED = true;
}

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_deinit() {
  CHECK(!BSAN_DEINIT_RUNNING);
  if (!BSAN_INITED)
    return;
  BSAN_DEINIT_RUNNING = true;
  __bsan_internal_deinit();
  BSAN_DEINIT_RUNNING = false;
  BSAN_INITED = false;
}

/// When we call a possibly uninstrumented function, we store our frame
/// pointer in a thread-local variable, marking the "boundary" between
/// instrumented and uninstrumented code. Once we enter a function that may have
/// been called from uninstrumented code, we check to see if our caller's frame
/// pointer matches this boundary marker to determine whether we can trust our
/// thread-local provenance arrays.
SANITIZER_INTERFACE_ATTRIBUTE void *__bsan_mark_tls(void *callee) {
  void *prev_marker = __BSAN_TLS_MARKER;
  __BSAN_TLS_MARKER = callee;
  return prev_marker;
}

/// Clears the parameter provenance array if the frame pointer of the
/// caller of the current function does not match the boundary marker,
/// indicating that we crossed into uninstrumented code. If it does match the
/// boundary marker, then we reset the boundary marker to null, signaling that
/// when we are back within the caller, we can trust the provenance array for
/// the return value.
SANITIZER_INTERFACE_ATTRIBUTE void __bsan_validate_param_tls(void *current_fn,
                                                             uptr len) {
  if (__BSAN_TLS_MARKER == 0 || current_fn == __BSAN_TLS_MARKER) {
    __BSAN_TLS_MARKER = 0;
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
SANITIZER_INTERFACE_ATTRIBUTE void __bsan_validate_retval_tls(void *prev_marker,
                                                              uptr len) {
  if (__BSAN_TLS_MARKER) {
    for (uptr i = 0; i < len; ++i) {
      *GetRetValSlot(i) = WILDCARD;
    }
  }
  __BSAN_TLS_MARKER = prev_marker;
}

// Get the top frame PC address from the current PC
// Returns the previous instruction PC (adjusted for return addresses)
SANITIZER_INTERFACE_ATTRIBUTE uptr __bsan_get_top_frame_pc(uptr pc) {
  return StackTrace::GetPreviousInstructionPc(pc);
}

// FIXME: this function should only be used internally and does not need to be
// visible in the binary. But we need to make it available to bsan-rt-core
SANITIZER_INTERFACE_ATTRIBUTE u32 __bsan_stack_depot_put(uptr pc, uptr bp,
                                                         u32 max_depth) {
  UNINITIALIZED BufferedStackTrace stack;
  stack.Unwind(pc, bp, /*context=*/nullptr, /*request_fast=*/true,
               /*max_depth=*/max_depth);
  return StackDepotPut(stack);
}

// Symbolize a single PC into file:line:column, writing the file path into
// the provided buffer. Returns 1 on success, 0 otherwise.
SANITIZER_INTERFACE_ATTRIBUTE u32 __bsan_symbolize_pc(uptr pc, char *file_buf,
                                                      uptr file_buf_len,
                                                      u32 *line, u32 *column) {
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
SANITIZER_INTERFACE_ATTRIBUTE uptr __bsan_read_file(const char *path,
                                                    char **file_buf,
                                                    uptr *file_buf_len) {
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
void __bsan_free_buffer(char *buf, uptr size) {
  if (buf && size > 0) {
    UnmapOrDie(buf, size);
  }
}

// Weak (de)init
SANITIZER_WEAK_ATTRIBUTE void __bsan_internal_init() {}

SANITIZER_WEAK_ATTRIBUTE void __bsan_internal_deinit() {}

// Weak tagging operations
SANITIZER_WEAK_ATTRIBUTE BorTag __bsan_new_bor_tag() { return 0; }

SANITIZER_INTERFACE_ATTRIBUTE BorTag
__bsan_retag(void *object_addr, uptr access_size, u8 is_prot, u8 is_freeze,
             u8 is_unpin, u8 ptr_kind, const uptr im_data[2], uptr im_len,
             BorTag bor_tag, AllocInfo *alloc_info) {
  GET_SPAN_PC_BP;
  BorTag tag =
      __bsan_retag_impl(object_addr, access_size, is_prot, is_freeze, is_unpin,
                        ptr_kind, im_data, im_len, bor_tag, alloc_info, span);
  HANDLE_ERROR(pc, bp);
  return tag;
}

SANITIZER_WEAK_ATTRIBUTE BorTag
__bsan_retag_impl(void *object_addr, uptr access_size, u8 is_prot, u8 is_freeze,
                  u8 is_unpin, u8 ptr_kind, const uptr im_data[2], uptr im_len,
                  BorTag bor_tag, AllocInfo *alloc_info, Span pc) {
  return bor_tag;
}

SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_pop_frame(const Provenance *frame_start, uptr prot) {
  GET_SPAN_PC_BP;
  __bsan_pop_frame_impl(frame_start, prot, span);
  HANDLE_ERROR(pc, bp);
}

SANITIZER_WEAK_ATTRIBUTE void
__bsan_pop_frame_impl(const Provenance *frame_start, uptr prot, Span pc) {}

// Define this somewhere out of the fast path (e.g., in bsan_report.cpp)
// Use SANITIZER_INTERFACE_ATTRIBUTE if this is called from instrumented code,
// or just NOINLINE if it's internal.
NOINLINE void __bsan_report_error(uptr pc, uptr bp, void *ptr,
                                  uptr access_size) {
  // 1. Guarantee the frame pointer is intact for the unwinder
  ENABLE_FRAME_POINTER;

  // 2. Fetch standard unwinding flags rather than hardcoding
  bool fast_unwind = common_flags()->fast_unwind_on_fatal;
  u32 max_depth = 3; // Or hardcode a safe depth like 50

  // 3. Unwind and report
  UNINITIALIZED BufferedStackTrace stack;
  stack.Unwind(pc, bp, nullptr, fast_unwind, max_depth);

  PrintStackTrace(stack);
  Die();
}

SANITIZER_WEAK_ATTRIBUTE void __bsan_read_impl(void *ptr, uptr access_size,
                                               BorTag bor_tag,
                                               AllocInfo *alloc_info, Span pc) {
}

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_read(void *ptr, uptr access_size,
                                               BorTag bor_tag,
                                               AllocInfo *alloc_info) {
  GET_SPAN_PC_BP;
  __bsan_read_impl(ptr, access_size, bor_tag, alloc_info, span);
  HANDLE_ERROR(pc, bp);
}

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_write(void *ptr, uptr access_size,
                                                BorTag bor_tag,
                                                AllocInfo *alloc_info) {
  GET_SPAN_PC_BP;
  __bsan_write_impl(ptr, access_size, bor_tag, alloc_info, span);
  HANDLE_ERROR(pc, bp);
}

SANITIZER_WEAK_ATTRIBUTE void __bsan_write_impl(void *ptr, uptr access_size,
                                                BorTag bor_tag,
                                                AllocInfo *alloc_info,
                                                Span pc) {}

SANITIZER_WEAK_ATTRIBUTE void
__bsan_shadow_transfer(void *dest, const void *src, uptr access_size) {}
SANITIZER_WEAK_ATTRIBUTE void __bsan_shadow_clear(void *dest,
                                                  uptr access_size) {}
SANITIZER_WEAK_ATTRIBUTE AllocInfo *__bsan_reserve_stack_slot() {
  return nullptr;
}
SANITIZER_WEAK_ATTRIBUTE void __bsan_destroy_stack_slot(AllocInfo *slot) {}

SANITIZER_WEAK_ATTRIBUTE AllocInfo *__bsan_alloc(void *base_addr, uptr size,
                                                 BorTag bor_tag, Span pc) {
  return nullptr;
}
SANITIZER_WEAK_ATTRIBUTE void __bsan_dealloc(void *ptr, BorTag bor_tag,
                                             AllocInfo *alloc_info, Span pc) {}

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_alloc_stack(void *base_addr,
                                                      uptr size, BorTag bor_tag,
                                                      AllocInfo *alloc_info) {
  GET_SPAN_PC_BP;
  __bsan_alloc_stack_impl(base_addr, size, bor_tag, alloc_info, span);
  HANDLE_ERROR(pc, bp);
}

SANITIZER_WEAK_ATTRIBUTE void __bsan_alloc_stack_impl(void *base_addr,
                                                      uptr size, BorTag bor_tag,
                                                      AllocInfo *alloc_info,
                                                      Span pc) {}

SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_dealloc_stack(void *ptr, BorTag bor_tag, AllocInfo *alloc_info) {
  GET_SPAN_PC_BP;
  __bsan_dealloc_stack_impl(ptr, bor_tag, alloc_info, span);
  HANDLE_ERROR(pc, bp);
}

SANITIZER_WEAK_ATTRIBUTE void __bsan_dealloc_stack_impl(void *ptr,
                                                        BorTag bor_tag,
                                                        AllocInfo *alloc_info,
                                                        Span pc) {}
// Debugging
SANITIZER_WEAK_ATTRIBUTE void __bsan_print(BorTag bor_tag,
                                           AllocInfo *alloc_info) {}
SANITIZER_INTERFACE_ATTRIBUTE void __bsan_debug_print(void *ptr) {
  Provenance *Slot = GetArgSlot(0);
  __bsan_print(Slot->Tag, Slot->Info);
}

SANITIZER_WEAK_ATTRIBUTE void __bsan_print_borrow_state(BorTag bor_tag,
                                                        AllocInfo *alloc_info) {
}
SANITIZER_INTERFACE_ATTRIBUTE void __bsan_debug_print_borrow_state(void *ptr) {
  Provenance *Slot = GetArgSlot(0);
  __bsan_print_borrow_state(Slot->Tag, Slot->Info);
}

SANITIZER_WEAK_ATTRIBUTE void __bsan_tree_size(BorTag bor_tag,
                                               AllocInfo *alloc_info) {}
SANITIZER_INTERFACE_ATTRIBUTE void __bsan_debug_tree_size(void *ptr) {
  Provenance *Slot = GetArgSlot(0);
  __bsan_tree_size(Slot->Tag, Slot->Info);
}

SANITIZER_WEAK_ATTRIBUTE void __bsan_snapshot(BorTag bor_tag,
                                              AllocInfo *alloc_info) {}
SANITIZER_INTERFACE_ATTRIBUTE void __bsan_debug_snapshot(void *ptr) {
  Provenance *Slot = GetArgSlot(0);
  __bsan_snapshot(Slot->Tag, Slot->Info);
}

SANITIZER_WEAK_ATTRIBUTE void __bsan_print_diff(BorTag bor_tag,
                                                AllocInfo *alloc_info) {}
SANITIZER_INTERFACE_ATTRIBUTE void __bsan_debug_print_diff(void *ptr) {
  Provenance *Slot = GetArgSlot(0);
  __bsan_print_diff(Slot->Tag, Slot->Info);
}

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_abort() {
  // Printf("BorrowSanitizer: aborting due to a fatal error.\n");
  Die();
}
} // extern "C"
