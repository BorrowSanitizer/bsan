#include "bsan.h"
#include "bsan_flags.h"
#include "bsan_interface_internal.h"
#include "bsan_thread.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_stacktrace_printer.h"
#include "sanitizer_common/sanitizer_symbolizer.h"

using namespace __sanitizer;

// Interface globals.
// Stores the function pointer of a possibly
// uninstrumented callee. We can check this against
// the current function's pointer to determine if we
// have been called from an uninstrumented context.
SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL void *__bsan_marker = nullptr;

// Pointer to the start of the current frame within the shadow
// stack, which stores the provenance of pointers that are on
// the stack or in registers. The shadow stack is always a fully
// initialized and contiguous from the top of the stack to the current
// value of the stack pointer.
SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL Provenance *__bsan_shadow_stack = nullptr;

namespace __bsan {

static THREADLOCAL int is_in_symbolizer_or_unwinder;
static void EnterSymbolizerOrUnwider() { ++is_in_symbolizer_or_unwinder; }
static void ExitSymbolizerOrUnwider() { --is_in_symbolizer_or_unwinder; }
bool IsInSymbolizerOrUnwider() { return is_in_symbolizer_or_unwinder; }

struct UnwinderScope {
  UnwinderScope() { EnterSymbolizerOrUnwider(); }
  ~UnwinderScope() { ExitSymbolizerOrUnwider(); }
};

bool bsan_inited = false;
bool bsan_init_running = false;
bool bsan_deinit_running = false;
atomic_uintptr_t thread_id{0};

u32 GetStackTraceLen() {
  uptr stacktrace_max_len = flags()->stacktrace_max_len;
  return static_cast<u32>(stacktrace_max_len) + 1;
}

Provenance *GetSlot(uptr Idx) { return __bsan_shadow_stack - (Idx + 1); }
void ClearSlot(uptr Idx) { *GetSlot(Idx) = WILDCARD; }

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

bool CallerIsInstrumented(void *sym) {
  if (__bsan_shadow_stack == nullptr) {
    return false;
  }
  if (__bsan_marker) {
    bool cond = __bsan_marker == sym;
    if (cond) {
      __bsan_marker = 0;
    }
    return cond;
  } else {
    return true;
  }
}

} // namespace __bsan

void __sanitizer::BufferedStackTrace::UnwindImpl(uptr pc, uptr bp,
                                                 void *context,
                                                 bool request_fast,
                                                 u32 max_depth) {
  using namespace __bsan;
  BsanThread *t = GetCurrentThread();
  if (!t || !StackTrace::WillUseFastUnwind(request_fast)) {
    // Block reports from our interceptors during _Unwind_Backtrace.
    UnwinderScope sym_scope;
    return Unwind(max_depth, pc, bp, context, t ? t->stack_top() : 0,
                  t ? t->stack_bottom() : 0, false);
  }
  if (StackTrace::WillUseFastUnwind(request_fast))
    Unwind(max_depth, pc, bp, nullptr, t->stack_top(), t->stack_bottom(), true);
  else
    Unwind(max_depth, pc, 0, context, 0, 0, false);
}

// Interface.

using namespace __bsan;

extern "C" {

void __bsan_init() {
  CHECK(!bsan_init_running);
  if (bsan_inited)
    return;
  bsan_init_running = true;

  AvoidCVE_2016_2143();
  InitializeFlags();
  __bsan_internal_init();
  InitializePlatformEarly();

  InitializeGC();
  InitializeInterceptors();
  InitializeTSD();

  BsanThread *main_thread = BsanThread::Create(nullptr, nullptr);
  SetCurrentThread(main_thread);
  main_thread->Init();
  bsan_init_running = false;
  bsan_inited = true;
}

void __bsan_deinit() {
  CHECK(!bsan_deinit_running);
  if (!bsan_inited)
    return;
  bsan_deinit_running = true;

  DeinitializeGC();

  __bsan_internal_deinit();
  bsan_deinit_running = false;
  bsan_inited = false;
}

/// When we call a possibly uninstrumented function, we store our frame
/// pointer in a thread-local variable, marking the "boundary" between
/// instrumented and uninstrumented code. Once we enter a function that may have
/// been called from uninstrumented code, we check to see if our caller's frame
/// pointer matches this boundary marker to determine whether we can trust our
/// thread-local provenance arrays.
SANITIZER_INTERFACE_ATTRIBUTE
void *__bsan_mark(void *callee) {
  void *prev_marker = __bsan_marker;
  __bsan_marker = callee;
  return prev_marker;
}

/// Clears the parameter provenance array if the frame pointer of the
/// caller of the current function does not match the boundary marker,
/// indicating that we crossed into uninstrumented code. If it does match the
/// boundary marker, then we reset the boundary marker to null, signaling that
/// when we are back within the caller, we can trust the provenance array for
/// the return value.
SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_validate_params(void *current_fn, Provenance *frame_start,
                            uptr len) {
  if (__bsan_marker && current_fn != __bsan_marker) {
    for (uptr i = 0; i < len; ++i) {
      frame_start[i] = WILDCARD;
    }
  }
  __bsan_marker = 0;
}

/// Ensures that the provenance array for the return value is valid.
/// If the boundary marker is null, then we called an instrumented function, so
/// we can trust that the contents of the array is valid. Otherwise, we need to
/// fill it with wildcard provenance values for each pointer being returned. We
/// also need to restore the boundary marker to the value it had before the
/// function that was called.
SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_validate_retval(void *prev_marker, Provenance *frame, uptr len) {
  if (__bsan_marker) {
    for (uptr i = 0; i < len; ++i) {
      frame[i] = WILDCARD;
    }
  }
  __bsan_marker = prev_marker;
}

// Symbolize a single PC into file:line:column, writing the file path into
// the provided buffer. Returns 1 on success, 0 otherwise.
SANITIZER_INTERFACE_ATTRIBUTE
u32 __bsan_symbolize_pc(uptr pc, char *file_buf, uptr file_buf_len, u32 *line,
                        u32 *column) {
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
SANITIZER_INTERFACE_ATTRIBUTE
uptr __bsan_read_file(const char *path, char **file_buf, uptr *file_buf_len) {
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
SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_free_buffer(char *buf, uptr size) {
  if (buf && size > 0) {
    UnmapOrDie(buf, size);
  }
}

// Weak (de)init
SANITIZER_WEAK_ATTRIBUTE
void __bsan_internal_init() {}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_internal_deinit() {}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_local_init(Provenance **prov) {}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_local_deinit() {}

// Weak tagging operations
SANITIZER_WEAK_ATTRIBUTE
BorTag __bsan_new_bor_tag() { return 0; }

SANITIZER_WEAK_ATTRIBUTE
BorTag __bsan_retag_impl(void *object_addr, uptr access_size, u8 flags,
                         const uptr im_data[2], uptr im_len,
                         const uptr pin_data[2], uptr pin_len, BorTag bor_tag,
                         AllocInfo *alloc_info, Span pc) {
  return bor_tag;
}

SANITIZER_INTERFACE_ATTRIBUTE
BorTag __bsan_retag(void *object_addr, uptr access_size, u8 flags,
                    const uptr im_data[2], uptr im_len, const uptr pin_data[2],
                    uptr pin_len, BorTag bor_tag, AllocInfo *alloc_info) {
  GET_SPAN_PC_BP;
  BorTag tag =
      __bsan_retag_impl(object_addr, access_size, flags, im_data, im_len,
                        pin_data, pin_len, bor_tag, alloc_info, span);
  HANDLE_ERROR(pc, bp);
  return tag;
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_read_impl(void *ptr, uptr access_size, BorTag bor_tag,
                      AllocInfo *alloc_info, Span pc) {}

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_read(void *ptr, uptr access_size, BorTag bor_tag,
                 AllocInfo *alloc_info) {
  GET_SPAN_PC_BP;
  __bsan_read_impl(ptr, access_size, bor_tag, alloc_info, span);
  HANDLE_ERROR(pc, bp);
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_write_impl(void *ptr, uptr access_size, BorTag bor_tag,
                       AllocInfo *alloc_info, Span pc) {}

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_write(void *ptr, uptr access_size, BorTag bor_tag,
                  AllocInfo *alloc_info) {
  GET_SPAN_PC_BP;
  __bsan_write_impl(ptr, access_size, bor_tag, alloc_info, span);
  HANDLE_ERROR(pc, bp);
}

SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE void
__bsan_shadow_transfer(void *dest, const void *src, uptr access_size) {}

SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE void
__bsan_shadow_clear(void *dest, uptr access_size) {}

SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE AllocInfo *
__bsan_reserve_stack_slot() {
  return nullptr;
}

SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE void
__bsan_destroy_stack_slot(AllocInfo *slot) {}

SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE AllocInfo *
__bsan_alloc(void *base_addr, uptr size, BorTag bor_tag, Span pc) {
  return nullptr;
}
SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE void
__bsan_dealloc(void *ptr, BorTag bor_tag, AllocInfo *alloc_info, Span pc) {}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_alloc_stack_impl(void *base_addr, uptr size, BorTag bor_tag,
                             AllocInfo *alloc_info, Span pc) {}

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_alloc_stack(void *base_addr, uptr size, BorTag bor_tag,
                        AllocInfo *alloc_info) {
  GET_SPAN_PC_BP;
  __bsan_alloc_stack_impl(base_addr, size, bor_tag, alloc_info, span);
  HANDLE_ERROR(pc, bp);
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_dealloc_stack_impl(BorTag bor_tag, AllocInfo *alloc_info, Span pc) {
}

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_dealloc_stack(void *ptr, BorTag bor_tag, AllocInfo *alloc_info) {
  GET_SPAN_PC_BP;
  __bsan_dealloc_stack_impl(bor_tag, alloc_info, span);
  HANDLE_ERROR(pc, bp);
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_protector_end_impl(BorTag bor_tag, AllocInfo *alloc_info, Span pc) {
}

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_pop_frame(const Provenance *frame_start, uptr prot,
                      uptr alloca_vec_size) {
  GET_SPAN;
  for (uptr i = 0; i < prot + alloca_vec_size; i++) {
    const Provenance Prov = frame_start[i];
    if (i < prot) {
      __bsan_protector_end_impl(Prov.Tag, Prov.Info, span);
    } else {
      __bsan_dealloc_stack_impl(Prov.Tag, Prov.Info, span);
      __bsan_destroy_stack_slot(Prov.Info);
    }
  }
}

// Debugging.

SANITIZER_WEAK_ATTRIBUTE
void __bsan_print(BorTag bor_tag, AllocInfo *alloc_info) {}

void __bsan_debug_print(void *ptr) {
  Provenance *Slot = GetSlot(0);
  __bsan_print(Slot->Tag, Slot->Info);
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_print_borrow_state(BorTag bor_tag, AllocInfo *alloc_info) {}

void __bsan_debug_print_borrow_state(void *ptr) {
  Provenance *Slot = GetSlot(0);
  __bsan_print_borrow_state(Slot->Tag, Slot->Info);
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_tree_size(BorTag bor_tag, AllocInfo *alloc_info) {}

void __bsan_debug_tree_size(void *ptr) {
  Provenance *Slot = GetSlot(0);
  __bsan_tree_size(Slot->Tag, Slot->Info);
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_snapshot(BorTag bor_tag, AllocInfo *alloc_info) {}

void __bsan_debug_snapshot(void *ptr) {
  Provenance *Slot = GetSlot(0);
  __bsan_snapshot(Slot->Tag, Slot->Info);
}

SANITIZER_WEAK_ATTRIBUTE void __bsan_print_diff(BorTag bor_tag,
                                                AllocInfo *alloc_info) {}

void __bsan_debug_print_diff(void *ptr) {
  Provenance *Slot = GetSlot(0);
  __bsan_print_diff(Slot->Tag, Slot->Info);
}

void __bsan_abort() {
  // Printf("BorrowSanitizer: aborting due to a fatal error.\n");
  Die();
}

} // extern "C"