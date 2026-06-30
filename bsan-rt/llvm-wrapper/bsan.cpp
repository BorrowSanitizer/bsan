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

// represents the number of provenance values that correspond to the variadic
// arguments being passed to the current function
SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL uptr __bsan_var_arg_ctr = 0;

// Pointer to the start of the current frame within the shadow
// stack, which stores the provenance of pointers that are on
// the stack or in registers. The shadow stack is always a fully
// initialized and contiguous from the top of the stack to the current
// value of the stack pointer.
SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL Provenance *__bsan_shadow_stack = nullptr;

// A flag set by the Rust core runtime to indicate to the LLVM
// wrapper that an error has occurred.
SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL uptr __bsan_had_error = 0;

SANITIZER_INTERFACE_ATTRIBUTE
atomic_uintptr_t __bsan_bor_tag_ctr{3};

namespace __bsan {

bool bsan_inited = false;
bool bsan_init_running = false;
bool bsan_deinit_running = false;
bool bsan_deinited = false;

// Every thread has a unique ID
atomic_uintptr_t thread_id{0};

BorTag NewBorTag() {
  return atomic_fetch_add(&__bsan_bor_tag_ctr, 1, memory_order_relaxed);
}

// Returns the desired length for the current stack trace.
// We add '1' to skip printing our runtime symbols in traces.
u32 GetStackTraceLen() {
  uptr stacktrace_max_len = flags()->stacktrace_max_len;
  return static_cast<u32>(stacktrace_max_len) + 1;
}

// Returns a pointer to the slot on the shadow stack at the given index.
// The shadow stack grows downward, so we subtract by the given index
// plus one to adjust the for the the zero-th slot.
Provenance *GetSlot(uptr Idx) { return __bsan_shadow_stack - (Idx + 1); }

// Clears the provenance from the given stack slot.
void ClearSlot(uptr Idx) { *GetSlot(Idx) = OMNIVALID; }

// Prints a note suggesting users raise stacktrace_max_len when the trace was
// truncated. The unwind in HANDLE_ERROR is bounded by GetStackTraceLen(), so a
// trace that fills that buffer was (almost certainly) cut short.
static void MaybeWarnTruncated(StackTrace &stack) {
  if (stack.size >= GetStackTraceLen())
    Printf("\nnote: stack trace was truncated after %zu frames; set "
           "stacktrace_max_len (e.g. BSAN_OPTIONS=stacktrace_max_len=32) "
           "to capture more.\n",
           (uptr)(stack.size - 1));
}

// Prints a stack trace, using Rust's formatting.
void PrintStackTrace(StackTrace &stack) {
  Printf("stack backtrace:\n");
  if (GetEnv("BSAN_SYMBOLIZER") == nullptr) {
    for (uptr i = 1; i < stack.size; ++i) {
      Printf("%ld: %p\n", (i - 1), (void *)stack.trace[i]);
    }
    Printf("\nwarning: Symbolizer not found. Please add llvm-symbolizer"
           " to your PATH or set BSAN_SYMBOLIZER for source code info "
           "(recommended).\n");
    MaybeWarnTruncated(stack);
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
  MaybeWarnTruncated(stack);
}

// Returns true if the file path belongs to a cargo or rustup library.
static bool IsLibraryFile(const char *file) {
  if (!file || *file == '\0')
    return true;
  return internal_strstr(file, ".cargo") || internal_strstr(file, ".rustup") ||
         internal_strstr(file, "cargo") || internal_strstr(file, "rustup");
}

// Returns true if any frame at this PC resolves to a user code file.
static bool HasUserInlineFrame(const SymbolizedStack *frame) {
  for (const SymbolizedStack *cur = frame; cur; cur = cur->next) {
    if (!IsLibraryFile(cur->info.file))
      return true;
  }
  return false;
}

// Locates the first user-code frame for the primary error location.
// Bounded above by __rust_begin_short_backtrace.
// Returns 0 when the symbolizer is unavailable or no user frame is found.
uptr FindUserFramePc(uptr pc, uptr bp) {
  if (GetEnv("BSAN_SYMBOLIZER") == nullptr)
    return 0;
  UNINITIALIZED BufferedStackTrace stack;
  stack.Unwind(pc, bp, nullptr, true, kStackTraceMax);
  for (uptr i = 1; i < stack.size; ++i) {
    SymbolizedStackHolder sym(
        Symbolizer::GetOrInit()->SymbolizePC(stack.trace[i]));
    const SymbolizedStack *frame = sym.get();
    if (!frame)
      continue;
    if (frame->info.function &&
        internal_strstr(frame->info.function, "__rust_begin_short_backtrace"))
      break;
    if (HasUserInlineFrame(frame))
      return stack.trace[i];
  }
  return 0;
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

SANITIZER_WEAK_ATTRIBUTE
void __bsan_format_pending_ub(uptr) {}

void __sanitizer::BufferedStackTrace::UnwindImpl(uptr pc, uptr bp,
                                                 void *context,
                                                 bool request_fast,
                                                 u32 max_depth) {
  using namespace __bsan;
  BsanThread *t = GetCurrentThread();
  if (!t || !StackTrace::WillUseFastUnwind(request_fast)) {
    // Block reports from our interceptors during _Unwind_Backtrace.
    InterceptorBarrier Barrier;
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

SANITIZER_WEAK_ATTRIBUTE
void __bsan_internal_init() {}

void __bsan_init() {
  CHECK(!bsan_init_running);
  if (bsan_inited)
    return;
  bsan_init_running = true;

  AvoidCVE_2016_2143();
  InitializeFlags();
  __bsan_internal_init();
  InitializePlatformEarly();

  if (!InitShadowWithReExec()) {
    Printf("FATAL: BorrowSanitizer can not mmap the shadow memory.\n");
    DumpProcessMap();
    Die();
  }
  InitializeAllocator();
  InitializeInterceptors();
  InitializeTSD();

  BsanThread *main_thread = BsanThread::Create(nullptr, nullptr);
  SetCurrentThread(main_thread);
  main_thread->Init();
  InitializeGC();

  bsan_init_running = false;
  bsan_inited = true;
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_internal_deinit() {}

void __bsan_deinit() {
  CHECK(!bsan_deinit_running);
  if (!bsan_inited)
    return;
  bsan_deinit_running = true;
  DeinitializeGC();
  bsan_deinit_running = false;
  bsan_inited = false;
  bsan_deinited = true;
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
      frame_start[i] = OMNIVALID;
    }
    __bsan_var_arg_ctr = 0;
  }
  __bsan_marker = 0;
}

/// Ensures that the provenance array for the return value is valid.
/// If the boundary marker is null, then we called an instrumented function, so
/// we can trust that the contents of the array is valid. Otherwise, we need to
/// fill it with omnivalid provenance values for each pointer being returned. We
/// also need to restore the boundary marker to the value it had before the
/// function that was called.
SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_validate_retval(void *prev_marker, Provenance *frame, uptr len) {
  if (__bsan_marker) {
    for (uptr i = 0; i < len; ++i) {
      frame[i] = OMNIVALID;
    }
  }
  __bsan_marker = prev_marker;
}

// Symbolize a single PC into file:line:column, writing the file path into
// the provided buffer. Returns 0 on failure, 1 when the frame resolves to
// user code, and 2 when every candidate frame is internal library code
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
  // The chain lists inline frames innermost first.
  // Prefer the first frame that is not library code
  const __sanitizer::SymbolizedStack *best = nullptr;
  for (const __sanitizer::SymbolizedStack *cur = res; cur; cur = cur->next) {
    if (!cur->info.file)
      continue;
    if (!best)
      best = cur;
    if (!IsLibraryFile(cur->info.file)) {
      best = cur;
      break;
    }
  }
  if (!best) {
    res->ClearAll();
    return 0;
  }

  __sanitizer::internal_strlcpy(file_buf, best->info.file, file_buf_len);
  if (line)
    *line = best->info.line;
  if (column)
    *column = best->info.column;
  u32 result = IsLibraryFile(best->info.file) ? 2 : 1;
  res->ClearAll();
  return result;
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

SANITIZER_WEAK_ATTRIBUTE
void __bsan_local_init(Provenance **prov) {}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_local_deinit() {}

SANITIZER_WEAK_ATTRIBUTE void
__bsan_retag_impl(void *object_addr, uptr access_size, u8 flags,
                  const uptr im_data[2], uptr im_len, const uptr pin_data[2],
                  uptr pin_len, BorTag bor_tag, AllocInfo *alloc_info,
                  void *dest, Span pc);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_retag(void *object_addr, uptr access_size, u8 flags,
                  const uptr im_data[2], uptr im_len, const uptr pin_data[2],
                  uptr pin_len, BorTag bor_tag, AllocInfo *alloc_info,
                  void *dest) {
  if (__bsan_retag_impl) {
    GET_SPAN;
    InterceptorBarrier Barrier;
    __bsan_retag_impl(object_addr, access_size, flags, im_data, im_len,
                      pin_data, pin_len, bor_tag, alloc_info, dest, span);
    HANDLE_ERROR;
  }
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_read_impl(void *ptr, uptr access_size, BorTag bor_tag,
                      AllocInfo *alloc_info, Span pc);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_read(void *ptr, uptr access_size, BorTag bor_tag,
                 AllocInfo *alloc_info) {
  if (__bsan_read_impl) {
    GET_SPAN;
    InterceptorBarrier Barrier;
    __bsan_read_impl(ptr, access_size, bor_tag, alloc_info, span);
    HANDLE_ERROR;
  }
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_write_impl(void *ptr, uptr access_size, BorTag bor_tag,
                       AllocInfo *alloc_info, Span pc);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_write(void *ptr, uptr access_size, BorTag bor_tag,
                  AllocInfo *alloc_info) {
  if (__bsan_write_impl) {
    GET_SPAN;
    InterceptorBarrier Barrier;
    __bsan_write_impl(ptr, access_size, bor_tag, alloc_info, span);
    HANDLE_ERROR;
  }
}

SANITIZER_WEAK_ATTRIBUTE
bool __bsan_rc_inc_impl(BorTag Tag, AllocInfo *Info);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_rc_inc(BorTag Tag, AllocInfo *Info) {
  if (__bsan_rc_inc_impl) {
    InterceptorBarrier Barrier;
    __bsan_rc_inc_impl(Tag, Info);
  }
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_rc_dec_impl(BorTag Tag, AllocInfo *Info);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_rc_dec(BorTag Tag, AllocInfo *Info) {
  if (__bsan_rc_dec_impl) {
    InterceptorBarrier Barrier;
    __bsan_rc_dec_impl(Tag, Info);
  }
}

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_shadow_clear(void *dest, uptr size) { ClearShadow(dest, size); }

SANITIZER_WEAK_ATTRIBUTE
AllocInfo *__bsan_reserve_stack_slot_impl();

SANITIZER_INTERFACE_ATTRIBUTE
AllocInfo *__bsan_reserve_stack_slot() {
  if (__bsan_reserve_stack_slot_impl) {
    InterceptorBarrier Barrier;
    return __bsan_reserve_stack_slot_impl();
  }
  return nullptr;
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_destroy_stack_slot_impl(AllocInfo *slot);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_destroy_stack_slot(AllocInfo *slot) {
  if (__bsan_destroy_stack_slot_impl) {
    InterceptorBarrier Barrier;
    __bsan_destroy_stack_slot_impl(slot);
  }
}

SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE AllocInfo *
__bsan_alloc(void *base_addr, uptr size, BorTag bor_tag, Span pc) {
  return nullptr;
}

SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE void
__bsan_dealloc(void *ptr, BorTag bor_tag, AllocInfo *alloc_info, Span pc) {}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_alloc_stack_impl(void *base_addr, uptr size, BorTag bor_tag,
                             AllocInfo *alloc_info, Span pc);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_alloc_stack(void *base_addr, uptr size, BorTag bor_tag,
                        AllocInfo *alloc_info) {
  if (__bsan_alloc_stack_impl) {
    GET_SPAN;
    InterceptorBarrier Barrier;
    __bsan_alloc_stack_impl(base_addr, size, bor_tag, alloc_info, span);
    HANDLE_ERROR;
  }
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_dealloc_stack_impl(BorTag bor_tag, AllocInfo *alloc_info, Span pc);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_dealloc_stack(void *ptr, BorTag bor_tag, AllocInfo *alloc_info) {
  if (__bsan_dealloc_stack_impl) {
    GET_SPAN;
    InterceptorBarrier Barrier;
    __bsan_dealloc_stack_impl(bor_tag, alloc_info, span);
    HANDLE_ERROR;
  }
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_expose_prov_impl(BorTag bor_tag, AllocInfo *alloc_info);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_expose_prov(BorTag bor_tag, AllocInfo *alloc_info) {
  if (__bsan_expose_prov_impl) {
    InterceptorBarrier Barrier;
    __bsan_expose_prov_impl(bor_tag, alloc_info);
  }
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_protector_end_impl(BorTag bor_tag, AllocInfo *alloc_info, Span pc);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_pop_frame(const Provenance *frame_start, uptr prot,
                      uptr alloca_vec_size) {
  if (__bsan_protector_end_impl && __bsan_destroy_stack_slot_impl &&
      __bsan_dealloc_stack_impl) {
    GET_SPAN;
    InterceptorBarrier Barrier;
    for (uptr i = 0; i < prot + alloca_vec_size; i++) {
      const Provenance Prov = frame_start[i];
      if (i < prot) {
        __bsan_protector_end_impl(Prov.Tag, Prov.Info, span);
      } else {
        __bsan_dealloc_stack_impl(Prov.Tag, Prov.Info, span);
        __bsan_destroy_stack_slot_impl(Prov.Info);
      }
    }
  }
}

// Debugging.
SANITIZER_WEAK_ATTRIBUTE
void __bsan_print(BorTag bor_tag, AllocInfo *alloc_info) {}

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_debug_print(void *ptr) {
  Provenance *Slot = GetSlot(0);
  InterceptorBarrier Barrier;
  __bsan_print(Slot->Tag, Slot->Info);
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_print_borrow_state(BorTag bor_tag, AllocInfo *alloc_info) {}

void __bsan_debug_print_borrow_state(void *ptr) {
  Provenance *Slot = GetSlot(0);
  InterceptorBarrier Barrier;
  __bsan_print_borrow_state(Slot->Tag, Slot->Info);
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_tree_size(BorTag bor_tag, AllocInfo *alloc_info) {}

void __bsan_debug_tree_size(void *ptr) {
  Provenance *Slot = GetSlot(0);
  InterceptorBarrier Barrier;
  __bsan_tree_size(Slot->Tag, Slot->Info);
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_snapshot(BorTag bor_tag, AllocInfo *alloc_info) {}

void __bsan_debug_snapshot(void *ptr) {
  Provenance *Slot = GetSlot(0);
  InterceptorBarrier Barrier;
  __bsan_snapshot(Slot->Tag, Slot->Info);
}

SANITIZER_WEAK_ATTRIBUTE void __bsan_print_diff(BorTag bor_tag,
                                                AllocInfo *alloc_info) {}

void __bsan_debug_print_diff(void *ptr) {
  Provenance *Slot = GetSlot(0);
  InterceptorBarrier Barrier;
  __bsan_print_diff(Slot->Tag, Slot->Info);
}

void __bsan_abort() { Die(); }

} // extern "C"
