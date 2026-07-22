#include "bsan.h"
#include "bsan_flags.h"
#include "bsan_global.h"
#include "bsan_interface_internal.h"
#include "bsan_thread.h"
#include "sanitizer_common/sanitizer_addrhashmap.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_stacktrace_printer.h"
#include "sanitizer_common/sanitizer_stoptheworld.h"
#include "sanitizer_common/sanitizer_symbolizer.h"

using namespace __sanitizer;

// Interface globals.
// Stores the function pointer of a possibly
// uninstrumented callee. We can check this against
// the current function's pointer to determine if we
// have been called from an uninstrumented context.
SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL void *__bsan_marker = nullptr;

// When we call one of Rust's allocator shims, we need to
// mark the underlying function as being trusted by our runtime,
// so that the return provenace does not get clobbered by boundary
// validation. In these situations, we set the boundary marker to
// dedicated "trusted" marker, indicating that we can unconditionally
// trust that our caller was instrumented, even if we do not have
// access to its function pointer.
static void *kTrustedMarker = (void *)1;

// The number of provenance values corresponding to variadic
// arguments being passed to the current function
SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL uptr __bsan_var_arg_ctr = 0;

// Pointer to the start of the current frame within the shadow
// stack, which stores the provenance of pointers that are on
// the stack or in registers. The shadow stack is always a fully
// initialized and contiguous from the top of the stack to the
// current value of the stack pointer.
SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL Provenance *__bsan_shadow_stack = nullptr;

// A flag set by the Rust "core" runtime to indicate to the LLVM
// wrapper that an error has occurred.
SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL uptr __bsan_had_error = 0;

// A counter used to create globally-unique "borrow tags"
// associated with permissions in the tree for an allocation.
// The values 0-2 are reserved:
// - 0: an omnivalid tag
// - 1: an invalid tag
// - 2: a wildcard tag
SANITIZER_INTERFACE_ATTRIBUTE
atomic_uintptr_t __bsan_bor_tag_ctr{3};

// Accumulates the number of tree-node visits performed by the Rust runtime
// since the last garbage collection request
SANITIZER_INTERFACE_ATTRIBUTE
atomic_uintptr_t __bsan_visits_since_gc{0};

namespace __bsan {

// Is the runtime initialized?
bool bsan_inited = false;

// Is the initializer for the runtime executing?
bool bsan_init_running = false;

// Allocates a new borrow tag.
BorTag NewBorTag() {
  return atomic_fetch_add(&__bsan_bor_tag_ctr, 1, memory_order_relaxed);
}

// Asks the global context to run the garbage collector once the Rust runtime
// has reported at least `visits_per_gc` tree-node visits since the last
// request, then resets the counter. Concurrent requests across threads are
// coalesced by `RequestGC`.
static void MaybeRequestGC() {
  uptr interval = flags()->visits_per_gc;
  if (interval == 0)
    return;
  if (atomic_load(&__bsan_visits_since_gc, memory_order_relaxed) >= interval) {
    atomic_store(&__bsan_visits_since_gc, 0, memory_order_relaxed);
    global_ctx()->RequestGC();
  }
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
Provenance *GetParamSlot(uptr idx) { return __bsan_shadow_stack - (idx + 1); }

// Returns a pointer to the slot on the shadow stack at the given index.
// The shadow stack grows downward, so we subtract by the given index
// plus one to adjust the for the the zero-th slot.
Provenance *GetRetValSlot(uptr idx) {
  Provenance *slot = GetParamSlot(idx);
  __bsan_shadow_stack = slot;
  return slot;
}

// Clears the provenance from the given stack slot.
void ClearSlot(uptr Idx) { *GetParamSlot(Idx) = OMNIVALID; }

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
  if (__bsan_marker == kTrustedMarker) {
    __bsan_marker = 0;
    return true;
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
  BsanThread *t = CurrentThread();
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
  new (global_ctx()) GlobalContext();

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

  bsan_init_running = false;
  bsan_inited = true;
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
  bool trusted =
      (__bsan_marker == current_fn || __bsan_marker == kTrustedMarker);
  if (!trusted) {
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

SANITIZER_WEAK_ATTRIBUTE
void __bsan_retag_impl(void *object_addr, uptr access_size, u8 flags,
                       const uptr im_data[2], uptr im_len,
                       const uptr pin_data[2], uptr pin_len, Node *node,
                       void *dest, Span pc, bool checked);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_retag(void *object_addr, uptr access_size, u8 flags,
                  const uptr im_data[2], uptr im_len, const uptr pin_data[2],
                  uptr pin_len, Node *node, void *dest, bool checked) {
  const bool known = ProvIsKnown(node);
  if (!bsan_inited || bsan_init_running || !known) {
    *(Provenance *)(dest) = known ? node : OMNIVALID;
    return;
  }
  if (__bsan_retag_impl) {
    GET_SPAN;
    InterceptorBarrier Barrier;
    Provenance prov;
    __bsan_retag_impl(object_addr, access_size, flags, im_data, im_len,
                      pin_data, pin_len, node, &prov, span, checked);
    HANDLE_ERROR;
    *(Provenance *)(dest) = prov;
    // A retag mints a fresh provenance value with no references yet; record it
    // in this thread's zero-count set as a collection candidate.
    CurrentThread()->AcquireProvenance(prov);
    MaybeRequestGC();
  }
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_read_impl(void *ptr, uptr access_size, Node *node, Span pc,
                      bool checked);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_read(void *ptr, uptr access_size, Node *node, bool checked) {
  // Skip before init, and skip unaligned shadow noise (not a sentinel / Node*).
  if (!bsan_inited || bsan_init_running || !ProvIsKnown(node)) {
    return;
  }
  if (__bsan_read_impl) {
    GET_SPAN;
    InterceptorBarrier Barrier;
    __bsan_read_impl(ptr, access_size, node, span, checked);
    HANDLE_ERROR;
  }
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_write_impl(void *ptr, uptr access_size, Node *node, Span pc,
                       bool checked);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_write(void *ptr, uptr access_size, Node *node, bool checked) {
  if (!bsan_inited || bsan_init_running || !ProvIsKnown(node)) {
    return;
  }
  if (__bsan_write_impl) {
    GET_SPAN;
    InterceptorBarrier Barrier;
    __bsan_write_impl(ptr, access_size, node, span, checked);
    HANDLE_ERROR;
  }
}

SANITIZER_WEAK_ATTRIBUTE
bool __bsan_rc_inc_impl(Node *node);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_rc_inc(Node *node) {
  // Shadow can be touched while copying libc structs during very early
  // init (before `bsan_inited`). Skip RC until the runtime is ready.
  if (!bsan_inited || bsan_init_running || !ProvIsConcrete(node)) {
    return;
  }
  if (__bsan_rc_inc_impl) {
    InterceptorBarrier Barrier;
    __bsan_rc_inc_impl(node);
  }
}

SANITIZER_WEAK_ATTRIBUTE
bool __bsan_rc_dec_impl(Node *node);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_rc_dec(Node *node) {
  if (!bsan_inited || bsan_init_running || !ProvIsConcrete(node)) {
    return;
  }
  if (__bsan_rc_dec_impl) {
    InterceptorBarrier Barrier;
    if (__bsan_rc_dec_impl(node)) {
      CurrentThread()->AcquireProvenance(node);
    }
  }
}

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_shadow_clear(void *dest, uptr size) { ClearShadow(dest, size); }

SANITIZER_WEAK_ATTRIBUTE
Node *__bsan_reserve_stack_slot_impl();

SANITIZER_INTERFACE_ATTRIBUTE
Node *__bsan_reserve_stack_slot() {
  if (__bsan_reserve_stack_slot_impl) {
    InterceptorBarrier Barrier;
    return __bsan_reserve_stack_slot_impl();
  }
  return nullptr;
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_destroy_stack_slot_impl(Node *slot);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_destroy_stack_slot(Node *slot) {
  if (__bsan_destroy_stack_slot_impl) {
    InterceptorBarrier Barrier;
    __bsan_destroy_stack_slot_impl(slot);
  }
}

SANITIZER_WEAK_ATTRIBUTE
BorTag __bsan_node_tag_impl(Node *node);

// Prefer the Rust RT when linked. CRT-only builds fall back to reading the
// first word of Node (BorTag), which #[repr(C)] guarantees.
SANITIZER_INTERFACE_ATTRIBUTE
BorTag __bsan_node_tag(Node *node) {
  if (__bsan_node_tag_impl) {
    return __bsan_node_tag_impl(node);
  }
  return *reinterpret_cast<BorTag *>(node);
}

SANITIZER_WEAK_ATTRIBUTE
Node *__bsan_alloc_impl(void *base_addr, uptr size, BorTag bor_tag, Span pc);

SANITIZER_INTERFACE_ATTRIBUTE
Node *__bsan_alloc(void *base_addr, uptr size, BorTag bor_tag, Span pc) {
  if (__bsan_alloc_impl) {
    InterceptorBarrier Barrier;
    Node *node = __bsan_alloc_impl(base_addr, size, bor_tag, pc);
    CurrentThread()->AcquireProvenance(node);
    return node;
  } else {
    return nullptr;
  }
}

SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE void
__bsan_dealloc(void *ptr, Node *node, Span pc, bool checked) {}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_alloc_stack_impl(void *base_addr, uptr size, BorTag bor_tag,
                             Node *node, Span pc);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_alloc_stack(void *base_addr, uptr size, BorTag bor_tag,
                        Node *node) {
  if (__bsan_alloc_stack_impl) {
    GET_SPAN;
    InterceptorBarrier Barrier;
    __bsan_alloc_stack_impl(base_addr, size, bor_tag, node, span);
    HANDLE_ERROR;
  }
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_dealloc_stack_impl(Node *node, Span pc);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_dealloc_stack(void *ptr, Node *node) {
  if (__bsan_dealloc_stack_impl) {
    GET_SPAN;
    InterceptorBarrier Barrier;
    __bsan_dealloc_stack_impl(node, span);
    HANDLE_ERROR;
  }
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_expose_prov_impl(Node *node);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_expose_prov(Node *node) {
  if (__bsan_expose_prov_impl) {
    InterceptorBarrier Barrier;
    __bsan_expose_prov_impl(node);
  }
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_protector_end_impl(Node *node, Span pc);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_pop_frame(const Provenance *frame_start, uptr prot,
                      uptr alloca_vec_size) {
  if (__bsan_protector_end_impl && __bsan_destroy_stack_slot_impl &&
      __bsan_dealloc_stack_impl) {
    GET_SPAN;
    InterceptorBarrier Barrier;
    for (uptr i = 0; i < prot + alloca_vec_size; i++) {
      const Provenance prov = frame_start[i];
      if (i < prot) {
        __bsan_protector_end_impl(prov, span);
      } else {
        __bsan_dealloc_stack_impl(prov, span);
        __bsan_destroy_stack_slot_impl(prov);
      }
    }
  }
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_print(Node *node) {}

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_debug_print(void *ptr) {
  Provenance *slot = GetParamSlot(0);
  InterceptorBarrier barrier;
  __bsan_print(*slot);
}

SANITIZER_WEAK_ATTRIBUTE void __bsan_print_borrow_state(Node *node) {}

void __bsan_debug_print_borrow_state(void *ptr) {
  Provenance *slot = GetParamSlot(0);
  InterceptorBarrier barrier;
  __bsan_print_borrow_state(*slot);
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_tree_size(Node *node) {}

void __bsan_debug_tree_size(void *ptr) {
  Provenance *slot = GetParamSlot(0);
  InterceptorBarrier barrier;
  __bsan_tree_size(*slot);
}

SANITIZER_WEAK_ATTRIBUTE
void __bsan_snapshot(Node *node) {}

void __bsan_debug_snapshot(void *ptr) {
  Provenance *slot = GetParamSlot(0);
  InterceptorBarrier barrier;
  __bsan_snapshot(*slot);
}

SANITIZER_WEAK_ATTRIBUTE void __bsan_print_diff(Node *node) {}

void __bsan_debug_print_diff(void *ptr) {
  Provenance *slot = GetParamSlot(0);
  InterceptorBarrier barrier;
  __bsan_print_diff(*slot);
}

// Asks the global state to run the garbage collector. Any thread may call this;
// concurrent requests are coalesced into a single collection.
SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_request_gc() { global_ctx()->RequestGC(); }

void __bsan_abort() { Die(); }

} // extern "C"
