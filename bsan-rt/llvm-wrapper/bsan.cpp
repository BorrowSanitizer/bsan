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
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL uptr __BSAN_TRUST = 0;

THREADLOCAL uptr BSAN_TLS_MARKER = 0;

bool BSAN_INITED = false;
bool BSAN_INIT_RUNNING;
bool BSAN_DEINIT_RUNNING;

const Provenance WILDCARD = {0, nullptr};

namespace __bsan {

Provenance *GetArgSlot(uptr Idx) { return &__BSAN_PARAM_TLS[Idx]; }
Provenance *GetRetValSlot(uptr Idx) { return &__BSAN_RETVAL_TLS[Idx]; }

void ClearArgSlot(uptr Idx) { __BSAN_PARAM_TLS[Idx] = WILDCARD; }
void ClearRetValSlot(uptr Idx) { __BSAN_RETVAL_TLS[Idx] = WILDCARD; }

void PrintStackTrace(StackTrace &stack) {
  Printf("stack backtrace:\n");
  InternalScopedString frame_desc;
  for (uptr i = 0; i < stack.size; ++i) {
    uptr pc = stack.trace[i];
    SymbolizedStackHolder symbolized_stack(
        Symbolizer::GetOrInit()->SymbolizePC(pc));
    const SymbolizedStack *frame = symbolized_stack.get();
    if (frame) {
      StackTracePrinter::GetOrInit()->RenderFrame(
          &frame_desc, "%n: %f\n      at %S", i, frame->info.address,
          &frame->info, common_flags()->symbolize_vs_style,
          common_flags()->strip_path_prefix);
      Printf("%s\n", frame_desc.data());
      frame_desc.clear();
    }
  }
}

} // namespace __bsan

uptr unwind(uptr bp, uptr len) {
  if (!bp || len == 0) {
    return bp;
  } else {
    return unwind(*(uptr *)bp, len - 1);
  }
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
SANITIZER_INTERFACE_ATTRIBUTE uptr __bsan_mark_tls() {
  uptr prev_pc = BSAN_TLS_MARKER;
  BSAN_TLS_MARKER = unwind(GET_CURRENT_FRAME(), 1);
  return prev_pc;
}

/// Clears the parameter provenance array if the frame pointer of the
/// caller of the current function does not match the boundary marker,
/// indicating that we crossed into uninstrumented code. If it does match the
/// boundary marker, then we reset the boundary marker to null, signaling that
/// when we are back within the caller, we can trust the provenance array for
/// the return value.
SANITIZER_INTERFACE_ATTRIBUTE void __bsan_validate_param_tls(uptr len) {
  uptr marker = unwind(GET_CURRENT_FRAME(), 2);
  if (marker == BSAN_TLS_MARKER) {
    BSAN_TLS_MARKER = 0;
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
SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_validate_retval_tls(uptr len, uptr prev_marker) {
  if (BSAN_TLS_MARKER) {
    for (uptr i = 0; i < len; ++i) {
      *GetRetValSlot(i) = WILDCARD;
    }
  }
  BSAN_TLS_MARKER = prev_marker;
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
  Location loc = LOCATION();
  BorTag tag =
      __bsan_retag_impl(object_addr, access_size, is_prot, is_freeze, is_unpin,
                        ptr_kind, im_data, im_len, bor_tag, alloc_info, loc);
  HANDLE_ERROR(loc);
  return tag;
}

SANITIZER_WEAK_ATTRIBUTE BorTag
__bsan_retag_impl(void *object_addr, uptr access_size, u8 is_prot, u8 is_freeze,
                  u8 is_unpin, u8 ptr_kind, const uptr im_data[2], uptr im_len,
                  BorTag bor_tag, AllocInfo *alloc_info, Location loc) {
  return bor_tag;
}

SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_pop_frame(const Provenance *frame_start, uptr prot) {
  Location loc = LOCATION();
  __bsan_pop_frame_impl(frame_start, prot, loc);
  HANDLE_ERROR(loc);
}

SANITIZER_WEAK_ATTRIBUTE void
__bsan_pop_frame_impl(const Provenance *frame_start, uptr prot, Location loc) {}

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_read(void *ptr, uptr access_size,
                                               BorTag bor_tag,
                                               AllocInfo *alloc_info) {
  Location loc = LOCATION();
  __bsan_read_impl(ptr, access_size, bor_tag, alloc_info, loc);
  HANDLE_ERROR(loc);
}

SANITIZER_WEAK_ATTRIBUTE void __bsan_read_impl(void *ptr, uptr access_size,
                                               BorTag bor_tag,
                                               AllocInfo *alloc_info,
                                               Location loc) {}

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_write(void *ptr, uptr access_size,
                                                BorTag bor_tag,
                                                AllocInfo *alloc_info) {
  Location loc = LOCATION();
  __bsan_write_impl(ptr, access_size, bor_tag, alloc_info, loc);
  HANDLE_ERROR(loc);
}

SANITIZER_WEAK_ATTRIBUTE void __bsan_write_impl(void *ptr, uptr access_size,
                                                BorTag bor_tag,
                                                AllocInfo *alloc_info,
                                                Location loc) {}

SANITIZER_WEAK_ATTRIBUTE void
__bsan_shadow_transfer(void *dest, const void *src, uptr access_size) {}
SANITIZER_WEAK_ATTRIBUTE void __bsan_shadow_clear(void *dest,
                                                  uptr access_size) {}
SANITIZER_WEAK_ATTRIBUTE AllocInfo *__bsan_reserve_stack_slot() {
  return nullptr;
}
SANITIZER_WEAK_ATTRIBUTE void __bsan_destroy_stack_slot(AllocInfo *slot) {}

SANITIZER_WEAK_ATTRIBUTE AllocInfo *__bsan_alloc(void *base_addr, uptr size,
                                                 BorTag bor_tag, Location loc) {
  return nullptr;
}
SANITIZER_WEAK_ATTRIBUTE void __bsan_dealloc(void *ptr, BorTag bor_tag,
                                             AllocInfo *alloc_info,
                                             Location loc) {}

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_alloc_stack(void *base_addr,
                                                      uptr size, BorTag bor_tag,
                                                      AllocInfo *alloc_info) {
  Location loc = LOCATION();
  __bsan_alloc_stack_impl(base_addr, size, bor_tag, alloc_info, loc);
  HANDLE_ERROR(loc);
}

SANITIZER_WEAK_ATTRIBUTE void __bsan_alloc_stack_impl(void *base_addr,
                                                      uptr size, BorTag bor_tag,
                                                      AllocInfo *alloc_info,
                                                      Location loc) {}

SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_dealloc_stack(void *ptr, BorTag bor_tag, AllocInfo *alloc_info) {
  Location loc = LOCATION();
  __bsan_dealloc_stack_impl(ptr, bor_tag, alloc_info, loc);
  HANDLE_ERROR(loc);
}

SANITIZER_WEAK_ATTRIBUTE void __bsan_dealloc_stack_impl(void *ptr,
                                                        BorTag bor_tag,
                                                        AllocInfo *alloc_info,
                                                        Location loc) {}
// Weak Debugging
SANITIZER_WEAK_ATTRIBUTE void __bsan_debug_assert_null(BorTag bor_tag,
                                                       AllocInfo *alloc_info) {}
SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_assert_wildcard(BorTag bor_tag, AllocInfo *alloc_info) {}
SANITIZER_WEAK_ATTRIBUTE void __bsan_debug_assert_valid(BorTag bor_tag,
                                                        AllocInfo *alloc_info) {
}
SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_assert_invalid(BorTag bor_tag, AllocInfo *alloc_info) {}
SANITIZER_WEAK_ATTRIBUTE void __bsan_debug_print(BorTag bor_tag,
                                                 AllocInfo *alloc_info) {}
SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_print_borrow_state(BorTag bor_tag, AllocInfo *alloc_info) {}
SANITIZER_WEAK_ATTRIBUTE void __bsan_debug_tree_size(BorTag bor_tag,
                                                     AllocInfo *alloc_info) {}
SANITIZER_WEAK_ATTRIBUTE void __bsan_debug_print_diff(BorTag bor_tag,
                                                      AllocInfo *alloc_info) {}

SANITIZER_WEAK_ATTRIBUTE void __bsan_debug_get_provenance(void *ptr, BorTag* bor_tag,
                                                      AllocInfo **alloc_info) {}

} // extern "C"
