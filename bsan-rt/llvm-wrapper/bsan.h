#ifndef BSAN_H
#define BSAN_H
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_stacktrace.h"

using __sanitizer::StackTrace;
using __sanitizer::u32;
using __sanitizer::u64;
using __sanitizer::u8;
using __sanitizer::uptr;

extern THREADLOCAL uptr __BSAN_HAD_ERROR;
extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL uptr __BSAN_TRUST;
extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL void *__BSAN_PROV_STACK;
extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL void *__BSAN_TLS_MARKER;

typedef uptr Span;

#define GET_SPAN uptr span = GET_CALLER_PC();

#define GET_SPAN_PC_BP                                                         \
  GET_SPAN;                                                                    \
  uptr pc = StackTrace::GetCurrentPc();                                        \
  uptr bp = GET_CURRENT_FRAME();

#define HANDLE_ERROR(pc, bp)                                                   \
  if (__BSAN_HAD_ERROR) {                                                      \
    UNINITIALIZED BufferedStackTrace stack;                                    \
    stack.Unwind(pc, bp, nullptr, true, 4);                                    \
    PrintStackTrace(stack);                                                    \
    Die();                                                                     \
  }

typedef uptr BorTag;
struct AllocInfo;
struct Provenance {
  BorTag Tag;
  AllocInfo *Info;
};

// Private BorrowSanitizer interface
extern "C" {

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_init();

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_deinit();

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_abort();

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_memmove(void *dest, const void *src,
                                                  uptr n);

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_memcpy(void *dest, const void *src,
                                                 uptr n);

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_memset(void *s, int c, uptr n);

SANITIZER_INTERFACE_ATTRIBUTE void *__bsan_mark_tls(void *callee);

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_validate_param_tls(void *current_fn,
                                                             uptr len);

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_validate_retval_tls(void *prev_marker,
                                                              uptr len);

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_print_stack_trace(Span pc,
                                                            uptr depth);
SANITIZER_INTERFACE_ATTRIBUTE uptr __bsan_get_top_frame_pc(uptr pc);
SANITIZER_INTERFACE_ATTRIBUTE u32 __bsan_stack_depot_put(uptr pc, uptr bp,
                                                         u32 max_depth);
SANITIZER_INTERFACE_ATTRIBUTE u32 __bsan_symbolize_pc(uptr pc, char *file_buf,
                                                      uptr file_buf_len,
                                                      u32 *line, u32 *column);
SANITIZER_INTERFACE_ATTRIBUTE uptr __bsan_read_file(const char *path,
                                                    char **file_buf,
                                                    uptr *file_buf_len);

} // extern "C"

extern "C" {

SANITIZER_WEAK_ATTRIBUTE AllocInfo *__bsan_alloc(void *base_addr, uptr size,
                                                 BorTag bor_tag, Span pc);

SANITIZER_WEAK_ATTRIBUTE void __bsan_dealloc(void *ptr, BorTag bor_tag,
                                             AllocInfo *alloc_info, Span pc);

SANITIZER_INTERFACE_ATTRIBUTE BorTag
__bsan_retag(void *object_addr, uptr access_size, u8 is_prot, u8 is_freeze,
             u8 is_unpin, u8 ptr_kind, const uptr im_data[2], uptr im_len,
             BorTag bor_tag, AllocInfo *alloc_info);

SANITIZER_WEAK_ATTRIBUTE BorTag
__bsan_retag_impl(void *object_addr, uptr access_size, u8 is_prot, u8 is_freeze,
                  u8 is_unpin, u8 ptr_kind, const uptr im_data[2], uptr im_len,
                  BorTag bor_tag, AllocInfo *alloc_info, Span pc);

SANITIZER_WEAK_ATTRIBUTE void __bsan_internal_init();

SANITIZER_WEAK_ATTRIBUTE void __bsan_internal_deinit();

SANITIZER_WEAK_ATTRIBUTE BorTag __bsan_new_bor_tag();

SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_pop_frame(const Provenance *frame_start, uptr protected_);

SANITIZER_WEAK_ATTRIBUTE void
__bsan_pop_frame_impl(const Provenance *frame_start, uptr protected_, Span pc);

SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_read(void *ptr, uptr access_size, BorTag bor_tag, AllocInfo *alloc_info);

SANITIZER_WEAK_ATTRIBUTE void __bsan_read_impl(void *ptr, uptr access_size,
                                               BorTag bor_tag,
                                               AllocInfo *alloc_info, Span pc);

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_write(void *ptr, uptr access_size,
                                                BorTag bor_tag,
                                                AllocInfo *alloc_info);

SANITIZER_WEAK_ATTRIBUTE void __bsan_write_impl(void *ptr, uptr access_size,
                                                BorTag bor_tag,
                                                AllocInfo *alloc_info, Span pc);

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_alloc_stack(void *base_addr,
                                                      uptr size, BorTag bor_tag,
                                                      AllocInfo *alloc_info);

SANITIZER_WEAK_ATTRIBUTE void __bsan_alloc_stack_impl(void *base_addr,
                                                      uptr size, BorTag bor_tag,
                                                      AllocInfo *alloc_info,
                                                      Span pc);

SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_dealloc_stack(void *ptr, BorTag bor_tag, AllocInfo *alloc_info);

SANITIZER_WEAK_ATTRIBUTE void __bsan_dealloc_stack_impl(void *ptr,
                                                        BorTag bor_tag,
                                                        AllocInfo *alloc_info,
                                                        Span pc);

SANITIZER_WEAK_ATTRIBUTE void
__bsan_shadow_transfer(void *dest, const void *src, uptr access_size);

SANITIZER_WEAK_ATTRIBUTE void __bsan_shadow_clear(void *dest, uptr access_size);

SANITIZER_WEAK_ATTRIBUTE AllocInfo *__bsan_reserve_stack_slot();

SANITIZER_WEAK_ATTRIBUTE void __bsan_destroy_stack_slot(AllocInfo *slot);

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_debug_print(void *ptr);
SANITIZER_INTERFACE_ATTRIBUTE void __bsan_debug_print_borrow_state(void *ptr);
SANITIZER_INTERFACE_ATTRIBUTE void __bsan_debug_tree_size(void *ptr);
SANITIZER_INTERFACE_ATTRIBUTE void __bsan_debug_print_diff(void *ptr);
SANITIZER_INTERFACE_ATTRIBUTE void __bsan_debug_snapshot(void *ptr);

} // extern "C"

extern THREADLOCAL void *BSAN_CURR_THREAD;
extern bool BSAN_INITED;
extern bool BSAN_INIT_RUNNING;
extern bool BSAN_DEINIT_RUNNING;

namespace __bsan {
void BsanTSDInit();
void InitializeInterceptors();
Provenance *GetArgSlot(uptr Idx);
Provenance *GetRetValSlot(uptr Idx);
void ClearArgSlot(uptr Idx);
void ClearRetValSlot(uptr Idx);
void PrintStackTrace(StackTrace &stack);
} // namespace __bsan

#endif // BSAN_H
