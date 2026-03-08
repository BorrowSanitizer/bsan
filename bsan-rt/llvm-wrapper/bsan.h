#ifndef BSAN_H
#define BSAN_H
#include "sanitizer_common/sanitizer_internal_defs.h"

using __sanitizer::u32;
using __sanitizer::u64;
using __sanitizer::uptr;

extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL uptr __BSAN_TRUST;
extern SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL void *__BSAN_PROV_STACK;

typedef uptr BorTag;
typedef const uptr FramePtr;
struct AllocInfo;
struct Provenance {
  BorTag Tag;
  AllocInfo *Info;
};

// Private BorrowSanitizer interface
extern "C" {

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_init();

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_deinit();

SANITIZER_INTERFACE_ATTRIBUTE void *__bsan_memmove(void *dest, const void *src,
                                                   uptr n);

SANITIZER_INTERFACE_ATTRIBUTE void *__bsan_memcpy(void *dest, const void *src,
                                                  uptr n);

SANITIZER_INTERFACE_ATTRIBUTE void *__bsan_memset(void *s, int c, uptr n);

SANITIZER_INTERFACE_ATTRIBUTE uptr __bsan_mark_tls();

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_validate_param_tls(uptr len);

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_validate_retval_tls(uptr len,
                                                              uptr prev_marker);

SANITIZER_INTERFACE_ATTRIBUTE void __bsan_print_current_stack_trace();
SANITIZER_INTERFACE_ATTRIBUTE void __bsan_print_stack_trace(u32 stackID);
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

SANITIZER_WEAK_ATTRIBUTE BorTag
__bsan_retag(void *object_addr, uptr access_size, u64 perm, BorTag bor_tag,
             AllocInfo *alloc_info, const uptr im_data[2], uptr im_len);

SANITIZER_WEAK_ATTRIBUTE void __bsan_internal_init();

SANITIZER_WEAK_ATTRIBUTE void __bsan_internal_deinit();

SANITIZER_WEAK_ATTRIBUTE BorTag __bsan_new_bor_tag();

SANITIZER_WEAK_ATTRIBUTE void __bsan_pop_frame(const Provenance *frame_start,
                                               uptr protected_);

SANITIZER_WEAK_ATTRIBUTE void
__bsan_read(void *ptr, uptr access_size, BorTag bor_tag, AllocInfo *alloc_info);

SANITIZER_WEAK_ATTRIBUTE void __bsan_write(void *ptr, uptr access_size,
                                           BorTag bor_tag,
                                           AllocInfo *alloc_info);

SANITIZER_WEAK_ATTRIBUTE AllocInfo *__bsan_alloc(void *base_addr, uptr size,
                                                 BorTag bor_tag);

SANITIZER_WEAK_ATTRIBUTE void __bsan_dealloc(void *ptr, BorTag bor_tag,
                                             AllocInfo *alloc_info);

SANITIZER_WEAK_ATTRIBUTE void __bsan_alloc_stack(void *base_addr, uptr size,
                                                 BorTag bor_tag,
                                                 AllocInfo *alloc_info);

SANITIZER_WEAK_ATTRIBUTE void __bsan_dealloc_stack(void *ptr, BorTag bor_tag,
                                                   AllocInfo *alloc_info);

SANITIZER_WEAK_ATTRIBUTE void
__bsan_shadow_transfer(void *dest, const void *src, uptr access_size);

SANITIZER_WEAK_ATTRIBUTE void __bsan_shadow_clear(void *dest, uptr access_size);

SANITIZER_WEAK_ATTRIBUTE AllocInfo *__bsan_reserve_stack_slot();

SANITIZER_WEAK_ATTRIBUTE void __bsan_destroy_stack_slot(AllocInfo *slot);

SANITIZER_WEAK_ATTRIBUTE void __bsan_debug_assert_null(BorTag bor_tag,
                                                       AllocInfo *alloc_info);
SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_assert_wildcard(BorTag bor_tag, AllocInfo *alloc_info);
SANITIZER_WEAK_ATTRIBUTE void __bsan_debug_assert_valid(BorTag bor_tag,
                                                        AllocInfo *alloc_info);
SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_assert_invalid(BorTag bor_tag, AllocInfo *alloc_info);
SANITIZER_WEAK_ATTRIBUTE void __bsan_debug_print(BorTag bor_tag,
                                                 AllocInfo *alloc_info);
SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_print_borrow_state(BorTag bor_tag, AllocInfo *alloc_info);
SANITIZER_WEAK_ATTRIBUTE void __bsan_debug_tree_size(BorTag bor_tag,
                                                     AllocInfo *alloc_info);
SANITIZER_WEAK_ATTRIBUTE void __bsan_debug_print_diff(BorTag bor_tag,
                                                      AllocInfo *alloc_info);

} // extern "C"

extern THREADLOCAL void *BSAN_CURR_THREAD;
extern THREADLOCAL uptr BSAN_TLS_MARKER;
extern bool BSAN_INITED;
extern bool BSAN_INIT_RUNNING;
extern bool BSAN_DEINIT_RUNNING;

namespace __bsan {
void BsanTSDInit();
void InitializeInterceptors();
Provenance *GetArgSlot(uptr Idx);
Provenance *GetRetValSlot(uptr Idx);
} // namespace __bsan

#endif // BSAN_H
