#ifndef BSAN_INTERFACE_H
#define BSAN_INTERFACE_H
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"

using namespace __sanitizer;
using namespace __bsan;

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_deinit();
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_init();
extern "C" SANITIZER_INTERFACE_ATTRIBUTE uptr __bsan_mark_tls();
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_validate_param_tls(uptr len);
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_validate_retval_tls(uptr len, uptr prev_marker);
// Weak (de)init attributes
extern "C" SANITIZER_WEAK_ATTRIBUTE void __bsan_deinit();
extern "C" SANITIZER_WEAK_ATTRIBUTE void __bsan_init();
extern "C" SANITIZER_WEAK_ATTRIBUTE void __bsan_reportError();
extern "C" SANITIZER_WEAK_ATTRIBUTE void __bsan_internal_init();
extern "C" SANITIZER_WEAK_ATTRIBUTE void __bsan_internal_deinit();

// Tagging operations
extern "C" SANITIZER_WEAK_ATTRIBUTE BorTag
__bsan_retag(void *object_addr, usize access_size, u64 perm, BorTag bor_tag,
             AllocInfo *alloc_info, const usize im_data[2], usize im_len);
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_pop_frame(const Provenance *frame_start, usize protected_);
extern "C" SANITIZER_WEAK_ATTRIBUTE void __bsan_read(void *ptr,
                                                     usize access_size,
                                                     BorTag bor_tag,
                                                     AllocInfo *alloc_info);
extern "C" SANITIZER_WEAK_ATTRIBUTE void __bsan_write(void *ptr,
                                                      usize access_size,
                                                      BorTag bor_tag,
                                                      AllocInfo *alloc_info);
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_dealloc(void *ptr, BorTag bor_tag, AllocInfo *alloc_info, bool weak);
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_shadow_copy(void *src, void *dest, usize access_size);
extern "C" SANITIZER_WEAK_ATTRIBUTE void __bsan_shadow_clear(void *dest,
                                                             usize access_size);
extern "C" SANITIZER_WEAK_ATTRIBUTE AllocInfo *__bsan_reserve_stack_slot();
// TODO: __bsan_shadow_load
// TODO: __bsan_shadow_store
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_destroy_stack_slot(AllocInfo *slot);
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_alloc_stack(void *base_addr, usize size, BorTag bor_tag,
                   AllocInfo *alloc_info);

// Debuging
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_assert_null(BorTag bor_tag, AllocInfo *alloc_info);
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_assert_wildcard(BorTag bor_tag, AllocInfo *alloc_info);
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_assert_valid(BorTag bor_tag, AllocInfo *alloc_info);
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_assert_invalid(BorTag bor_tag, AllocInfo *alloc_info);
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_print(BorTag bor_tag, AllocInfo *alloc_info);
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_print_borrow_state(BorTag bor_tag, AllocInfo *alloc_info);
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_tree_size(BorTag bor_tag, AllocInfo *alloc_info);
extern "C" SANITIZER_WEAK_ATTRIBUTE void
__bsan_debug_print_diff(BorTag bor_tag, AllocInfo *alloc_info);

#endif
