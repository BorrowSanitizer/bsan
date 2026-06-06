#ifndef BSAN_INTERFACE_INTERNAL_H
#define BSAN_INTERFACE_INTERNAL_H

#include "sanitizer_common/sanitizer_internal_defs.h"
using namespace __sanitizer;

// Private BorrowSanitizer interface
extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_init();

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_deinit();

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_abort();

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_memmove(void *dest, const void *src, uptr n);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_memcpy(void *dest, const void *src, uptr n);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_memset(void *s, int c, uptr n);

SANITIZER_INTERFACE_ATTRIBUTE
u32 __bsan_symbolize_pc(uptr pc, char *file_buf, uptr file_buf_len, u32 *line,
                        u32 *column);

SANITIZER_INTERFACE_ATTRIBUTE
uptr __bsan_read_file(const char *path, char **file_buf, uptr *file_buf_len);

SANITIZER_WEAK_ATTRIBUTE
AllocInfo *__bsan_alloc(void *base_addr, uptr size, BorTag bor_tag, Span pc);

SANITIZER_WEAK_ATTRIBUTE
void __bsan_dealloc(void *ptr, BorTag bor_tag, AllocInfo *alloc_info, Span pc);

SANITIZER_WEAK_ATTRIBUTE
void __bsan_local_init(Provenance **prov);

SANITIZER_WEAK_ATTRIBUTE
void __bsan_local_deinit();

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_read(void *ptr, uptr access_size, BorTag bor_tag,
                 AllocInfo *alloc_info);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_write(void *ptr, uptr access_size, BorTag bor_tag,
                  AllocInfo *alloc_info);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_shadow_transfer(void *dest, const void *src, uptr access_size);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_shadow_clear(void *dest, uptr access_size);

SANITIZER_INTERFACE_ATTRIBUTE
Provenance *__bsan_shadow(void *addr);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_rc_store(BorTag bor_tag, AllocInfo *alloc_info, Provenance *dest);

} // extern "C"

#endif