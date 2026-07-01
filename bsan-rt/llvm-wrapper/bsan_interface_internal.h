#ifndef BSAN_INTERFACE_INTERNAL_H
#define BSAN_INTERFACE_INTERNAL_H

#include "sanitizer_common/sanitizer_internal_defs.h"
using namespace __sanitizer;

// Private BorrowSanitizer interface
extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_init();

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_abort();

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_memmove(void *dest, const void *src, uptr n);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_memcpy(void *dest, const void *src, uptr n);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_memset(void *s, int c, uptr n);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_shadow_clear(void *dest, uptr size);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_rc_dec(BorTag Tag, AllocInfo *Info);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_rc_inc(BorTag Tag, AllocInfo *Info);

SANITIZER_INTERFACE_ATTRIBUTE
u32 __bsan_symbolize_pc(uptr pc, char *file_buf, uptr file_buf_len, u32 *line,
                        u32 *column);

SANITIZER_INTERFACE_ATTRIBUTE
uptr __bsan_read_file(const char *path, char **file_buf, uptr *file_buf_len);

SANITIZER_WEAK_ATTRIBUTE
AllocInfo *__bsan_alloc(void *base_addr, uptr size, BorTag bor_tag, Span pc);

SANITIZER_WEAK_ATTRIBUTE
void __bsan_dealloc(void *ptr, BorTag bor_tag, AllocInfo *alloc_info, Span pc);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_read(void *ptr, uptr access_size, BorTag bor_tag,
                 AllocInfo *alloc_info);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_write(void *ptr, uptr access_size, BorTag bor_tag,
                  AllocInfo *alloc_info);

// Records a zero-count (alloc_info, bor_tag) pair in the zero-count table.
// Called by the Rust core when a node's reference count reaches zero.
SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_release(BorTag bor_tag, AllocInfo *alloc_info);

// Requests a garbage collection. Any thread may call this.
SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_request_gc();

// Prunes a list of nodes from a tree that correspond to the tags in the list.
// Returns true if every tag has been pruned, indicating that the allocation
// metadata object can also be reclaimed.
SANITIZER_WEAK_ATTRIBUTE
bool __bsan_prune(AllocInfo *Info, const BorTag *tags, uptr len);

// Frees an `AllocInfo` object. The pointer must be nonnull and unreachable
// in shadow memory.
SANITIZER_WEAK_ATTRIBUTE
void __bsan_eject(AllocInfo *Info);

} // extern "C"

#endif
