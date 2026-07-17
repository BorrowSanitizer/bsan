#ifndef BSAN_INTERFACE_INTERNAL_H
#define BSAN_INTERFACE_INTERNAL_H

#include "bsan_dense_alloc.h"
#include "sanitizer_common/sanitizer_internal_defs.h"

using namespace __bsan;
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
void __bsan_rc_dec(Provenance prov);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_rc_inc(Provenance prov);

SANITIZER_INTERFACE_ATTRIBUTE
u32 __bsan_symbolize_pc(uptr pc, char *file_buf, uptr file_buf_len, u32 *line,
                        u32 *column);

SANITIZER_INTERFACE_ATTRIBUTE
uptr __bsan_read_file(const char *path, char **file_buf, uptr *file_buf_len);

SANITIZER_WEAK_ATTRIBUTE
Block *__bsan_alloc(void *base_addr, uptr size, BorTag bor_tag, Span pc);

SANITIZER_WEAK_ATTRIBUTE
void __bsan_dealloc(void *ptr, BorTag bor_tag, Block *alloc_info, Span pc,
                    bool checked);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_read(void *ptr, uptr access_size, Provenance prov, bool checked);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_write(void *ptr, uptr access_size, Provenance prov, bool checked);

// Records a zero-count (alloc_info, bor_tag) pair in the zero-count table.
// Called by the Rust core when a node's reference count reaches zero.
SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_release(BorTag bor_tag, Block *alloc_info);

// Requests a garbage collection. Any thread may call this.
SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_request_gc();

// Prunes a list of nodes from a tree that correspond to the tags in the list.
// Returns true if every tag has been pruned, indicating that the allocation
// metadata object can also be reclaimed.
SANITIZER_WEAK_ATTRIBUTE
bool __bsan_prune(Block *Info, BorTag *tags, uptr len);

// Frees an `AllocInfo` object. The pointer must be nonnull and unreachable
// in shadow memory.
SANITIZER_WEAK_ATTRIBUTE
void __bsan_eject(Block *Info);

// Allocates one uninitialized `AllocInfo` slot from the C++ slab allocator
// (`bsan_dense_alloc.h`). Never returns null. The Rust runtime constructs the
// `AllocInfo` in place in the returned storage.
SANITIZER_INTERFACE_ATTRIBUTE
Block *__bsan_alloc_metadata();

// Returns an `AllocInfo` slot to the C++ slab allocator. The `AllocInfo` must
// already have been destructed by the Rust runtime.
SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_dealloc_metadata(Block *ptr);

} // extern "C"

#endif
