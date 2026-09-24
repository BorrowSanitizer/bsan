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
bool __bsan_dealloc(void *ptr, BorTag bor_tag, AllocInfo *alloc_info, Span pc,
                    bool checked);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_read(void *ptr, uptr access_size, BorTag bor_tag,
                 AllocInfo *alloc_info, bool checked);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_write(void *ptr, uptr access_size, BorTag bor_tag,
                  AllocInfo *alloc_info, bool checked);

// Records a zero-count (alloc_info, bor_tag) pair in the zero-count table.
// Called by the Rust core when a node's reference count reaches zero.
SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_release(BorTag bor_tag, AllocInfo *alloc_info);

// Requests a garbage collection. Any thread may call this.
SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_request_gc();

// The result of attempting to "prune" dead nodes from a tree.
enum class EjectStatus : int {
  // The allocation can be "ejected" from the GC,
  // as long as it is no longer alive on any of the
  // shadow stacks. All of its nodes are gone.
  Ejectable = 0,
  // All of the nodes in this allocation have been
  // removed by deallocation, but the allocation
  // itself is still somewhere in shadow memory
  // with a nonzero reference count. It needs to
  // be kept around.
  RetainEmpty = 1,
  // Some of the nodes in this allocation are still
  // alive, or the allocation is being accessed by another
  // thread. It could not be pruned, and needs to be visited
  // again the next time that the world is stopped.
  RetainNonEmpty = 2,
};

// Prunes a list of nodes from a tree that correspond to the tags in the list.
// Returns an `EjectStatus`, indicating if the allocation metadata object
// can be reclaimed.
SANITIZER_WEAK_ATTRIBUTE
EjectStatus __bsan_prune(AllocInfo *Info, BorTag *tags, uptr len);

// Frees an `AllocInfo` object. The pointer must be nonnull and unreachable
// in shadow memory.
SANITIZER_WEAK_ATTRIBUTE
void __bsan_eject(AllocInfo *Info);

} // extern "C"

#endif
