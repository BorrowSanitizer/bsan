#ifndef BSAN_SYS_ALLOC_H
#define BSAN_SYS_ALLOC_H

#include "sanitizer_common/sanitizer_common.h"
using namespace __sanitizer;

namespace __bsan {

struct BsanThreadLocalMallocStorage {
  alignas(8) uptr allocator_cache[96 * (512 * 8 + 16)]; // Opaque.
  void CommitBack();

private:
  // These objects are allocated via mmap() and are zero-initialized.
  BsanThreadLocalMallocStorage() {}
};

void InitializeAllocator();
void LockAllocator();
void UnlockAllocator();

void *bsan_malloc(uptr size);
void bsan_deallocate(void *ptr);
void *bsan_calloc(uptr nmemb, uptr size);
void *bsan_realloc(void *ptr, uptr size);
void *bsan_reallocarray(void *ptr, uptr nmemb, uptr size);
void *bsan_valloc(uptr size);
void *bsan_pvalloc(uptr size);
void *bsan_aligned_alloc(uptr alignment, uptr size);
void *bsan_memalign(uptr alignment, uptr size);
int bsan_posix_memalign(void **memptr, uptr alignment, uptr size);

} // namespace __bsan
#endif // BSAN_SYS_ALLOC_H