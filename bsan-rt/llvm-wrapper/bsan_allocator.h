#ifndef BSAN_ALLOC_H
#define BSAN_ALLOC_H

#include "bsan_shadow.h"
#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_common.h"
using namespace __sanitizer;

namespace __bsan {

struct Metadata {
  uptr requested_size;
};

// Parameters for the primary allocator that replaces
// malloc. All allocations created from this allocator
// have a corresponding region in shadow memory.
struct ShadowedAP64 {
  static const uptr kSpaceBeg = kAllocatorSpace;
  static const uptr kSpaceSize = kAllocatorSpaceSize;
  static const uptr kMetadataSize = sizeof(Metadata);
  using SizeClassMap = DefaultSizeClassMap;
  typedef NoOpMapUnmapCallback MapUnmapCallback;
  static const uptr kFlags = 0;
  using AddressSpaceView = LocalAddressSpaceView;
};

typedef SizeClassAllocator64<ShadowedAP64> PrimaryAllocator;
typedef CombinedAllocator<PrimaryAllocator> Allocator;
typedef Allocator::AllocatorCache AllocatorCache;

// Parameters for the primary allocator used by the Rust runtime.
struct RustAP64 {
  static const uptr kSpaceBeg = ~(uptr)0;
  static const uptr kSpaceSize = kAllocatorSpaceSize;
  static const uptr kMetadataSize = 0;
  using SizeClassMap = DefaultSizeClassMap;
  typedef NoOpMapUnmapCallback MapUnmapCallback;
  static const uptr kFlags = 0;
  using AddressSpaceView = LocalAddressSpaceView;
};

typedef SizeClassAllocator64<RustAP64> PrimaryRustAllocator;
typedef CombinedAllocator<PrimaryRustAllocator> RustAllocator;
typedef RustAllocator::AllocatorCache RustAllocatorCache;

void CommitBackShadowedCache(AllocatorCache *cache);
void CommitBackRustCache(RustAllocatorCache *cache);

void InitializeShadowedAllocator();
void LockShadowedAllocator();
void UnlockShadowedAllocator();

void InitializeRustAllocator();
void LockRustAllocator();
void UnlockRustAllocator();

void *RustAlloc(uptr size, uptr alignment);
void RustDealloc(void *ptr);

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
uptr bsan_mz_size(const void *p);

} // namespace __bsan
#endif // BSAN_ALLOC_H