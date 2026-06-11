#include "bsan_allocator.h"
#include "bsan.h"
#include "bsan_flags.h"
#include "bsan_shadow.h"
#include "bsan_thread.h"
#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_allocator_checks.h"
#include "sanitizer_common/sanitizer_allocator_interface.h"
#include "sanitizer_common/sanitizer_allocator_report.h"
#include "sanitizer_common/sanitizer_errno.h"

using namespace __bsan;

namespace {

struct Metadata {
  uptr requested_size;
};

struct BsanMapUnmapCallback {
  void OnMap(uptr p, uptr size) const {}
  void OnMapSecondary(uptr p, uptr size, uptr user_begin,
                      uptr user_size) const {
    OnMap(p, size);
  }
  void OnUnmap(uptr p, uptr size) const {}
};

const uptr kMaxAllowedMallocSize = 1ULL << 40;

struct AP64 { // Allocator64 parameters. Deliberately using a short name.
  static const uptr kSpaceBeg = kAllocatorSpace;
  static const uptr kSpaceSize = kAllocatorSpaceSize;
  static const uptr kMetadataSize = sizeof(Metadata);
  using SizeClassMap = DefaultSizeClassMap;
  using MapUnmapCallback = BsanMapUnmapCallback;
  static const uptr kFlags = 0;
  using AddressSpaceView = LocalAddressSpaceView;
};

typedef SizeClassAllocator64<AP64> PrimaryAllocator;

typedef CombinedAllocator<PrimaryAllocator> Allocator;
typedef Allocator::AllocatorCache AllocatorCache;

static Allocator allocator;
static AllocatorCache fallback_allocator_cache;
static StaticSpinMutex fallback_mutex;

static uptr max_malloc_size;
} // namespace

void __bsan::InitializeAllocator() {
  SetAllocatorMayReturnNull(common_flags()->allocator_may_return_null);
  allocator.Init(common_flags()->allocator_release_to_os_interval_ms);
  if (common_flags()->max_allocation_size_mb)
    max_malloc_size = Min(common_flags()->max_allocation_size_mb << 20,
                          kMaxAllowedMallocSize);
  else
    max_malloc_size = kMaxAllowedMallocSize;
}

static AllocatorCache *GetAllocatorCache(BsanThreadLocalMallocStorage *ms) {
  CHECK(ms);
  CHECK_LE(sizeof(AllocatorCache), sizeof(ms->allocator_cache));
  return reinterpret_cast<AllocatorCache *>(ms->allocator_cache);
}

void BsanThreadLocalMallocStorage::CommitBack() {
  allocator.SwallowCache(GetAllocatorCache(this));
}

static void *BsanAllocate(uptr size, uptr alignment, bool zeroise) {
  if (size > max_malloc_size) {
    if (AllocatorMayReturnNull()) {
      Report("WARNING: BorrowSanitizer failed to allocate 0x%zx bytes\n",
             size);
      return nullptr;
    }
    UNINITIALIZED BufferedStackTrace stack;
    ReportAllocationSizeTooBig(size, max_malloc_size, &stack);
  }
  if (UNLIKELY(IsRssLimitExceeded())) {
    if (AllocatorMayReturnNull())
      return nullptr;
    UNINITIALIZED BufferedStackTrace stack;
    ReportRssLimitExceeded(&stack);
  }
  BsanThread *t = GetCurrentThread();
  void *allocated;
  if (t) {
    AllocatorCache *cache = GetAllocatorCache(&t->malloc_storage());
    allocated = allocator.Allocate(cache, size, alignment);
  } else {
    SpinMutexLock l(&fallback_mutex);
    AllocatorCache *cache = &fallback_allocator_cache;
    allocated = allocator.Allocate(cache, size, alignment);
  }
  if (UNLIKELY(!allocated)) {
    SetAllocatorOutOfMemory();
    if (AllocatorMayReturnNull())
      return nullptr;
    UNINITIALIZED BufferedStackTrace stack;
    ReportOutOfMemory(size, &stack);
  }
  Metadata *meta =
      reinterpret_cast<Metadata *>(allocator.GetMetaData(allocated));
  meta->requested_size = size;
  if (zeroise) {
    internal_memset(allocated, 0, size);
  }
  return allocated;
}

void __bsan::bsan_deallocate(void *p) {
  CHECK(p);
  Metadata *meta = reinterpret_cast<Metadata *>(allocator.GetMetaData(p));
  meta->requested_size = 0;
  BsanThread *t = GetCurrentThread();
  if (t) {
    AllocatorCache *cache = GetAllocatorCache(&t->malloc_storage());
    allocator.Deallocate(cache, p);
  } else {
    SpinMutexLock l(&fallback_mutex);
    AllocatorCache *cache = &fallback_allocator_cache;
    allocator.Deallocate(cache, p);
  }
}

static void *BsanReallocate(void *old_p, uptr new_size, uptr alignment) {
  Metadata *meta = reinterpret_cast<Metadata *>(allocator.GetMetaData(old_p));
  uptr old_size = meta->requested_size;
  uptr actually_allocated_size = allocator.GetActuallyAllocatedSize(old_p);
  if (new_size <= actually_allocated_size) {
    // We are not reallocating here.
    meta->requested_size = new_size;
    return old_p;
  }
  uptr memcpy_size = Min(new_size, old_size);
  void *new_p = BsanAllocate(new_size, alignment, false /*zeroise*/);
  if (new_p) {
    internal_memcpy(new_p, old_p, memcpy_size);
    CopyShadow(new_p, old_p, memcpy_size);
    bsan_deallocate(old_p);
  }
  return new_p;
}

static void *BsanCalloc(uptr nmemb, uptr size) {
  if (UNLIKELY(CheckForCallocOverflow(size, nmemb))) {
    if (AllocatorMayReturnNull())
      return nullptr;
    UNINITIALIZED BufferedStackTrace stack;
    ReportCallocOverflow(nmemb, size, &stack);
  }
  return BsanAllocate(nmemb * size, sizeof(u64), true /*zeroise*/);
}

static const void *AllocationBegin(const void *p) {
  if (!p)
    return nullptr;
  void *beg = allocator.GetBlockBegin(p);
  if (!beg)
    return nullptr;
  Metadata *b = (Metadata *)allocator.GetMetaData(beg);
  if (!b)
    return nullptr;
  if (b->requested_size == 0)
    return nullptr;
  return (const void *)beg;
}

static uptr AllocationSize(const void *p) {
  if (!p)
    return 0;
  const void *beg = allocator.GetBlockBegin(p);
  if (beg != p)
    return 0;
  Metadata *b = (Metadata *)allocator.GetMetaData(p);
  return b->requested_size;
}

static uptr AllocationSizeFast(const void *p) {
  return reinterpret_cast<Metadata *>(allocator.GetMetaData(p))->requested_size;
}

void *__bsan::bsan_malloc(uptr size) {
  return SetErrnoOnNull(BsanAllocate(size, sizeof(u64), false /*zeroise*/));
}

void *__bsan::bsan_calloc(uptr nmemb, uptr size) {
  return SetErrnoOnNull(BsanCalloc(nmemb, size));
}

void *__bsan::bsan_realloc(void *ptr, uptr size) {
  if (!ptr)
    return SetErrnoOnNull(BsanAllocate(size, sizeof(u64), false /*zeroise*/));
  if (size == 0) {
    bsan_deallocate(ptr);
    return nullptr;
  }
  return SetErrnoOnNull(BsanReallocate(ptr, size, sizeof(u64)));
}

void *__bsan::bsan_reallocarray(void *ptr, uptr nmemb, uptr size) {
  if (UNLIKELY(CheckForCallocOverflow(size, nmemb))) {
    errno = errno_ENOMEM;
    if (AllocatorMayReturnNull())
      return nullptr;
    UNINITIALIZED BufferedStackTrace stack;
    ReportReallocArrayOverflow(nmemb, size, &stack);
  }
  return bsan_realloc(ptr, nmemb * size);
}

void *__bsan::bsan_valloc(uptr size) {
  return SetErrnoOnNull(
      BsanAllocate(size, GetPageSizeCached(), false /*zeroise*/));
}

void *__bsan::bsan_pvalloc(uptr size) {
  uptr PageSize = GetPageSizeCached();
  if (UNLIKELY(CheckForPvallocOverflow(size, PageSize))) {
    errno = errno_ENOMEM;
    if (AllocatorMayReturnNull())
      return nullptr;
    UNINITIALIZED BufferedStackTrace stack;
    ReportPvallocOverflow(size, &stack);
  }
  // pvalloc(0) should allocate one page.
  size = size ? RoundUpTo(size, PageSize) : PageSize;
  return SetErrnoOnNull(BsanAllocate(size, PageSize, false /*zeroise*/));
}

void *__bsan::bsan_aligned_alloc(uptr alignment, uptr size) {
  if (UNLIKELY(!CheckAlignedAllocAlignmentAndSize(alignment, size))) {
    errno = errno_EINVAL;
    if (AllocatorMayReturnNull())
      return nullptr;
    UNINITIALIZED BufferedStackTrace stack;
    ReportInvalidAlignedAllocAlignment(size, alignment, &stack);
  }
  return SetErrnoOnNull(BsanAllocate(size, alignment, false /*zeroise*/));
}

void *__bsan::bsan_memalign(uptr alignment, uptr size) {
  if (UNLIKELY(!IsPowerOfTwo(alignment))) {
    errno = errno_EINVAL;
    if (AllocatorMayReturnNull())
      return nullptr;
    UNINITIALIZED BufferedStackTrace stack;
    ReportInvalidAllocationAlignment(alignment, &stack);
  }
  return SetErrnoOnNull(BsanAllocate(size, alignment, false /*zeroise*/));
}

int __bsan::bsan_posix_memalign(void **memptr, uptr alignment, uptr size) {
  if (UNLIKELY(!CheckPosixMemalignAlignment(alignment))) {
    if (AllocatorMayReturnNull())
      return errno_EINVAL;
    UNINITIALIZED BufferedStackTrace stack;
    ReportInvalidPosixMemalignAlignment(alignment, &stack);
  }
  void *ptr = BsanAllocate(size, alignment, false /*zeroise*/);
  if (UNLIKELY(!ptr))
    // OOM error is already taken care of by BsanAllocate.
    return errno_ENOMEM;
  CHECK(IsAligned((uptr)ptr, alignment));
  *memptr = ptr;
  return 0;
}

extern "C" {
uptr __sanitizer_get_current_allocated_bytes() {
  uptr stats[AllocatorStatCount];
  allocator.GetStats(stats);
  return stats[AllocatorStatAllocated];
}

uptr __sanitizer_get_heap_size() {
  uptr stats[AllocatorStatCount];
  allocator.GetStats(stats);
  return stats[AllocatorStatMapped];
}

uptr __sanitizer_get_free_bytes() { return 1; }

uptr __sanitizer_get_unmapped_bytes() { return 1; }

uptr __sanitizer_get_estimated_allocated_size(uptr size) { return size; }

int __sanitizer_get_ownership(const void *p) { return AllocationSize(p) != 0; }

const void *__sanitizer_get_allocated_begin(const void *p) {
  return AllocationBegin(p);
}

uptr __sanitizer_get_allocated_size(const void *p) { return AllocationSize(p); }

uptr __sanitizer_get_allocated_size_fast(const void *p) {
  DCHECK_EQ(p, __sanitizer_get_allocated_begin(p));
  uptr ret = AllocationSizeFast(p);
  DCHECK_EQ(ret, __sanitizer_get_allocated_size(p));
  return ret;
}
}