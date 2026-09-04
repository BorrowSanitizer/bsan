#ifndef BSAN_DENSE_ALLOC_H
#define BSAN_DENSE_ALLOC_H

// This is a port of ThreadSanitizer's `DenseSlabAlloc`. The original design
// can only be used for objects smaller than 32 bits. Our version hands out 
// 256-byte blocks from a preallocated 1 TB region.

#include "bsan.h"
#include "bsan_shadow.h"
#include "sanitizer_common/sanitizer_common.h"

using namespace __sanitizer;

namespace __bsan {
// The block size needs to be a power of two, so that we can
// efficiently convert an index into a pointer to its block
// using an add + shift.
static constexpr uptr kBlockShift = __builtin_ctzll(kBlockSize);
static_assert((kBlockSize & (kBlockSize - 1)) == 0,
              "kBlockSizeBytes must be a power-of-two");

// Threads can allocate 1 MB segments of blocks.
static constexpr uptr kSegmentSize = 1 * 1024 * 1024;
static constexpr uptr kBlocksPerSegment = kSegmentSize / kBlockSize;
static_assert((kSegmentSize % kBlockSize) == 0,
              "a segment must be a whole number of blocks");

// Segments are also aligned to powers of two, making it possible to
// determine a block's segment with a shift. 
static constexpr uptr kSegmentShift = __builtin_ctzll(kBlocksPerSegment);

// All segments are allocated from a fixed 1 TB region, which covers
// the entire 32-bit `BlockIndex` address space.
static_assert((kMetadataSpaceSize % kBlockSize) == 0,
              "the region must be a whole number of blocks");
static constexpr uptr kNumBlocks = kMetadataSpaceSize / kBlockSize;
static constexpr uptr kNumSegments = kMetadataSpaceSize / kSegmentSize;

// A thread-local cache of free blocks.
class DenseSlabAllocCache {
  static const uptr kSize = 128;
  uptr pos;
  BlockIndex cache[kSize];
  uptr cursor;
  uptr end;
  template <uptr> friend class DenseSlabAlloc;

public:
  constexpr DenseSlabAllocCache() : pos(0), cache(), cursor(0), end(0) {}
};

template <uptr kRegionStart> class DenseSlabAlloc {
public:
  typedef DenseSlabAllocCache Cache;
  static_assert((kRegionStart & (kSegmentSize - 1)) == 0,
                "the region must be segment-aligned");
  DenseSlabAlloc(LinkerInitialized, const char *name) : name_(name) {}
  explicit DenseSlabAlloc(const char *name)
      : DenseSlabAlloc(LINKER_INITIALIZED, name) {}
  ~DenseSlabAlloc() {}

  BlockIndex Alloc(Cache *c) {
    if (c->pos == 0)
      Refill(c);
    return c->cache[--c->pos];
  }

  void Free(Cache *c, BlockIndex idx) {
    DCHECK_NE(idx, 0);
    if (c->pos == Cache::kSize)
      Drain(c);
    c->cache[c->pos++] = idx;
  }

  static Block *Map(BlockIndex idx) {
    DCHECK_NE(idx, 0);
    uptr addr = kRegionStart + (static_cast<uptr>(idx) << kBlockShift);
    return reinterpret_cast<Block *>(addr);
  }

  static BlockIndex IndexOf(Block *elem) {
    uptr addr = reinterpret_cast<uptr>(elem);
    // The address must fall within the prefixed region
    DCHECK_GE(addr, kRegionStart + kBlockSize);
    // It must be aligned to the block size.
    DCHECK_EQ(addr & (kBlockSize - 1), 0);
    return static_cast<BlockIndex>((addr - kRegionStart) >> kBlockShift);
  }

  void FlushCache(Cache *c) {
    while (c->pos)
      Drain(c);
  }

  void InitCache(Cache *c) {
    c->pos = 0;
    c->cursor = 0;
    c->end = 0;
    internal_memset(c->cache, 0, sizeof(c->cache));
  }

private:
  // The freelist is organized as a lock-free stack of batches of nodes.
  // The stack itself uses Block::next links, while the batch within each
  // stack node uses Block::batch links.
  // Low 32-bits of freelist_ is the node index, top 32-bits is ABA-counter.
  atomic_uint64_t freelist_ = {0};
  atomic_uintptr_t fillpos_ = {0};
  const char *const name_;

  struct FreeBlock {
    BlockIndex next;
    BlockIndex batch;
  };

  static_assert(kBlockSize >= sizeof(FreeBlock),
                "a block must have room for the freelist links");

  static FreeBlock *MapBlock(BlockIndex idx) {
    return reinterpret_cast<FreeBlock *>(Map(idx));
  }

  static constexpr u64 kCounterInc = 1ull << 32;
  static constexpr u64 kCounterMask = ~(kCounterInc - 1);

  NOINLINE void Refill(Cache *c) {
    // Pop 1 batch of nodes from the freelist.
    BlockIndex idx;
    u64 xchg;
    u64 cmp = atomic_load(&freelist_, memory_order_acquire);
    do {
      idx = static_cast<BlockIndex>(cmp);
      if (!idx)
        return AllocSuperBlock(c);
      FreeBlock *ptr = MapBlock(idx);
      xchg = ptr->next | (cmp & kCounterMask);
    } while (!atomic_compare_exchange_weak(&freelist_, &cmp, xchg,
                                           memory_order_acq_rel));
    // Unpack it into c->cache.
    while (idx) {
      c->cache[c->pos++] = idx;
      idx = MapBlock(idx)->batch;
    }
  }

  NOINLINE void Drain(Cache *c) {
    // Build a batch of at most Cache::kSize / 2 nodes linked by Block::batch.
    BlockIndex head_idx = 0;
    for (uptr i = 0; i < Cache::kSize / 2 && c->pos; i++) {
      BlockIndex idx = c->cache[--c->pos];
      FreeBlock *ptr = MapBlock(idx);
      ptr->batch = head_idx;
      head_idx = idx;
    }
    // Push it onto the freelist stack.
    FreeBlock *head = MapBlock(head_idx);
    u64 xchg;
    u64 cmp = atomic_load(&freelist_, memory_order_acquire);
    do {
      head->next = static_cast<BlockIndex>(cmp);
      xchg = head_idx | ((cmp & kCounterMask) + kCounterInc);
    } while (!atomic_compare_exchange_weak(&freelist_, &cmp, xchg,
                                           memory_order_acq_rel));
  }

  NOINLINE void AllocSuperBlock(Cache *c) {
    if (c->cursor == c->end) {
      // Allocate a new segment
      uptr seg = atomic_fetch_add(&fillpos_, 1, memory_order_relaxed);
      if (UNLIKELY(seg >= kNumSegments)) {
        Printf("BorrowSanitizer: %s overflow (%zu segments of %zu bytes). "
               "Dying.\n",
               name_, kNumSegments, kSegmentSize);
        Die();
      }
      VPrintf(3, "BorrowSanitizer: growing %s: segment %zu out of %zu\n", name_,
              seg, kNumSegments);
      c->cursor = seg * kBlocksPerSegment;
      c->end = c->cursor + kBlocksPerSegment;
      // Block 0 of the region is reserved as the invalid index.
      if (UNLIKELY(c->cursor == 0))
        c->cursor = 1;
    }
    uptr batch = Min(Cache::kSize, c->end - c->cursor);
    for (uptr i = 0; i < batch; i++)
      c->cache[c->pos++] = static_cast<BlockIndex>(c->cursor++);
    CHECK(c->pos);
  }
};

} // namespace __bsan
#endif