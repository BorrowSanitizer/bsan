#include "bsan_shadow.h"
#include "bsan.h"
#include "bsan_interface_internal.h"
#include "sanitizer_common/sanitizer_common.h"
#if SANITIZER_LINUX
#include <sys/mman.h>
#include <sys/personality.h>
#endif

// TODO: CheckMemoryLayout is based on msan.
// Consider refactoring these into a shared implementation.
static void CheckMemoryLayout() {
  uptr prev_end = 0;
  for (unsigned i = 0; i < kMemoryLayoutSize; ++i) {
    uptr start = kMemoryLayout[i].start;
    uptr end = kMemoryLayout[i].end;
    MappingDesc::Type type = kMemoryLayout[i].type;
    CHECK_LT(start, end);
    CHECK_EQ(prev_end, start);
    CHECK(addr_is_type(start, type));
    CHECK(addr_is_type((start + end) / 2, type));
    CHECK(addr_is_type(end - 1, type));
    if (type == MappingDesc::APP) {
      uptr addr = start;
      CHECK(MEM_IS_SHADOW(MEM_TO_SHADOW(addr)));
      CHECK(MEM_IS_ORIGIN(MEM_TO_ORIGIN(addr)));
      CHECK_EQ(MEM_TO_ORIGIN(addr), SHADOW_TO_ORIGIN(MEM_TO_SHADOW(addr)));

      addr = (start + end) / 2;
      CHECK(MEM_IS_SHADOW(MEM_TO_SHADOW(addr)));
      CHECK(MEM_IS_ORIGIN(MEM_TO_ORIGIN(addr)));
      CHECK_EQ(MEM_TO_ORIGIN(addr), SHADOW_TO_ORIGIN(MEM_TO_SHADOW(addr)));

      addr = end - 1;
      CHECK(MEM_IS_SHADOW(MEM_TO_SHADOW(addr)));
      CHECK(MEM_IS_ORIGIN(MEM_TO_ORIGIN(addr)));
      CHECK_EQ(MEM_TO_ORIGIN(addr), SHADOW_TO_ORIGIN(MEM_TO_SHADOW(addr)));
    }
    prev_end = end;
  }
}

// TODO: CheckMemoryRangeAvailability is based on msan.
// Consider refactoring these into a shared implementation.
static bool CheckMemoryRangeAvailability(uptr beg, uptr size, bool verbose,
                                         const char *name) {
  if (size > 0) {
    uptr end = beg + size - 1;
    if (!MemoryRangeIsAvailable(beg, end)) {
      if (verbose)
        Printf("FATAL: BorrowSanitizer: memory range %p - %p is not available "
               "(%s).\n",
               (void *)beg, (void *)end, name);
      return false;
    }
  }
  return true;
}

static bool ProtectMemoryRange(uptr beg, uptr size, const char *name) {
  if (size > 0) {
    void *addr = MmapFixedNoAccess(beg, size, name);
    if (beg == 0 && addr) {
      // Depending on the kernel configuration, we may not be able to protect
      // the page at address zero.
      uptr gap = 16 * GetPageSizeCached();
      beg += gap;
      size -= gap;
      addr = MmapFixedNoAccess(beg, size, name);
    }
    if ((uptr)addr != beg) {
      uptr end = beg + size - 1;
      Printf("FATAL: BorrowSanitizer: cannot protect memory range %p - %p "
             "(%s).\n",
             (void *)beg, (void *)end, name);
      return false;
    }
  }
  return true;
}

static bool InitShadow(bool init_origins, bool dry_run) {
  // Let user know mapping parameters first.
  VPrintf(1, "bsan_init %p\n", (void *)&__bsan_init);
  for (unsigned i = 0; i < kMemoryLayoutSize; ++i)
    VPrintf(1, "%s: %zx - %zx\n", kMemoryLayout[i].name, kMemoryLayout[i].start,
            kMemoryLayout[i].end - 1);

  // Verify the memory layout is internally consistent and that the
  // application-to-shadow/origin mappings stay within their regions.
  CheckMemoryLayout();

  if (!MEM_IS_APP(&__bsan_init)) {
    if (!dry_run)
      Printf("FATAL: BorrowSanitizer: code %p is out of application range."
             "Non-PIE build?\n",
             (void *)&__bsan_init);
    return false;
  }

  const uptr maxVirtualAddress = GetMaxUserVirtualAddress();

  for (unsigned i = 0; i < kMemoryLayoutSize; ++i) {
    uptr start = kMemoryLayout[i].start;
    uptr end = kMemoryLayout[i].end;
    uptr size = end - start;
    MappingDesc::Type type = kMemoryLayout[i].type;

    // Check if the segment should be mapped based on platform constraints.
    if (start >= maxVirtualAddress)
      continue;

    bool map = type == MappingDesc::SHADOW || type == MappingDesc::METADATA ||
               (init_origins && type == MappingDesc::ORIGIN);
    bool protect = type == MappingDesc::INVALID ||
                   (!init_origins && type == MappingDesc::ORIGIN);
    CHECK(!(map && protect));
    if (!map && !protect) {
      CHECK(type == MappingDesc::APP || type == MappingDesc::ALLOCATOR);

      if (dry_run && type == MappingDesc::ALLOCATOR &&
          !CheckMemoryRangeAvailability(start, size, !dry_run,
                                        kMemoryLayout[i].name))
        return false;
    }
    if (map) {
      if (dry_run && !CheckMemoryRangeAvailability(start, size, !dry_run,
                                                   kMemoryLayout[i].name))
        return false;
      if (!dry_run &&
          !MmapFixedSuperNoReserve(start, size, kMemoryLayout[i].name)) {
        Printf("FATAL: BorrowSanitizer: failed to map memory range %p - %p "
               "(%s).\n",
               (void *)start, (void *)(end - 1), kMemoryLayout[i].name);
        return false;
      }
      if (!dry_run && common_flags()->use_madv_dontdump)
        DontDumpShadowMemory(start, size);
    }
    if (protect) {
      if (dry_run && !CheckMemoryRangeAvailability(start, size, !dry_run,
                                                   kMemoryLayout[i].name))
        return false;
      if (!dry_run && !ProtectMemoryRange(start, size, kMemoryLayout[i].name))
        return false;
    }
  }

  return true;
}

static void ReportUnavailableMemoryRegions(bool init_origins) {
  const uptr maxVirtualAddress = GetMaxUserVirtualAddress();
  for (unsigned i = 0; i < kMemoryLayoutSize; ++i) {
    uptr start = kMemoryLayout[i].start;
    uptr end = kMemoryLayout[i].end;
    uptr size = end - start;
    MappingDesc::Type type = kMemoryLayout[i].type;

    if (start >= maxVirtualAddress)
      continue;

    bool map = type == MappingDesc::SHADOW || type == MappingDesc::METADATA ||
               (init_origins && type == MappingDesc::ORIGIN);
    bool protect = type == MappingDesc::INVALID ||
                   (!init_origins && type == MappingDesc::ORIGIN);
    if (!map && !protect) {
      if (type == MappingDesc::ALLOCATOR)
        CheckMemoryRangeAvailability(start, size, true, kMemoryLayout[i].name);
      continue;
    }
    CheckMemoryRangeAvailability(start, size, true, kMemoryLayout[i].name);
  }
}

namespace __bsan {
bool InitShadowWithReExec() {
  bool init_origins = true;
  // Start with dry run: check layout is ok, but don't print warnings because
  // warning messages will cause tests to fail (even if we successfully re-exec
  // after the warning).
  bool success = InitShadow(init_origins, true);
  if (!success) {
#if SANITIZER_LINUX
    // Perhaps ASLR entropy is too high. If ASLR is enabled, re-exec without it.
    int old_personality = personality(0xffffffff);
    bool personality_failed = (old_personality == -1);
    bool aslr_on =
        !personality_failed && ((old_personality & ADDR_NO_RANDOMIZE) == 0);
    if (aslr_on) {
      VReport(1, "WARNING: BorrowSanitizer: memory layout is incompatible, "
                 "possibly due to high-entropy ASLR.\n");
      personality_failed =
          personality(old_personality | ADDR_NO_RANDOMIZE) == -1;
      if (personality_failed) {
        VReport(1,
                "Failed to disable ASLR, `personality` syscall returned -1.\n"
                "It may have been blocked by a security setting if "
                "BorrowSanitizer is running in a containerized environment.\n"
                "Reducing ASLR entropy is preferable. Trying again...\n");
      } else {
        VReport(1, "Re-executing with a fixed virtual address space.\n"
                   "Reducing ASLR entropy is preferable.\n");
      }
      ReExec();
    }
#endif
    ReportUnavailableMemoryRegions(init_origins);
    return false;
  }

  // The earlier dry run didn't actually map or protect anything. Run again in
  // non-dry run mode.
  return InitShadow(init_origins, false);
}

// Returns the address of the provenance slot that contains `addr`.
ALWAYS_INLINE static uptr SlotOf(uptr addr) {
  return addr & ~(kMinProvAlignment - 1);
}

// Returns the byte offset of `addr` within its provenance slot.
ALWAYS_INLINE static uptr AlignRemOf(uptr addr) {
  return addr & (kMinProvAlignment - 1);
}

ALWAYS_INLINE static BorTag *SlotTag(uptr slot) {
  return reinterpret_cast<BorTag *>(MEM_TO_SHADOW(slot));
}

ALWAYS_INLINE static Block **SlotBlock(uptr slot) {
  return reinterpret_cast<Block **>(MEM_TO_ORIGIN(slot));
}

// Overwrites the provenance stored at `tag_ptr` and `block_ptr`, adjusting
// reference counts. The source count is incremented before the destination
// count is decremented, in case they refer to the same allocation.
ALWAYS_INLINE static void StoreProvenance(BorTag *tag_ptr, Block **block_ptr,
                                          BorTag tag, Block *block) {
  BorTag old_tag = *tag_ptr;
  if (tag != 0)
    __bsan_rc_inc(tag, block, tag_ptr);
  if (old_tag != 0)
    __bsan_rc_dec(old_tag, *block_ptr, tag_ptr);
  *tag_ptr = tag;
  if (tag != 0)
    *block_ptr = block;
}

// Clears the provenance in `slot` if its pointer overlaps [dst, dst + size).
ALWAYS_INLINE static void ClearIfOverlapping(uptr slot, uptr dst, uptr size) {
  BorTag tag = *SlotTag(slot);
  if (tag == 0)
    return;
  uptr start = slot + (tag & kBorTagOffsetMask);
  if (start < dst + size && start + kMinProvAlignment > dst)
    StoreProvenance(SlotTag(slot), SlotBlock(slot), 0, nullptr);
}

// Returns the address of the pointer stored in `slot` if it is not omnivalid
// and it begins within [lo, hi). Otherwise, returns 0.
ALWAYS_INLINE static uptr PointerWithin(uptr slot, uptr lo, uptr hi) {
  BorTag tag = *SlotTag(slot);
  if (STRIP_TAG_OFFSET(tag) == kOmnivalidTag)
    return 0;
  uptr start = slot + (tag & kBorTagOffsetMask);
  return lo <= start && start < hi ? start : 0;
}

// Computes the new value of the destination slot `slot` after copying `size`
// bytes from `src` to `dst`. A pointer is copied into `slot` if all of its
// bytes lie within the source range and it lands within `slot`. Otherwise,
// `slot` is cleared if its pointer was overwritten.
//
// `kAligned` must be true only if `src_start_addr` and `dest_start_addr` have
// the same offset within their slots.
template <bool kAligned>
ALWAYS_INLINE static void TransferSlot(uptr slot, uptr dest_start_addr,
                                       uptr src_start_addr, uptr size) {
  // Each slot in the destination corresponds
  // to at most 8 bytes of the source: (0, 8]
  uptr src_lo = (slot + src_start_addr) - dest_start_addr;

  // The maximum address where we can transfer a slot.
  // For example, if we are copying 8 bytes, then we
  // can only copy a full pointer if we are starting
  // at the 0th byte.
  uptr src_max = src_start_addr + size - (kMinProvAlignment - 1);

  uptr src_ptr_addr = 0;
  if constexpr (kAligned) {
    // When the source and destination are equally
    // aligned, `src_lo` is itself a slot, so a pointer
    // can only come from that one slot, and it keeps
    // its offset when it is copied.
    src_ptr_addr = PointerWithin(src_lo, src_start_addr, src_max);
  } else {
    uptr src_hi = src_lo + kMinProvAlignment;

    // However, the first slot copied might be
    // before the start of the source address.
    // If our destination is unaligned, then our
    // slot will be positioned at `-align_rem`,
    // The inclusive lower bound of the source
    // range is either the low end above, or the
    // start of the source range—whichever is greater.
    uptr lo = Max(src_lo, src_start_addr);

    // The exclusive upper bound of the source
    // range being copied.
    uptr hi = Min(src_hi, src_max);

    uptr lo_slot = SlotOf(lo);
    uptr hi_slot = SlotOf(hi - 1);

    if (lo < hi) {
      // Since the bounds span 8 bytes, a pointer could begin in
      // either of two source slots.
      src_ptr_addr = PointerWithin(lo_slot, lo, hi);
      if (hi_slot != lo_slot) {
        uptr other = PointerWithin(hi_slot, lo, hi);
        // If this pointer could correspond to either slot,
        // then we always take the provenance of the higher
        // slot. This is because when we copy provenance, we
        // clear the provenance of a pointers that overlaps with
        // the high end of the range being copied, but we do not
        // clear for the low end of the range. Mostly because this
        // would add a constant overhead for aligned stores in main
        // memory. So if two provenance values correspond to the same
        // slot, we know that either they are both stale values, or
        // the higher one is valid.
        if (other)
          src_ptr_addr = other;
      }
    }
  }

  if (src_ptr_addr) {
    uptr from = SlotOf(src_ptr_addr);
    uptr to = src_ptr_addr + dest_start_addr - src_start_addr;
    uptr tag = STRIP_TAG_OFFSET(*SlotTag(from)) | (to & kBorTagOffsetMask);
    StoreProvenance(SlotTag(slot), SlotBlock(slot), tag, *SlotBlock(from));
  } else {
    ClearIfOverlapping(slot, dest_start_addr, size);
  }
}

// Transfers provenance into every destination slot that overlaps
// [dest_addr, dest_addr + size). Slots are visited in the same order as
// `memmove`, so that overlapping source slots are read before they are
// overwritten.
template <bool kAligned>
static void TransferSlots(uptr dest_addr, uptr src_addr, uptr size) {
  uptr first = SlotOf(dest_addr);
  uptr last = SlotOf(dest_addr + size - 1);
  if (dest_addr < src_addr) {
    for (uptr slot = first; slot <= last; slot += kMinProvAlignment)
      TransferSlot<kAligned>(slot, dest_addr, src_addr, size);
  } else {
    for (uptr slot = last + kMinProvAlignment; slot != first;)
      TransferSlot<kAligned>(slot -= kMinProvAlignment, dest_addr, src_addr,
                             size);
  }
}

void JoinShadow(void *dest, const void *s_shadow, const void *s_origin,
                uptr s_size) {
  // This operation relies on our instrumentation pass
  // to ensure that the source and size are aligned.
  uptr d_aligned = SlotOf((uptr)dest);
  BorTag *d_tags = SlotTag(d_aligned);
  Block **d_blocks = SlotBlock(d_aligned);
  const BorTag *s_tags = reinterpret_cast<const BorTag *>(s_shadow);
  Block *const *s_blocks = reinterpret_cast<Block *const *>(s_origin);
  for (uptr i = 0; i * kMinProvAlignment < s_size; i++)
    StoreProvenance(&d_tags[i], &d_blocks[i], s_tags[i], s_blocks[i]);
}

// Copies provenance for `size` bytes from `src` to `dest`, as if by `memmove`.
void TransferShadow(void *dest, const void *src, uptr size) {
  if (!MEM_IS_APP(dest) || !MEM_IS_APP(src))
    return;
  uptr dest_addr = (uptr)dest;
  uptr src_addr = (uptr)src;
  if (size == 0 || dest_addr == src_addr)
    return;

  if (AlignRemOf(src_addr) == AlignRemOf(dest_addr))
    TransferSlots<true>(dest_addr, src_addr, size);
  else
    TransferSlots<false>(dest_addr, src_addr, size);
}

void ClearShadow(void *dest, uptr size) {
  if (!MEM_IS_APP(dest) || size == 0)
    return;
  // Only the slots that overlap [dst, dst + size) are cleared.
  uptr dst = (uptr)dest;
  uptr first = SlotOf(dst);
  uptr last = SlotOf(dst + size - 1);
  for (uptr slot = first; slot <= last; slot += kMinProvAlignment)
    ClearIfOverlapping(slot, dst, size);
}

void ClearShadowAligned(uptr shadow_start, uptr origin_start,
                        uptr size_aligned) {
  BorTag *tags = reinterpret_cast<BorTag *>(shadow_start);
  Block **blocks = reinterpret_cast<Block **>(origin_start);
  for (uptr i = 0; i * kMinProvAlignment < size_aligned; i++)
    StoreProvenance(&tags[i], &blocks[i], 0, nullptr);
}

// Zeroes the range [beg, end) of shadow memory. Every page that lies
// entirely within the range is dropped instead of being written to.
static void ZeroShadowRange(uptr beg, uptr end) {
  uptr page_size = GetPageSizeCached();
  uptr beg_aligned = RoundUpTo(beg, page_size);
  uptr end_aligned = RoundDownTo(end, page_size);
  if (beg_aligned >= end_aligned) {
    internal_memset((void *)beg, 0, end - beg);
    return;
  }
  internal_memset((void *)beg, 0, beg_aligned - beg);
  // Shadow memory is a private, anonymous mapping, so the pages that we
  // drop here will read as zero the next time that they are touched. Pages
  // that were never touched to begin with are skipped by the kernel.
  if (internal_madvise(beg_aligned, end_aligned - beg_aligned, MADV_DONTNEED))
    internal_memset((void *)beg_aligned, 0, end_aligned - beg_aligned);
  internal_memset((void *)end_aligned, 0, end - end_aligned);
}

void ReleaseShadow(uptr begin, uptr end) {
  begin = RoundUpTo(begin, kMinProvAlignment);
  end = RoundDownTo(end, kMinProvAlignment);
  if (begin >= end)
    return;
  ZeroShadowRange(MEM_TO_SHADOW(begin), MEM_TO_SHADOW(end));
  ZeroShadowRange(MEM_TO_ORIGIN(begin), MEM_TO_ORIGIN(end));
}

void WriteShadow(void *dest, Provenance prov) {
  if (!MEM_IS_APP(dest))
    return;
  uptr slot = SlotOf((uptr)dest);
  // Record where the pointer begins within its slot.
  StoreProvenance(SlotTag(slot), SlotBlock(slot),
                  prov.tag | ((uptr)dest & kBorTagOffsetMask), prov.block);
}
} // namespace __bsan
