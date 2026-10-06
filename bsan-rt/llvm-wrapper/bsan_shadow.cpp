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
      // DepJending on the kernel configuration, we may not be able to protect
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
    bool aslr_on =
        (old_personality != -1) && ((old_personality & ADDR_NO_RANDOMIZE) == 0);

    if (aslr_on) {
      VReport(1, "WARNING: BorrowSanitizer: memory layout is incompatible, "
                 "possibly due to high-entropy ASLR.\n"
                 "Re-execing with fixed virtual address space.\n"
                 "N.B. reducing ASLR entropy is preferable.\n");
      CHECK_NE(personality(old_personality | ADDR_NO_RANDOMIZE), -1);
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

static void AlignPtr8(uptr addr, uptr &aligned_addr) {
  aligned_addr = addr & ~7UL;
}
static void AlignRange8(uptr addr, uptr size, uptr &aligned_addr,
                        uptr &aligned_size) {
  AlignPtr8(addr, aligned_addr);
  uptr end = (addr + size + 7) & ~7UL;
  aligned_size = end - aligned_addr;
}

ALWAYS_INLINE static void UpdateShadowSlot(uptr d_shadow, uptr d_origin,
                                           uptr s_shadow, uptr s_origin,
                                           uptr offset) {
  Block **dest_block_ptr = reinterpret_cast<Block **>(d_origin + offset);
  Block **source_block_ptr = reinterpret_cast<Block **>(s_origin + offset);

  BorTag *dest_tag_ptr = reinterpret_cast<BorTag *>(d_shadow + offset);
  BorTag *source_tag_ptr = reinterpret_cast<BorTag *>(s_shadow + offset);

  BorTag dest_tag = *dest_tag_ptr;
  BorTag source_tag = *source_tag_ptr;

  if (source_tag != 0)
    __bsan_rc_inc(source_tag, *source_block_ptr, dest_tag_ptr);
  if (dest_tag != 0)
    __bsan_rc_dec(dest_tag, *dest_block_ptr, dest_tag_ptr);

  *dest_tag_ptr = source_tag;

  if (source_tag != 0)
    *dest_block_ptr = *source_block_ptr;
}

// The tag in each provenance slot records the offset at which its pointer
// begins, so the pointer occupies [slot + offset, slot + offset + 8). This may
// extend into the following slot.
ALWAYS_INLINE static BorTag *SlotTag(uptr slot) {
  return reinterpret_cast<BorTag *>(MEM_TO_SHADOW(slot));
}

ALWAYS_INLINE static Block **SlotBlock(uptr slot) {
  return reinterpret_cast<Block **>(MEM_TO_ORIGIN(slot));
}

// Clears the provenance in `slot` if its pointer overlaps [dst, dst + size).
ALWAYS_INLINE static void ClearIfOverlapping(uptr slot, uptr dst, uptr size) {
  BorTag *tag_ptr = SlotTag(slot);
  BorTag tag = *tag_ptr;
  if (tag == 0)
    return;
  uptr start = slot + (tag & kBorTagOffsetMask);
  if (start < dst + size && start + 8 > dst) {
    __bsan_rc_dec(tag, *SlotBlock(slot), tag_ptr);
    *tag_ptr = 0;
  }
}

// Returns the address that the pointer in `src_slot` is copied to, if all
// of its bytes lie within the source range, and it lands in `dest_slot`.
ALWAYS_INLINE static uptr MovedPointer(uptr src_slot, uptr dest_slot, uptr dst,
                                       uptr src, uptr size) {
  if (src_slot < (src & ~kBorTagOffsetMask) || src_slot + 8 > src + size)
    return 0;
  BorTag tag = *SlotTag(src_slot);
  if (STRIP_TAG_OFFSET(tag) == kOmnivalidTag)
    return 0;
  uptr start = src_slot + (tag & kBorTagOffsetMask);
  if (start < src || start + 8 > src + size)
    return 0;
  uptr moved = start - src + dst;
  if ((moved & ~kBorTagOffsetMask) != dest_slot)
    return 0;
  return moved;
}

// Computes the new value of `slot` after copying `size` bytes from `src` to
// `dst`, adjusting reference counts for any provenance that is overwritten.
ALWAYS_INLINE static void TransferSlot(uptr slot, uptr dst, uptr src,
                                       uptr size) {
  uptr window = slot - dst + src;
  uptr first_src = window & ~kBorTagOffsetMask;
  uptr moved = MovedPointer(first_src, slot, dst, src, size);
  uptr moved_slot = first_src;
  if (window & kBorTagOffsetMask) {
    uptr second_src = first_src + 8;
    if (uptr other = MovedPointer(second_src, slot, dst, src, size)) {
      // Two pointers cannot overlap, so one of them must be stale.
      // We cannot tell which, so neither one is copied.
      moved = moved ? 0 : other;
      moved_slot = second_src;
    }
  }

  // If no pointer lands here, clear any pointer whose bytes were overwritten.
  if (!moved) {
    ClearIfOverlapping(slot, dst, size);
    return;
  }

  BorTag *tag_ptr = SlotTag(slot);
  Block **block_ptr = SlotBlock(slot);
  BorTag old_tag = *tag_ptr;
  BorTag tag = STRIP_TAG_OFFSET(*SlotTag(moved_slot));
  Block *block = *SlotBlock(moved_slot);
  __bsan_rc_inc(tag, block, tag_ptr);
  if (old_tag != 0)
    __bsan_rc_dec(old_tag, *block_ptr, tag_ptr);
  *block_ptr = block;
  *tag_ptr = tag | (moved & kBorTagOffsetMask);
}

void CopyShadow(void *dest, const void *src, uptr size) {
  MoveShadow(dest, src, size);
}

void JoinShadow(void *dest, const void *s_shadow, const void *s_origin,
                uptr s_size) {
  // This operation relies on our instrumentation pass
  // to ensure that the source and size are aligned.
  uptr d_aligned;
  AlignPtr8((uptr)dest, d_aligned);

  uptr d_shadow = MEM_TO_SHADOW(d_aligned);
  uptr d_origin = MEM_TO_ORIGIN(d_aligned);

  uptr s_shadow_addr = (uptr)s_shadow;
  uptr s_origin_addr = (uptr)s_origin;

  const uptr step = kMinProvAlignment;

  for (uptr offset = 0; offset < s_size; offset += step)
    UpdateShadowSlot(d_shadow, d_origin, s_shadow_addr, s_origin_addr, offset);
}

// Copies provenance for `size` bytes from `src` to `dest`, as if by `memmove`.
void MoveShadow(void *dest, const void *src, uptr size) {
  if (!MEM_IS_APP(dest))
    return;
  if (!MEM_IS_APP(src))
    return;
  uptr dst = (uptr)dest;
  uptr from = (uptr)src;
  if (size == 0 || dst == from)
    return;

  uptr first = (dst & ~kBorTagOffsetMask) - 8;
  if (!MEM_IS_APP(first))
    first += 8;
  uptr last = (dst + size - 1) & ~kBorTagOffsetMask;
  // Read in the backwards/forwards direction based on the ordering of `dst`/`from`.
  // This prevents slots being overwritten before they're read.
  if (dst < from) {
    for (uptr slot = first; slot <= last; slot += 8)
      TransferSlot(slot, dst, from, size);
  } else {
    for (uptr slot = last;; slot -= 8) {
      TransferSlot(slot, dst, from, size);
      if (slot == first)
        break;
    }
  }
}

void ClearShadow(void *dest, uptr size) {
  if (!MEM_IS_APP(dest) || size == 0)
    return;
  uptr dst = (uptr)dest;
  uptr first = (dst & ~kBorTagOffsetMask) - 8;
  if (!MEM_IS_APP(first))
    first += 8;
  uptr last = (dst + size - 1) & ~kBorTagOffsetMask;
  for (uptr slot = first; slot <= last; slot += 8)
    ClearIfOverlapping(slot, dst, size);
}

void ClearShadowAligned(uptr shadow_start, uptr origin_start,
                        uptr size_aligned) {

  const uptr step = kMinProvAlignment;

  for (uptr offset = 0; offset < size_aligned; offset += step) {
    BorTag *tag_ptr = reinterpret_cast<BorTag *>(shadow_start + offset);
    Block **block_ptr = reinterpret_cast<Block **>(origin_start + offset);

    // We use the borrow tag as a proxy for the initialization of the
    // `AllocInfo` component of provenance metadata.
    if (*tag_ptr != 0) {
      __bsan_rc_dec(*tag_ptr, *block_ptr, tag_ptr);
      *tag_ptr = 0;
    }
  }
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
  uptr d_aligned, d_size;
  AlignRange8((uptr)dest, 8, d_aligned, d_size);
  uptr shadow_start = MEM_TO_SHADOW(d_aligned);
  uptr origin_start = MEM_TO_ORIGIN(d_aligned);

  BorTag *tag_ptr = reinterpret_cast<BorTag *>(shadow_start);
  Block **block_ptr = reinterpret_cast<Block **>(origin_start);

  if (prov.block != nullptr)
    __bsan_rc_inc(prov.tag, prov.block, tag_ptr);
  if (*tag_ptr != 0)
    __bsan_rc_dec(*tag_ptr, *block_ptr, tag_ptr);

  // Record where the pointer begins within its slot.
  *block_ptr = prov.block;
  *tag_ptr = prov.tag | ((uptr)dest & kBorTagOffsetMask);
}
} // namespace __bsan
