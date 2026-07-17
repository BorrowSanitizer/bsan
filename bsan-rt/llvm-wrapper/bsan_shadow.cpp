#include "bsan.h"
#include "bsan_interface_internal.h"
#include "sanitizer_common/sanitizer_common.h"
#if SANITIZER_LINUX
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
    if (type == MappingDesc::METADATA) {
      // The slab in `bsan_dense_alloc.h` indexes this region directly, so its
      // constants have to agree with the layout.
      CHECK_EQ(start, kMetadataSpace);
      CHECK_EQ(end - start, kMetadataSpaceSize);
    }
    if (type == MappingDesc::APP) {
      CHECK(MEM_IS_SHADOW(MEM_TO_SHADOW(start)));
      CHECK(MEM_IS_SHADOW(MEM_TO_SHADOW((start + end) / 2)));
      CHECK(MEM_IS_SHADOW(MEM_TO_SHADOW(end - 1)));
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

static bool InitShadow(bool dry_run) {
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
      Printf("FATAL: BorrowSanitizer: code %p is out of application range. "
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

    bool map = type == MappingDesc::SHADOW || type == MappingDesc::METADATA;
    bool protect = type == MappingDesc::INVALID;
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

static void ReportUnavailableMemoryRegions() {
  const uptr maxVirtualAddress = GetMaxUserVirtualAddress();
  for (unsigned i = 0; i < kMemoryLayoutSize; ++i) {
    uptr start = kMemoryLayout[i].start;
    uptr end = kMemoryLayout[i].end;
    uptr size = end - start;
    MappingDesc::Type type = kMemoryLayout[i].type;

    if (start >= maxVirtualAddress)
      continue;

    bool map = type == MappingDesc::SHADOW || type == MappingDesc::METADATA;
    bool protect = type == MappingDesc::INVALID;
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
  // Start with dry run: check layout is ok, but don't print warnings because
  // warning messages will cause tests to fail (even if we successfully re-exec
  // after the warning).
  bool success = InitShadow(true);
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
    ReportUnavailableMemoryRegions();
    return false;
  }

  // The earlier dry run didn't actually map or protect anything. Run again in
  // non-dry run mode.
  return InitShadow(false);
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

void MoveAligned(void *dest, const void *src, uptr size) {
  uptr d_aligned;
  uptr s_aligned, s_size;
  AlignPtr8((uptr)dest, d_aligned);
  AlignRange8((uptr)src, size, s_aligned, s_size);
  internal_memmove((void *)d_aligned, (const void *)s_aligned, s_size);
}

void CopyAligned(void *dest, const void *src, uptr size) {
  uptr d_aligned;
  uptr s_aligned, s_size;
  AlignPtr8((uptr)dest, d_aligned);
  AlignRange8((uptr)src, size, s_aligned, s_size);
  internal_memcpy((void *)d_aligned, (const void *)s_aligned, s_size);
}

ALWAYS_INLINE static void UpdateShadowSlot(uptr d_aligned, uptr s_aligned,
                                           uptr offset) {
  Provenance *dest =
      reinterpret_cast<Provenance *>(MEM_TO_SHADOW(d_aligned) + offset);
  Provenance *source =
      reinterpret_cast<Provenance *>(MEM_TO_SHADOW(s_aligned) + offset);

  Provenance src_prov = *source;
  Provenance dest_prov = *dest;
  __bsan_rc_inc(src_prov);
  __bsan_rc_dec(dest_prov);
  *dest = src_prov;
}

void CopyShadow(void *dest, const void *src, uptr size) {
  if (!MEM_IS_APP(dest))
    return;
  if (!MEM_IS_APP(src))
    return;
  if (size == 0)
    return;

  const uptr step = kMinProvAlignment;

  uptr d_aligned;
  uptr s_aligned, s_size;
  AlignPtr8((uptr)dest, d_aligned);
  AlignRange8((uptr)src, size, s_aligned, s_size);

  for (uptr offset = 0; offset < s_size; offset += step)
    UpdateShadowSlot(d_aligned, s_aligned, offset);
}

void MoveShadow(void *dest, const void *src, uptr size) {
  if (!MEM_IS_APP(dest))
    return;
  if (!MEM_IS_APP(src))
    return;
  if (size == 0)
    return;

  const uptr step = kMinProvAlignment;

  uptr d_aligned;
  uptr s_aligned, s_size;
  AlignPtr8((uptr)dest, d_aligned);
  AlignRange8((uptr)src, size, s_aligned, s_size);

  if (d_aligned == s_aligned)
    return;

  if (d_aligned < s_aligned) {
    for (uptr offset = 0; offset < s_size; offset += step)
      UpdateShadowSlot(d_aligned, s_aligned, offset);
  } else {
    for (uptr offset = s_size - step;; offset -= step) {
      UpdateShadowSlot(d_aligned, s_aligned, offset);
      // signed so must break at 0
      if (offset == 0)
        break;
    }
  }
}

void ClearShadow(void *dest, uptr size) {
  if (!MEM_IS_APP(dest))
    return;
  uptr d_aligned, d_size;
  AlignRange8((uptr)dest, size, d_aligned, d_size);

  uptr shadow_start = MEM_TO_SHADOW(d_aligned);

  const uptr step = kMinProvAlignment;

  for (uptr offset = 0; offset < d_size; offset += step) {
    Provenance *slot = reinterpret_cast<Provenance *>(shadow_start + offset);
    Provenance slot_prov = *slot;
    if (!IS_OMNIVALID(slot_prov)) {
      if (IS_CONCRETE(slot_prov)) {
        __bsan_rc_dec(slot_prov);
      }
      *slot = OMNIVALID;
    }
  }
}

void WriteShadow(void *dest, Provenance prov) {
  if (!MEM_IS_APP(dest))
    return;
  uptr d_aligned, d_size;
  AlignRange8((uptr)dest, 8, d_aligned, d_size);
  Provenance *slot = reinterpret_cast<Provenance *>(MEM_TO_SHADOW(d_aligned));

  __bsan_rc_inc(prov);
  __bsan_rc_dec(*slot);
  *slot = prov;
}
} // namespace __bsan
