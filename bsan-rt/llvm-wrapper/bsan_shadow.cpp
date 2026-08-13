#include "bsan_shadow.h"
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

    bool map = type == MappingDesc::SHADOW ||
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

    bool map = type == MappingDesc::SHADOW ||
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

ALWAYS_INLINE static void UpdateShadowSlot(uptr d_shadow, uptr d_origin,
                                           uptr s_shadow, uptr s_origin,
                                           uptr offset) {
  AllocInfo **dest_info_ptr = reinterpret_cast<AllocInfo **>(d_origin + offset);
  AllocInfo **source_info_ptr =
      reinterpret_cast<AllocInfo **>(s_origin + offset);

  BorTag *dest_tag_ptr = reinterpret_cast<BorTag *>(d_shadow + offset);
  BorTag *source_tag_ptr = reinterpret_cast<BorTag *>(s_shadow + offset);

  BorTag dest_tag = *dest_tag_ptr;
  BorTag source_tag = *source_tag_ptr;

  if (source_tag != 0)
    __bsan_rc_inc(source_tag, *source_info_ptr);
  if (dest_tag != 0)
    __bsan_rc_dec(dest_tag, *dest_info_ptr);

  *dest_tag_ptr = source_tag;

  if (source_tag != 0)
    *dest_info_ptr = *source_info_ptr;
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

  uptr d_shadow = MEM_TO_SHADOW(d_aligned);
  uptr d_origin = MEM_TO_ORIGIN(d_aligned);
  uptr s_shadow = MEM_TO_SHADOW(s_aligned);
  uptr s_origin = MEM_TO_ORIGIN(s_aligned);

  for (uptr offset = 0; offset < s_size; offset += step)
    UpdateShadowSlot(d_shadow, d_origin, s_shadow, s_origin, offset);
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

  uptr d_shadow = MEM_TO_SHADOW(d_aligned);
  uptr d_origin = MEM_TO_ORIGIN(d_aligned);
  uptr s_shadow = MEM_TO_SHADOW(s_aligned);
  uptr s_origin = MEM_TO_ORIGIN(s_aligned);

  if (d_aligned < s_aligned) {
    for (uptr offset = 0; offset < s_size; offset += step)
      UpdateShadowSlot(d_shadow, d_origin, s_shadow, s_origin, offset);
  } else {
    for (uptr offset = s_size - step;; offset -= step) {
      UpdateShadowSlot(d_shadow, d_origin, s_shadow, s_origin, offset);
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
  uptr origin_start = MEM_TO_ORIGIN(d_aligned);

  ClearShadowAligned(shadow_start, origin_start, d_size);
}

void ClearShadowAligned(uptr shadow_start, uptr origin_start,
                        uptr size_aligned) {

  const uptr step = kMinProvAlignment;

  for (uptr offset = 0; offset < size_aligned; offset += step) {
    BorTag *tag_ptr = reinterpret_cast<BorTag *>(shadow_start + offset);
    AllocInfo **info_ptr =
        reinterpret_cast<AllocInfo **>(origin_start + offset);

    // We use the borrow tag as a proxy for the initialization of the
    // `AllocInfo` component of provenance metadata.
    if (*tag_ptr != 0) {
      __bsan_rc_dec(*tag_ptr, *info_ptr);
      *tag_ptr = 0;
    }
  }
}

void WriteShadow(void *dest, Provenance prov) {
  if (!MEM_IS_APP(dest))
    return;
  uptr d_aligned, d_size;
  AlignRange8((uptr)dest, 8, d_aligned, d_size);
  uptr shadow_start = MEM_TO_SHADOW(d_aligned);
  uptr origin_start = MEM_TO_ORIGIN(d_aligned);

  BorTag *tag_ptr = reinterpret_cast<BorTag *>(shadow_start);
  AllocInfo **info_ptr = reinterpret_cast<AllocInfo **>(origin_start);

  if (prov.info != nullptr)
    __bsan_rc_inc(prov.tag, prov.info);
  if (*tag_ptr != 0)
    __bsan_rc_dec(*tag_ptr, *info_ptr);

  *info_ptr = prov.info;
  *tag_ptr = prov.tag;
}
} // namespace __bsan
