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
static bool CheckMemoryRangeAvailability(uptr beg, uptr size, bool verbose) {
  if (size > 0) {
    uptr end = beg + size - 1;
    if (!MemoryRangeIsAvailable(beg, end)) {
      if (verbose)
        Printf("FATAL: Memory range %p - %p is not available.\n", (void *)beg,
               (void *)end);
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
      Printf("FATAL: Cannot protect memory range %p - %p (%s).\n", (void *)beg,
             (void *)end, name);
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
      Printf("FATAL: Code %p is out of application range. Non-PIE build?\n",
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
          !CheckMemoryRangeAvailability(start, size, !dry_run))
        return false;
    }
    if (map) {
      if (dry_run && !CheckMemoryRangeAvailability(start, size, !dry_run))
        return false;
      if (!dry_run &&
          !MmapFixedSuperNoReserve(start, size, kMemoryLayout[i].name))
        return false;
      if (!dry_run && common_flags()->use_madv_dontdump)
        DontDumpShadowMemory(start, size);
    }
    if (protect) {
      if (dry_run && !CheckMemoryRangeAvailability(start, size, !dry_run))
        return false;
      if (!dry_run && !ProtectMemoryRange(start, size, kMemoryLayout[i].name))
        return false;
    }
  }

  return true;
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
      VReport(1, "WARNING: DataflowSanitizer: memory layout is incompatible, "
                 "possibly due to high-entropy ASLR.\n"
                 "Re-execing with fixed virtual address space.\n"
                 "N.B. reducing ASLR entropy is preferable.\n");
      CHECK_NE(personality(old_personality | ADDR_NO_RANDOMIZE), -1);
      ReExec();
    }
#endif
  }

  // The earlier dry run didn't actually map or protect anything. Run again in
  // non-dry run mode.
  return success && InitShadow(init_origins, false);
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

void CopyShadow(void *dest, const void *src, uptr size) {
  if (!MEM_IS_APP(dest))
    return;
  if (!MEM_IS_APP(src))
    return;
  CopyAligned((void *)MEM_TO_SHADOW(dest), (const void *)MEM_TO_SHADOW(src),
              size);
  CopyAligned((void *)MEM_TO_ORIGIN(dest), (const void *)MEM_TO_ORIGIN(src),
              size);
}

void MoveShadow(void *dest, const void *src, uptr size) {
  if (!MEM_IS_APP(dest))
    return;
  if (!MEM_IS_APP(src))
    return;
  MoveAligned((void *)MEM_TO_SHADOW(dest), (const void *)MEM_TO_SHADOW(src),
              size);
  MoveAligned((void *)MEM_TO_ORIGIN(dest), (const void *)MEM_TO_ORIGIN(src),
              size);
}

void ClearShadow(void *dest, uptr size) {
  if (!MEM_IS_APP(dest))
    return;
  uptr d_aligned, d_size;
  AlignRange8((uptr)dest, size, d_aligned, d_size);

  uptr shadow_start = MEM_TO_SHADOW(d_aligned);
  uptr origin_start = MEM_TO_ORIGIN(d_aligned);

  const uptr step = kMinProvAlignment;

  for (uptr offset = 0; offset < d_size; offset += step) {
    BorTag *tag_ptr = reinterpret_cast<BorTag *>(shadow_start + offset);
    AllocInfo **info_ptr =
        reinterpret_cast<AllocInfo **>(origin_start + offset);

    if (*info_ptr != nullptr)
      __bsan_rc_dec(*tag_ptr, *info_ptr);

    *info_ptr = nullptr;
  }
}

} // namespace __bsan
