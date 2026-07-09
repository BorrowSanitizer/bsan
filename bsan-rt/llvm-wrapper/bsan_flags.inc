#ifndef BSAN_FLAG
# error "Define BSAN_FLAG prior to including this file!"
#endif

// BSAN_FLAG(Type, Name, DefaultValue, Description)
// See COMMON_FLAG in sanitizer_flags.inc for more details.

BSAN_FLAG(bool, disable_node_debug_info, false,
          "Disable NodeDebugInfo diagnostics from the tree.")
BSAN_FLAG(uptr, stacktrace_max_len, 3,
          "Maximum number of frames captured for BorrowSanitizer stack traces.")
BSAN_FLAG(uptr, visits_per_gc, 40000,
          "Trigger a garbage collection request after this many retags."
          "0 disables the garbage collector.")