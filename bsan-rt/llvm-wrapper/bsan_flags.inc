#ifndef BSAN_FLAG
# error "Define BSAN_FLAG prior to including this file!"
#endif

// BSAN_FLAG(Type, Name, DefaultValue, Description)
// See COMMON_FLAG in sanitizer_flags.inc for more details.

BSAN_FLAG(bool, disable_node_debug_info, false,
          "Disable NodeDebugInfo diagnostics from the tree.")
BSAN_FLAG(uptr, stacktrace_max_len, 3,
          "Maximum number of frames captured for BorrowSanitizer stack traces.")
BSAN_FLAG(uptr, zct_per_gc, 10000,
          "Trigger a garbage collection request once this many provenance"
          "values have been added to the zero-count tables since the last"
          "collection. 0 disables the garbage collector.")
BSAN_FLAG(uptr, tree_gc_min_nodes, 64,
          "Only prune borrow trees with more than this many nodes."
          "0 makes every initialized tree prunable.")
BSAN_FLAG(uptr, max_compacted_children, 16,
          "Only compact away a dead node by reparenting its children onto its"
          "parent if doing so leaves the parent with at most this many children.")