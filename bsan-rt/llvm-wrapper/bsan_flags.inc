//===-- bsan_flags.inc ------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// BSan runtime flags.
//
//===----------------------------------------------------------------------===//
#ifndef BSAN_FLAG
# error "Define BSAN_FLAG prior to including this file!"
#endif

// BSAN_FLAG(Type, Name, DefaultValue, Description)
// See COMMON_FLAG in sanitizer_flags.inc for more details.

BSAN_FLAG(bool, disable_node_debug_info, false,
          "Disable NodeDebugInfo diagnostics from the tree.")
BSAN_FLAG(uptr, stacktrace_max_len, 3,
          "Maximum number of frames captured for BorrowSanitizer stack traces.")