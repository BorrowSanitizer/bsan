#ifndef BSAN_FLAGS_H
#define BSAN_FLAGS_H

#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_internal_defs.h"

// BSan flag values can be defined in four ways:
// 1) initialized with default values at startup.
// 2) overridden during compilation of BSan runtime by providing
// compile definition BSAN_DEFAULT_OPTIONS.
// 3) overridden from string returned by user-specified function
// __bsan_default_options().
// 4) overridden from env variable BSAN_OPTIONS.

namespace __bsan {

using __sanitizer::uptr;

struct Flags {
#define BSAN_FLAG(Type, Name, DefaultValue, Description) Type Name;
#include "bsan_flags.inc"
#undef BSAN_FLAG

  void SetDefaults();
};

extern Flags bsan_flags_dont_use_directly;
inline Flags *flags() { return &bsan_flags_dont_use_directly; }

void InitializeFlags();

} // namespace __bsan

#endif // BSAN_FLAGS_H