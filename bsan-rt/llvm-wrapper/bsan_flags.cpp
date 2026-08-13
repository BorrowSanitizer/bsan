#include "bsan_flags.h"
#include "bsan.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_win_interception.h"

using namespace __sanitizer;

extern "C" SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE const char *
__bsan_default_options();

namespace __bsan {

Flags bsan_flags_dont_use_directly; // use via flags().

static const char *MaybeUseBsanDefaultOptionsCompileDefinition() {
#ifdef BSAN_DEFAULT_OPTIONS
  return SANITIZER_STRINGIFY(BSAN_DEFAULT_OPTIONS);
#else
  return "";
#endif
}

void Flags::SetDefaults() {
#define BSAN_FLAG(Type, Name, DefaultValue, Description) Name = DefaultValue;
#include "bsan_flags.inc"
#undef BSAN_FLAG
}

static void RegisterBsanFlags(FlagParser *parser, Flags *f) {
#define BSAN_FLAG(Type, Name, DefaultValue, Description)                       \
  RegisterFlag(parser, #Name, Description, &f->Name);
#include "bsan_flags.inc"
#undef BSAN_FLAG
}

static void DisplayHelpMessages(FlagParser *parser) {
  if (Verbosity()) {
    ReportUnrecognizedFlags();
  }

  if (common_flags()->help) {
    parser->PrintFlagDescriptions();
  }
}

static void InitializeDefaultFlags() {
  Flags *f = flags();
  FlagParser bsan_parser;

  // Set the default values and prepare for parsing BSan and common flags.
  SetCommonFlagsDefaults();
  {
    CommonFlags cf;
    cf.CopyFrom(*common_flags());
    if (const char *symbolizer_path = GetEnv("BSAN_SYMBOLIZER")) {
      cf.external_symbolizer_path = symbolizer_path;
    } else {
      cf.external_symbolizer_path = GetEnv("BSAN_SYMBOLIZER_PATH");
    }
    cf.allocator_may_return_null = 1;
    cf.exitcode = 1;
    OverrideCommonFlags(cf);
  }
  f->SetDefaults();

  RegisterBsanFlags(&bsan_parser, f);
  RegisterCommonFlags(&bsan_parser);

  // Override from BSan compile definition.
  const char *bsan_compile_def = MaybeUseBsanDefaultOptionsCompileDefinition();
  bsan_parser.ParseString(bsan_compile_def);

  // Override from user-specified string.
  const char *bsan_default_options = __bsan_default_options();
  bsan_parser.ParseString(bsan_default_options);

  // Override from command line.
  bsan_parser.ParseStringFromEnv("BSAN_OPTIONS");

  InitializeCommonFlags();

  DisplayHelpMessages(&bsan_parser);
}

// Validate flags and report incompatible configurations
static void ProcessFlags() {
  // Flags *f = flags();
  // Flag validation goes here.
}

void InitializeFlags() {
  InitializeDefaultFlags();
  ProcessFlags();

#if SANITIZER_WINDOWS
  // On Windows, weak symbols (such as the `__bsan_default_options` function)
  // are emulated by having the user program register which weak functions are
  // defined. The BSAN DLL will initialize flags prior to user module
  // initialization, so __bsan_default_options will not point to the user
  // definition yet. We still want to ensure we capture when options are passed
  // via
  // __bsan_default_options, so we add a callback to be run
  // when it is registered with the runtime.

  AddRegisterWeakFunctionCallback(
      reinterpret_cast<uptr>(__bsan_default_options), []() {
        // We call `InitializeDefaultFlags` again, instead of just parsing
        // `__bsan_default_options` directly, to ensure that flags set through
        // `BSAN_OPTS` take precedence over those set through
        // `__bsan_default_options`.
        InitializeDefaultFlags();
        ProcessFlags();
        ApplyFlags();
      });
#endif
}

} // namespace __bsan

extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE bool __bsan_disable_node_debug_info() {
  return __bsan::flags()->disable_node_debug_info;
}
SANITIZER_INTERFACE_ATTRIBUTE uptr __bsan_tree_gc_min_nodes() {
  return __bsan::flags()->tree_gc_min_nodes;
}
SANITIZER_INTERFACE_ATTRIBUTE uptr __bsan_max_compacted_children() {
  return __bsan::flags()->max_compacted_children;
}
SANITIZER_INTERFACE_ATTRIBUTE uptr __bsan_visits_per_gc() {
  return __bsan::flags()->visits_per_gc;
}
SANITIZER_INTERFACE_ATTRIBUTE uptr __bsan_tree_gc_target_dead_ratio_percent() {
  return __bsan::flags()->tree_gc_target_dead_ratio_percent;
}
SANITIZER_INTERFACE_ATTRIBUTE uptr __bsan_tree_gc_min_interval() {
  return __bsan::flags()->tree_gc_min_interval;
}
SANITIZER_INTERFACE_ATTRIBUTE uptr __bsan_tree_gc_max_interval() {
  return __bsan::flags()->tree_gc_max_interval;
}
}

SANITIZER_INTERFACE_WEAK_DEF(const char *, __bsan_default_options, void) {
  return "";
}

// Linker-time fallback
extern "C" SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE uptr
__bsan_current_gc_interval(void) {
  return __bsan::flags()->visits_per_gc;
}