#include "sanitizer_common/sanitizer_common.h"
#include "bsan.h"

using namespace __sanitizer;
using namespace __bsan;

namespace __bsan {
    bool bsan_inited = false;
    bool bsan_init_is_running;
    bool bsan_deinit_is_running;
}

extern "C" {
  void __bsan_internal_init();
  void __bsan_internal_deinit();
}

static void BSanInitializePlatform() {
  AvoidCVE_2016_2143();
  __bsan_internal_init();
  #ifdef BSAN_RUNTIME_VMA
    vmaSize = (MostSignificantSetBitIndex(GET_CURRENT_FRAME()) + 1);
  #if defined(__aarch64__) && !SANITIZER_APPLE
    if (vmaSize != 39 && vmaSize != 42 && vmaSize != 48) {
      Printf("FATAL: BorrowSanitizer: unsupported VMA range\n");
      Printf("FATAL: Found %d - Supported 39, 42 and 48\n", vmaSize);
      Die();
    } 
  #endif
  #endif
}

static void BSanDeinitializePlatform() {
  __bsan_internal_deinit();
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_init() {
  CHECK(!bsan_init_is_running);
  if (bsan_inited)
    return;
  bsan_init_is_running = true;
  BSanInitializePlatform();
  bsan_init_is_running = false;
  bsan_inited = true;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_deinit() {
  CHECK(!bsan_deinit_is_running);
  if (!bsan_inited)
    return;
  bsan_deinit_is_running = true;
  BSanDeinitializePlatform();
  bsan_deinit_is_running = false;
  bsan_inited = false;
}