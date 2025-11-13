#include "bsan.h"
#include "bsan_thread.h"
#include "sanitizer_common/sanitizer_common.h"

using namespace __sanitizer;
using namespace __bsan;

bool bsan_inited = false;
bool bsan_init_is_running;
bool bsan_deinit_is_running;

extern "C" {
void __bsan_internal_init();
void __bsan_internal_deinit();
}

static void BsanInit() {
  AvoidCVE_2016_2143();
  __bsan_internal_init();
  __sanitizer::InitializePlatformEarly();
}

static void BsanDeinit() { __bsan_internal_deinit(); }

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_init() {
  CHECK(!bsan_init_is_running);
  if (bsan_inited)
    return;
  bsan_init_is_running = true;
  BsanInit();
  InitializeInterceptors();

  BsanTSDInit();
  BsanThread *main_thread = BsanThread::Create(nullptr, nullptr);
  SetCurrentThread(main_thread);
  main_thread->Init();

  bsan_init_is_running = false;
  bsan_inited = true;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_deinit() {
  CHECK(!bsan_deinit_is_running);
  if (!bsan_inited)
    return;
  bsan_deinit_is_running = true;
  BsanDeinit();
  bsan_deinit_is_running = false;
  bsan_inited = false;
}