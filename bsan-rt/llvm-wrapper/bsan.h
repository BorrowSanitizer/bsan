#ifndef BSAN_H
#define BSAN_H

#include "sanitizer_common/sanitizer_internal_defs.h"

extern THREADLOCAL void *__BSAN_CURR_THREAD;

extern bool bsan_inited;
extern bool bsan_init_is_running;
extern bool bsan_deinit_is_running;

#define BSAN_SANITIZER_TOOL_NAME "BorrowSanitizer"

namespace __bsan {
void BsanTSDInit();
void InitializeInterceptors();
} // namespace __bsan
#endif // BSAN_H
