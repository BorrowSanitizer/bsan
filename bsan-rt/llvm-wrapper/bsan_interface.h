#ifndef BSAN_INTERFACE_H
#define BSAN_INTERFACE_H

#include "sanitizer_common/sanitizer_internal_defs.h"

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_deinit();
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_init();
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_reportError();

#endif
