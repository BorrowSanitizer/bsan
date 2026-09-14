#include "bsan.h"
#include "bsan_interface_internal.h"

using namespace __bsan;

#if SANITIZER_CAN_USE_PREINIT_ARRAY
    __attribute__((section(".preinit_array"), used)) static auto preinit = __bsan_init;
#endif
