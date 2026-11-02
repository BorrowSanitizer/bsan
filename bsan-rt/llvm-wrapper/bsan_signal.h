#ifndef BSAN_SIGNAL_H
#define BSAN_SIGNAL_H

#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_platform_limits_posix.h"

using namespace __sanitizer;

namespace __bsan {

// Implement the `sigaction` and `signal` interceptors. Instead of installing
// the program's handler, we record it and install a trampoline that calls it,
// so that the runtime controls when the program's handler runs. The program
// still sees its own handler through `oldact` and the return value of
// `signal`, never the trampoline.
int SigactionImpl(int signo, const __sanitizer_sigaction *act,
                  __sanitizer_sigaction *oldact);
uptr SignalImpl(int signo, uptr handler);

} // namespace __bsan

#endif // BSAN_SIGNAL_H
