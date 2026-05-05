#include "bsan.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_libc.h"

using namespace __sanitizer;
using namespace __bsan;

namespace __bsan {
  
// Indicates to garbage collection thread(s)
// that the runtime is terminating. 
atomic_uint8_t gc_stop_flag;
// A pointer to the garbage collection thread state.
void *gc_thread_handler = nullptr;

static void *GCThreadFn(void *) {
  while (!atomic_load(&gc_stop_flag, memory_order_acquire))
    SleepForMillis(100);
  return nullptr;
}

void InitializeGC() {
    atomic_store(&gc_stop_flag, 0, memory_order_release);
    gc_thread_handler = internal_start_thread(GCThreadFn, nullptr);
}

void DeinitializeGC() {
    // end gc thread
    atomic_store(&gc_stop_flag, 1, memory_order_release);
    internal_join_thread(gc_thread_handler);
}

} // namespace __bsan
