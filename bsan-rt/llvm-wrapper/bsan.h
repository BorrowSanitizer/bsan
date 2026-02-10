#ifndef BSAN_H
#define BSAN_H
#include "sanitizer_common/sanitizer_internal_defs.h"

extern THREADLOCAL void *__BSAN_CURR_THREAD;

extern bool bsan_inited;
extern bool bsan_init_is_running;
extern bool bsan_deinit_is_running;

#define BSAN_SANITIZER_TOOL_NAME "BorrowSanitizer"

using namespace __sanitizer;
namespace __bsan {
void BsanTSDInit();
void InitializeInterceptors();
} // namespace __bsan

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_print_current_stack_trace();
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_print_stack_trace(u32 stackID);
extern "C" SANITIZER_INTERFACE_ATTRIBUTE uptr __bsan_get_top_frame_pc(uptr pc);
extern "C" SANITIZER_INTERFACE_ATTRIBUTE u32
__bsan_StackDepotPut(uptr pc, uptr bp, u32 max_depth);
extern "C" SANITIZER_INTERFACE_ATTRIBUTE u32 __bsan_symbolize_pc(
    uptr pc, char *file_buf, uptr file_buf_len, u32 *line, u32 *column);
extern "C" SANITIZER_INTERFACE_ATTRIBUTE uptr
__bsan_read_file(const char *path, char **file_buf, uptr *file_buf_len);

#endif // BSAN_H
