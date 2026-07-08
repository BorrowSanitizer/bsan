#include "bsan.h"
#include "bsan_interface_internal.h"
#include "bsan_allocator.h"
#include "interception/interception.h"
#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_allocator_report.h"
#include <stddef.h>

using namespace __bsan;

// Fake std::nothrow_t and std::align_val_t to avoid including <new>.
namespace std {
  struct nothrow_t {};
  enum class align_val_t: size_t {};
}  // namespace std

#  define OPERATOR_NEW_BODY(nothrow)  \
    void *res = bsan_malloc(size);    \
    return res

#  define OPERATOR_NEW_BODY_ALIGN(nothrow)                \
    void *res = bsan_memalign((uptr)align, size);         \
    return res;

/*
  bool already_in_scope = BlockInterception();                  \
  InterceptorBarrier barrier;                                   \
  void *ptr = bsan_malloc(size);                                \
  if (!already_in_scope && INST_CALLER(malloc)) {               \
    Provenance *RetSlot = GetSlot(0);                           \
    BorTag Tag = NewBorTag();                                   \
    *RetSlot = {Tag, __bsan_alloc(ptr, size, Tag, span)};       \
  }                                                             \
  return ptr;                                                   
*/

INTERCEPTOR_ATTRIBUTE
void *operator new(size_t size) { OPERATOR_NEW_BODY(false /*nothrow*/); }
INTERCEPTOR_ATTRIBUTE
void *operator new[](size_t size) { OPERATOR_NEW_BODY(false /*nothrow*/); }
INTERCEPTOR_ATTRIBUTE
void *operator new(size_t size, std::nothrow_t const&) {
  OPERATOR_NEW_BODY(true /*nothrow*/);
}
INTERCEPTOR_ATTRIBUTE
void *operator new[](size_t size, std::nothrow_t const&) {
  OPERATOR_NEW_BODY(true /*nothrow*/);
}
INTERCEPTOR_ATTRIBUTE
void *operator new(size_t size, std::align_val_t align)
{ OPERATOR_NEW_BODY_ALIGN(false /*nothrow*/); }
INTERCEPTOR_ATTRIBUTE
void *operator new[](size_t size, std::align_val_t align)
{ OPERATOR_NEW_BODY_ALIGN(false /*nothrow*/); }
INTERCEPTOR_ATTRIBUTE
void *operator new(size_t size, std::align_val_t align, std::nothrow_t const&)
{ OPERATOR_NEW_BODY_ALIGN(true /*nothrow*/); }
INTERCEPTOR_ATTRIBUTE
void *operator new[](size_t size, std::align_val_t align, std::nothrow_t const&)
{ OPERATOR_NEW_BODY_ALIGN(true /*nothrow*/); }

#define OPERATOR_DELETE_BODY \
  if (ptr) bsan_deallocate(ptr)

INTERCEPTOR_ATTRIBUTE
void operator delete(void *ptr) NOEXCEPT { OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete[](void *ptr) NOEXCEPT { OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete(void *ptr, std::nothrow_t const&) { OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete[](void *ptr, std::nothrow_t const&) {
  OPERATOR_DELETE_BODY;
}
INTERCEPTOR_ATTRIBUTE
void operator delete(void *ptr, size_t size) NOEXCEPT { OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete[](void *ptr, size_t size) NOEXCEPT
{ OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete(void *ptr, std::align_val_t align) NOEXCEPT
{ OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete[](void *ptr, std::align_val_t align) NOEXCEPT
{ OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete(void *ptr, std::align_val_t align, std::nothrow_t const&)
{ OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete[](void *ptr, std::align_val_t align, std::nothrow_t const&)
{ OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete(void *ptr, size_t size, std::align_val_t align) NOEXCEPT
{ OPERATOR_DELETE_BODY; }
INTERCEPTOR_ATTRIBUTE
void operator delete[](void *ptr, size_t size, std::align_val_t align) NOEXCEPT
{ OPERATOR_DELETE_BODY; }
