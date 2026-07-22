#ifndef BSAN_INTERFACE_INTERNAL_H
#define BSAN_INTERFACE_INTERNAL_H

#include "sanitizer_common/sanitizer_internal_defs.h"
using namespace __sanitizer;

// Private BorrowSanitizer interface
extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_init();

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_abort();

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_memmove(void *dest, const void *src, uptr n);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_memcpy(void *dest, const void *src, uptr n);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_memset(void *s, int c, uptr n);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_shadow_clear(void *dest, uptr size);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_rc_dec(Node *node);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_rc_inc(Node *node);

// Tag of a concrete Node*. Must not be called on provenance sentinels.
// Prefer __bsan_node_tag_impl (Rust RT); CRT fallback reads Node::tag first
// word.
SANITIZER_INTERFACE_ATTRIBUTE
BorTag __bsan_node_tag(Node *node);

SANITIZER_INTERFACE_ATTRIBUTE
u32 __bsan_symbolize_pc(uptr pc, char *file_buf, uptr file_buf_len, u32 *line,
                        u32 *column);

SANITIZER_INTERFACE_ATTRIBUTE
uptr __bsan_read_file(const char *path, char **file_buf, uptr *file_buf_len);

SANITIZER_WEAK_ATTRIBUTE
Node *__bsan_alloc(void *base_addr, uptr size, BorTag bor_tag, Span pc);

SANITIZER_WEAK_ATTRIBUTE
void __bsan_dealloc(void *ptr, Node *node, Span pc, bool checked);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_read(void *ptr, uptr access_size, Node *node, bool checked);

SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_write(void *ptr, uptr access_size, Node *node, bool checked);

// Requests a garbage collection. Any thread may call this.
SANITIZER_INTERFACE_ATTRIBUTE
void __bsan_request_gc();

// Prunes tags from the tree rooted at `node`.
// Returns true if the tree is empty afterward (caller may eject the RootNode).
SANITIZER_WEAK_ATTRIBUTE
bool __bsan_prune(Node *node, BorTag *tags, uptr len);

// Frees a root Node / RootNode slot. The pointer must be nonnull and
// unreachable in shadow memory.
SANITIZER_WEAK_ATTRIBUTE
void __bsan_eject(Node *node);

// Inline root Node* for the allocation containing `node` (RootNode::from_node
// → RootNode::node_ptr). Used to canonicalize ZCT / live / pending map keys.
SANITIZER_WEAK_ATTRIBUTE
Node *__bsan_alloc_root(Node *node);

} // extern "C"

#endif
