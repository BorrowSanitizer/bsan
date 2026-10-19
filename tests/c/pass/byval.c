#include <stdint.h>
// %struct.Big = type { ptr, [2 x i64] }
typedef struct { 
    const uint64_t *ptr;
    uint64_t pad[2]; 
} Big;

// On x86, this struct will be received
// `byval`, with the annotated type above.
// However, it will be passed `byval` on
// the Rust side with a different type: `[i8 x 24]`.
// Integers do not have provenance, so the parameter
// TLS array will be left uninitialized. However, 
// boundary validation catches this function as
// possibly uninstrumented, clearing the
// TLS of the `byval` and zero-initializing the three
// slots that get read in on this side. 
uint64_t read_byval(Big b) {
    return *b.ptr; 
}