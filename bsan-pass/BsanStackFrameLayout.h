#ifndef BSAN_STACKFRAMELAYOUT_H
#define BSAN_STACKFRAMELAYOUT_H

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"

namespace llvm {

class AllocaInst;

struct BSanStackVariableDescription {
const char *Name;    // Name of the variable that will be displayed by asan
                      // if a stack-related bug is reported.
uint64_t Size;       // Size of the variable in bytes.
size_t LifetimeSize; // Size in bytes to use for lifetime analysis check.
                      // Will be rounded up to Granularity.
uint64_t Alignment;  // Alignment of the variable (power of 2).
AllocaInst *AI;      // The actual AllocaInst.
size_t Offset;       // Offset from the beginning of the frame;
                      // set by ComputeASanStackFrameLayout.
unsigned Line;       // Line number.
};

// Output data struct for ComputeASanStackFrameLayout.
struct BSanStackFrameLayout {
uint64_t FrameSize;       // Size of the frame in bytes.
};

BSanStackFrameLayout ComputeBSanStackFrameLayout(
  // The array of stack variables. The elements may get reordered and changed.
  SmallVectorImpl<BSanStackVariableDescription> &Vars
);

} // llvm namespace

#endif  // BSAN_STACKFRAMELAYOUT_H