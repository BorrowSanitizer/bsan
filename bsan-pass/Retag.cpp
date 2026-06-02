
#include "Retag.h"

namespace llvm {
// Indicates that this is a call to one of
// BorrowSanitizer's retag intrinsic functions.
bool IsRetag(const CallBase *CB) {
  Function *Callee = CB->getCalledFunction();
  return CB->arg_size() == 5 && Callee &&
         Callee->getName().starts_with(RUST_FN("retag"));
}

// Indicates that this is a call to one of
// BorrowSanitizer's retag intrinsic functions,
// and that this represents a function-entry retag,
// which creates a protected permission.
bool IsFnEntryRetag(const CallBase *CB) {
  if (IsRetag(CB)) {
    return RetagInfo(CB).isProtected();
  }
  return false;
}
} // namespace llvm