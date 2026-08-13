
#include "Retag.h"

namespace llvm {
// Indicates that this is a call to one of
// BorrowSanitizer's retag intrinsic functions.
bool isRetag(CallBase *CB) {
  Function *Callee = CB->getCalledFunction();
  return CB->arg_size() == 5 && Callee &&
         Callee->getName().starts_with(RUST_FN("retag"));
}
} // namespace llvm