
#include "Retag.h"
#include "BorrowSanitizerPass.h"
#include "llvm/IR/Module.h"
namespace llvm {
// Indicates that this is a call to one of
// BorrowSanitizer's retag intrinsic functions.
bool IsRetag(const CallBase *CB) {
  Function *Callee = CB->getCalledFunction();
  return CB->arg_size() == 5 && Callee &&
         Callee->getName().starts_with(RUST_FN("retag"));
}

bool IsExpose(const CallBase *CB) {
  Function *Callee = CB->getCalledFunction();
  return CB->arg_size() == 1 && Callee &&
         Callee->getName().starts_with(RUST_FN("expose"));
}

PreservedAnalyses
BorrowSanitizerNoMergeRetagsPass::run(Module &M, ModuleAnalysisManager &AM) {
  for (Function &F : M) {
    if (F.getName().starts_with(RUST_FN("retag")))
      F.addFnAttr(Attribute::NoMerge);
  }
  return PreservedAnalyses::all();
}

} // namespace llvm