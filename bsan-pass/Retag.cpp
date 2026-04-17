#include "Retag.h"
#include "Declarations.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Value.h"

namespace llvm {

RetagInfo::RetagInfo(const CallBase *CB) {
  assert(CB->arg_size() == 7);
  Ptr = CB->getOperand(0);
  ImArray = CB->getOperand(1);
  Size = cast<ConstantInt>(CB->getOperand(2));
  IsProtected = cast<ConstantInt>(CB->getOperand(3));
  IsFreeze = cast<ConstantInt>(CB->getOperand(4));
  IsUnpin = cast<ConstantInt>(CB->getOperand(5));
  PtrKind = cast<ConstantInt>(CB->getOperand(6));
}

bool isRetag(const CallBase *CB) {
  Function *Callee = CB->getCalledFunction();
  return CB->arg_size() == 7 && Callee &&
         Callee->getName().starts_with(kBsanRustIntrinsicRetagPrefix);
}

bool isFnEntryRetag(const CallBase *CB) {
  if (isRetag(CB)) {
    ConstantInt *IsProtected = cast<ConstantInt>(CB->getOperand(3));
    return IsProtected->getZExtValue() != 0;
  }
  return false;
}
} // namespace llvm