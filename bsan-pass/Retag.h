#ifndef BSAN_RETAG_H
#define BSAN_RETAG_H
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
using namespace llvm;

namespace llvm {

#define RUST_PREFIX "__rust_"
#define RUST_FN(name) RUST_PREFIX name

class RetagInfo {
public:
  Value *Ptr;
  GlobalVariable *ImArray;
  GlobalVariable *PinArray;
  ConstantInt *Size;
  ConstantInt *Perms;
  CallBase *CB;
  RetagInfo(CallBase *CB) : CB(CB) {
    assert(CB->arg_size() == 5);
    Ptr = CB->getOperand(0);
    Size = cast<ConstantInt>(CB->getOperand(1));
    Perms = cast<ConstantInt>(CB->getOperand(2));
    ImArray = cast<GlobalVariable>(CB->getOperand(3));
    PinArray = cast<GlobalVariable>(CB->getOperand(4));
  }

  bool isProtected() {
    // The least significant bit of the permission
    // indicates whether this is a function-entry retag.
    return (Perms->getZExtValue() & 0x1) != 0;
  }

  bool canReplace(RetagInfo &Child) {
    bool NestedAliases =
        // This retag, the "parent", is only
        // used once.
        this->CB->hasOneUse()
        // The parent and the child are both
        // of the form `retag_reg`.
        && Child.CB->getType()->isPointerTy()
        // The first parameter of the child
        // is the parent.
        && Child.Ptr == this->CB;

    bool NestedSizes = Child.Size->getZExtValue() <= this->Size->getZExtValue();
    bool WellNested = NestedAliases && NestedSizes;

    // We compare each permission for equality, up to protection.
    // We can merge an unprotected permission into a protected one.
    uint64_t LhsUnprotected = this->Perms->getZExtValue() & (~0x1);
    uint64_t RhsUnprotected = Child.Perms->getZExtValue() & (~0x1);

    bool CompatiblePermissions = (RhsUnprotected == LhsUnprotected) &&
                                 Child.ImArray == this->ImArray &&
                                 Child.PinArray == this->PinArray;

    return WellNested && CompatiblePermissions;
  }
};

// Indicates that this is a call to one of
// BorrowSanitizer's retag intrinsic functions.
static std::optional<RetagInfo> getRetagInfo(Value *Val) {
  auto *CB = dyn_cast<CallBase>(Val);
  if (!CB)
    return std::nullopt;

  Function *Callee = CB->getCalledFunction();

  bool HasRetagSignature = CB->arg_size() == 5 && Callee &&
                           Callee->getName().starts_with(RUST_FN("retag"));

  if (HasRetagSignature) {
    return RetagInfo(CB);
  }
  return std::nullopt;
}
} // end namespace llvm

#endif