#ifndef BSAN_RETAG_H
#define BSAN_RETAG_H
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"

namespace llvm {

#define RUST_PREFIX "__rust_"
#define RUST_FN(name) RUST_PREFIX name

class RetagInfo {
public:
  Value *Ptr;
  Value *ImArray;
  Value *PinArray;
  ConstantInt *Size;
  ConstantInt *Perms;

  RetagInfo(const CallBase *CB) {
    assert(CB->arg_size() == 5);
    Ptr = CB->getOperand(0);
    Size = cast<ConstantInt>(CB->getOperand(1));
    Perms = cast<ConstantInt>(CB->getOperand(2));
    ImArray = CB->getOperand(3);
    PinArray = CB->getOperand(4);
  }
  bool isProtected() {
    // The least significant bit of the permission indicates
    // if this is a function-entry retag.
    return (Perms->getZExtValue() & 0x1) != 0;
  }
};

bool IsFnEntryRetag(const CallBase *CB);
bool IsRetag(const CallBase *CB);

} // end namespace llvm

#endif