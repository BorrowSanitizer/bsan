#ifndef BSAN_RETAG_H
#define BSAN_RETAG_H
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/ErrorHandling.h"

namespace llvm {

#define RUST_PREFIX "__rust_"
#define RUST_FN(name) RUST_PREFIX name

class RetagInfo {
public:
  CallBase *CB;
  Value *Ptr;
  Value *ImArray;
  Value *PinArray;
  ConstantInt *Size;
  ConstantInt *Perms;

  RetagInfo(CallBase *CB) : CB(CB) {
    assert(CB->arg_size() == 5);
    // Compile-time check that all operands are constants (not a PHI or select),
    // which would be the result of a merge.
    if (!isa<ConstantInt>(CB->getOperand(1)) ||
        !isa<ConstantInt>(CB->getOperand(2)) ||
        !isa<Constant>(CB->getOperand(3)) || !isa<Constant>(CB->getOperand(4)))
      report_fatal_error(Twine("BorrowSanitizer: retag in `") +
                         CB->getFunction()->getName() +
                         "` has a non-constant operand. It was likely "
                         "merged with another retag by an optimization.");
    Ptr = CB->getOperand(0);
    Size = cast<ConstantInt>(CB->getOperand(1));
    Perms = cast<ConstantInt>(CB->getOperand(2));
    ImArray = CB->getOperand(3);
    PinArray = CB->getOperand(4);
  }

  bool isProtected() {
    // The least significant bit of the permission
    // indicates whether this is a function-entry retag.
    return (Perms->getZExtValue() & 0x1) != 0;
  }

  void stripProtector() {
    if (!isProtected())
      return;
    uint64_t OldVal = Perms->getZExtValue();
    uint64_t NewVal = OldVal & ~0x1;
    Perms = cast<ConstantInt>(ConstantInt::get(Perms->getType(), NewVal));
    CB->setOperand(2, Perms);
  }
};

bool IsRetag(const CallBase *CB);

} // end namespace llvm

#endif