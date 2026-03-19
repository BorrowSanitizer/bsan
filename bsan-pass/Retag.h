#ifndef BSAN_RETAG_H
#define BSAN_RETAG_H

#include "llvm/IR/Instructions.h"

namespace llvm {

class Value;
class ConstantInt;
class CallBase;

class Instruction;
class IntrinsicInst;

class RetagInfo {
public:
  Value *Ptr;
  Value *ImArray;
  ConstantInt *Size;
  ConstantInt *IsProtected;
  ConstantInt *IsFreeze;
  ConstantInt *IsUnpin;
  ConstantInt *PtrKind;
  RetagInfo(const CallBase *CB);
};

bool isFnEntryRetag(const CallBase *CB);
bool isRetag(const CallBase *CB);

} // namespace llvm
#endif