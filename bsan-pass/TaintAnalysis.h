#ifndef BORROWSANITIZER_TAINT_ANALYSIS_H
#define BORROWSANITIZER_TAINT_ANALYSIS_H

#include "llvm/ADT/BitVector.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SmallPtrSet.h"

namespace llvm {

class BasicBlock;
class Function;
class Instruction;
class Value;

class FunctionTaintAnalysis {
private:
  Function &F;
  SmallPtrSet<const AllocaInst*, 32> RetaggedAllocas;
public:
  FunctionTaintAnalysis(Function &F);
  void run();
  /// Returns true if the alloca is alive after the instruction.
  bool isTainted(const Value *V) const;
};

} // end namespace llvm

#endif // BORROWSANITIZER_TAINT_ANALYSIS_H