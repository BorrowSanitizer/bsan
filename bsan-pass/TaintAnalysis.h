#ifndef BORROWSANITIZER_TAINT_ANALYSIS_H
#define BORROWSANITIZER_TAINT_ANALYSIS_H

#include "llvm/ADT/BitVector.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"

namespace llvm {

class BasicBlock;
class Function;
class Instruction;
class Value;

class FunctionTaintAnalysis {
  struct BlockInfo {
    explicit BlockInfo(unsigned Size)
        : Tainted(Size), TaintedIn(Size), TaintedOut(Size) {}
    /// Which objects are tainted by this basic block.
    BitVector Tainted;
    /// Which objects are tainted on entry to this block.
    BitVector TaintedIn;
    /// Which objects are tainted after exiting this block.
    BitVector TaintedOut;
  };

private:
  Function &F;
  using BlockInfoMap = DenseMap<const BasicBlock *, BlockInfo>;
  BlockInfoMap BlockInfo;

  SmallVector<const Value *> Objects;
  unsigned NumObjects;
  DenseMap<const Value *, unsigned> ObjectNumbering;

public:
  FunctionTaintAnalysis(Function &F);
  void run();
  /// Returns true if the alloca is alive after the instruction.
  bool isTainted(const Value *V) const;
};

} // end namespace llvm

#endif // BORROWSANITIZER_TAINT_ANALYSIS_H