#ifndef BSAN_INST_PLAN_H
#define BSAN_INST_PLAN_H

#include "BorrowSanitizerPass.h"
#include "Retag.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/Analysis/DomTreeUpdater.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/StackLifetime.h"
#include "llvm/Analysis/StackSafetyAnalysis.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/ConstantRange.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Instrumentation.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

namespace llvm {

// The extent of a memory access, in bytes, relative to the pointer being
// dereferenced. This has multiple components, which is necessary to handle
// static and dynamic ranges.
struct AccessRange {
  // The known minimum static range of the access. For dynamically-sized types,
  // like scalable vectors, this does not cover the full range of the access,
  // but it is sufficient for optimizing checks, because we can still coalesce
  // accesses of smaller sizes into a dynamically-sized check that is known to
  // be at least as large. An empty range indicates that we do not know anything
  // about the bounds of the access.
  ConstantRange StaticRange;
  // The size of the type. This only applies for checks associated with
  // operations like `load` and `store`, where a specific type determines the
  // size of the access.
  TypeSize Size = TypeSize::getFixed(0);
  // The (optional) dynamic size of the access. This is necessary to record
  // access sizes for memintrinsics.
  Value *DynValue = nullptr;

  AccessRange(const DataLayout *DL)
      : StaticRange(ConstantRange::getEmpty(DL->getPointerSizeInBits())) {}

  AccessRange(const DataLayout *DL, TypeSize AccessSize) : AccessRange(DL) {
    Size = AccessSize;
    APInt Bytes(StaticRange.getLower().getBitWidth(), Size.getKnownMinValue(),
                /*isSigned=*/true);
    if (Bytes.isNonNegative()) {
      StaticRange = ConstantRange(StaticRange.getLower(), Bytes);
    }
  }

  AccessRange(const DataLayout *DL, Value *Val) : AccessRange(DL) {
    DynValue = Val;
    if (auto *CL = dyn_cast<ConstantInt>(DynValue)) {
      unsigned BitWidth = StaticRange.getLower().getBitWidth();
      APInt APLen = CL->getValue().sextOrTrunc(BitWidth);
      if (APLen.isStrictlyPositive()) {
        StaticRange = ConstantRange(StaticRange.getLower(), APLen);
      }
    }
  }
};

// Everything needed to emit a runtime check validating read or write access for
// a given pointer, across a particular range.
struct CheckInfo {
  // The location where the check needs to be inserted.
  Instruction *InsertPt;
  enum Kind { Read, Write };
  Kind AccessKind;
  // The pointer being dereferenced.
  Value *Target;
  AccessRange Range;
  CheckInfo(Instruction *InsertPt, Kind AccessKind, Value *Target,
            AccessRange Range)
      : InsertPt(InsertPt), AccessKind(AccessKind), Target(Target),
        Range(Range) {}

  // Materializes the number of bytes that this check needs to validate, as a
  // value of type `Ty`, immediately before `InsertPt`. A runtime length takes
  // precedence; otherwise the count follows from the accessed type, which
  // `CreateTypeSize` expands into a `vscale` multiply when that type is
  // scalable.
  Value *getAccessSize(Type *Ty) const {
    IRBuilder<> IRB(InsertPt);
    return Range.DynValue ? IRB.CreateIntCast(Range.DynValue, Ty, false)
                          : IRB.CreateTypeSize(Ty, Range.Size);
  }
};

class InstrumentationPlan {
private:
  Function &F;
  const DataLayout *DL;

  // Cached analysis results
  DominatorTree &DT;
  const StackSafetyGlobalInfo &SSGI;

public:
  InstrumentationPlan(Function &F, const DataLayout *DL, DominatorTree &DT,
                      const StackSafetyGlobalInfo &SSGI)
      : F(F), DL(DL), DT(DT), SSGI(SSGI) {}

  void build(CycleInfo &CI);

private:
  // The static allocations that we will instrument.
  SmallVector<AllocaInst *, 8> StaticAllocaVec;

  // The static allocations that have a `lifetime.start` intrinsic.
  SmallDenseSet<const AllocaInst *> HasLifetimeStart;

  // A vector containing every retag intrinsic invocation. Since these are
  // "dummy" function calls, they need to be erased before the pass has
  // finished.
  SmallVector<CallBase *> Retags;

  // The number of function-entry retags that occurred.
  unsigned NumFnEntryRetags = 0;

  // Instructions to be visited by the subsequent instrumentation pass.
  SmallVector<Instruction *, 64> Instructions;

  // The locations where a runtime access check is required, in the order
  // that they are encountered while walking the function.
  SmallVector<CheckInfo, 32> Checks;

public:
  unsigned getNumFnEntryRetags() { return NumFnEntryRetags; }

  SmallVector<Instruction *, 64> &instructions() { return Instructions; }

  SmallVector<CheckInfo, 32> &checks() { return Checks; }

  SmallVector<AllocaInst *, 8> &allocas() { return StaticAllocaVec; }

  bool hasLifetimeStart(const AllocaInst *AI) {
    return HasLifetimeStart.contains(AI);
  }

  ~InstrumentationPlan() {
    for (CallBase *CB : Retags) {
      if (CB->getType()->isPointerTy()) {
        CB->replaceAllUsesWith(CB->getOperand(0));
      }
      CB->eraseFromParent();
    }
  }

private:
  bool shouldInstrumentAlloca(const AllocaInst &AI);
  void collectChecks(Instruction *Inst);
};

} // namespace llvm
#endif