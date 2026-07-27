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
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Instrumentation.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

namespace llvm {

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

  void build();

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

public:
  unsigned getNumFnEntryRetags() { return NumFnEntryRetags; }

  SmallVector<Instruction *, 64> &instructions() { return Instructions; }

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
};

} // namespace llvm
#endif