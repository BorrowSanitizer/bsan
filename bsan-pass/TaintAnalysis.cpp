#include "TaintAnalysis.h"
#include "Retag.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Value.h"

using namespace llvm;

#define DEBUG_TYPE "bsan-analysis"

void FunctionTaintAnalysis::run() {
  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      if (auto *CB = dyn_cast<CallBase>(&I)) {
        if (IsRetag(CB) && CB->getType()->isPointerTy()) {
          RetagInfo RI(CB);
          if (auto *AI = findAllocaForValue(RI.Ptr)) {
            RetaggedAllocas.insert(AI);
          }
        }
      }
    }
  }
}

bool FunctionTaintAnalysis::isTainted(const Value *V) {
  if (auto *AI = dyn_cast<AllocaInst>(V)) {
    if (!RetaggedAllocas.contains(AI)) {
      if (!PointerMayBeCaptured(AI, /*ReturnCaptures=*/true)) {
        return false;
      }
    }
  }
  return true;
}