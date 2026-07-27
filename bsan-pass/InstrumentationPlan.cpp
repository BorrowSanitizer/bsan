#include "InstrumentationPlan.h"

namespace llvm {

// We only instrument static allocas that have a non-zero size
// and cannot be proven safe via LLVM's StackSafetyAnalysis.
bool InstrumentationPlan::shouldInstrumentAlloca(const AllocaInst &AI) {
  Type *AllocType = AI.getAllocatedType();
  std::optional<TypeSize> AllocSize = AI.getAllocationSize(*DL);
  return AllocType->isSized() && AI.isStaticAlloca() && !SSGI.isSafe(AI);
}

void InstrumentationPlan::build() {
  for (BasicBlock *BB : depth_first<BasicBlock *>(&F.getEntryBlock())) {
    for (Instruction &I : *BB) {
      if (I.getMetadata(LLVMContext::MD_nosanitize))
        continue;
      if (I.getOpcode() == Instruction::Alloca) {
        auto &AI = static_cast<AllocaInst &>(I);
        if (shouldInstrumentAlloca(AI))
          StaticAllocaVec.push_back(&AI);
        continue;
      }
      if (auto *CB = dyn_cast<CallBase>(&I)) {
        if (IsRetag(CB)) {
          Retags.push_back(CB);
          if (IsFnEntryRetag(CB))
            NumFnEntryRetags += 1;
        }
        if (auto *LI = dyn_cast<LifetimeIntrinsic>(CB)) {
          AllocaInst *AI = findAllocaForValue(LI->getArgOperand(0), true);
          if (AI && shouldInstrumentAlloca(*AI)) {
            if (CB->getIntrinsicID() == Intrinsic::lifetime_start) {
              HasLifetimeStart.insert(AI);
            }
          } else {
            continue;
          }
        }
      }
      Instructions.push_back(&I);
    }
  }
}
} // namespace llvm