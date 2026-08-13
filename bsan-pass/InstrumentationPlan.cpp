#include "InstrumentationPlan.h"

namespace llvm {

// We only instrument static allocas that have a non-zero size
// and cannot be proven safe via LLVM's StackSafetyAnalysis.
bool InstrumentationPlan::shouldInstrumentAlloca(const AllocaInst &AI) {
  // Although Rust emits retags for ZSTs, tracking these
  // allocations leads to false positive errors—probably
  // due to interactions with lowering.
  Type *AllocType = AI.getAllocatedType();
  std::optional<TypeSize> AllocSize = AI.getAllocationSize(*DL);
  return AllocType->isSized() && AllocSize.has_value() &&
         !AllocSize.value().isZero() &&
         // We only instrument static allocas
         AI.isStaticAlloca() &&
         // Retags are treated as an unknown source
         // of memory effects, so they block stack safety
         // from eliding checks for allocations that are
         // accessed in-bounds, but may still be subject to
         // aliasing violations.
         !SSGI.isSafe(AI);
}

void InstrumentationPlan::collectChecks(Instruction *Inst) {
  if (isa<MemSetInst>(Inst) || isa<MemTransferInst>(Inst)) {

    auto *MI = cast<MemIntrinsic>(Inst);
    AccessRange Range(DL, MI->getLength());

    if (auto *MTI = dyn_cast<MemTransferInst>(MI)) {
      Checks.emplace_back(Inst, CheckInfo::Read, MTI->getSource(), Range);
    }
    Checks.emplace_back(Inst, CheckInfo::Write, MI->getDest(), Range);
    return;
  }

  Value *Ptr;
  Type *AccessTy;
  CheckInfo::Kind AccessKind;

  if (auto *SI = dyn_cast<StoreInst>(Inst)) {
    Ptr = SI->getPointerOperand();
    AccessTy = SI->getValueOperand()->getType();
    AccessKind = CheckInfo::Write;
  } else if (auto *LI = dyn_cast<LoadInst>(Inst)) {
    Ptr = LI->getPointerOperand();
    AccessTy = LI->getType();
    AccessKind = CheckInfo::Read;
  } else {
    return;
  }

  TypeSize AccessSize = DL->getTypeStoreSize(AccessTy);
  if (AccessSize.isZero())
    return;

  Checks.emplace_back(Inst, AccessKind, Ptr, AccessRange(DL, AccessSize));
}

void InstrumentationPlan::build() {
  // Collect each of the instructions that might propagate provenance metadata.
  for (BasicBlock *BB : depth_first<BasicBlock *>(&F.getEntryBlock())) {
    for (Instruction &I : *BB) {
      // Skip instructions that are marked to be ignored by the sanitizers.
      if (I.getMetadata(LLVMContext::MD_nosanitize))
        continue;
      // Collect a list of static allocas to instrument.
      if (I.getOpcode() == Instruction::Alloca) {
        auto &AI = static_cast<AllocaInst &>(I);
        if (shouldInstrumentAlloca(AI))
          StaticAllocaVec.push_back(&AI);
        continue;
      }

      if (auto *CB = dyn_cast<CallBase>(&I)) {
        if (isRetag(CB)) {
          RetagInfo ChildRetag(CB);
          if (auto *Parent = dyn_cast<CallBase>(CB->getOperand(0))) {
            if (isRetag(Parent)) {
              RetagInfo ParentRetag(Parent);
              if (ParentRetag.canReplace(ChildRetag)) {
                CB->replaceAllUsesWith(Parent);
              }
            }
          }
          Retags.push_back(CB);
          if (ChildRetag.isProtected())
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

      collectChecks(&I);
      Instructions.push_back(&I);
    }
  }
}

} // namespace llvm
