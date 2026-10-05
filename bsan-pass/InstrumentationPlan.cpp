#include "InstrumentationPlan.h"
#include "llvm/Analysis/CycleAnalysis.h"

namespace llvm {

static cl::opt<bool>
    ClInstrumentAllocas("bsan-inst-allocas",
                        cl::desc("Instrument stack allocations (`alloca`)"),
                        cl::Hidden, cl::init(true));

static cl::opt<bool>
    ClInstrumentByval("bsan-inst-byval",
                      cl::desc("Instrument implicit `byval` allocations."),
                      cl::Hidden, cl::init(true));

// Indicates if all stack instrumentation has been disabled, covering both
// `alloca` and `byval` allocations.
//
// rustc parses `-Cllvm-args` before loading plugins passed via
// `-Zllvm-plugins`, so our options are not registered yet at parse time. The
// environment provides an alternative channel for disabling stack
// instrumentation when the pass is loaded through rustc instead of `opt`.
static bool disableStackInstrumentation() {
  return std::getenv("BSAN_DISABLE_STACK_INSTRUMENTATION") != nullptr;
}

bool InstrumentationPlan::shouldInstrumentByVal(const Argument &Arg) {
  return ClInstrumentByval && !disableStackInstrumentation() &&
         Arg.hasAttribute(Attribute::ByVal);
}

// We only instrument static allocas that have a non-zero size
// and cannot be proven safe via LLVM's StackSafetyAnalysis.
bool InstrumentationPlan::shouldInstrumentAlloca(const AllocaInst &AI) {
  if (!ClInstrumentAllocas || disableStackInstrumentation())
    return false;
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
      Checks[Inst].push_back(
          CheckInfo(CheckInfo::Read, MTI->getSource(), Range));
    }
    Checks[Inst].push_back(CheckInfo(CheckInfo::Write, MI->getDest(), Range));
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

  Checks[Inst].push_back(
      CheckInfo(AccessKind, Ptr, AccessRange(DL, AccessSize)));
}

void InstrumentationPlan::build(CycleInfo &CI) {
  // Collect each of the instructions might propagate provenance metadata.
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
        if (IsRetag(CB)) {
          Retags.push_back(CB);

          RetagInfo RI(CB);
          if (RI.isProtected()) {
            // If we see a function-entry retag within a cyclic subgraph
            // of the CFG, then we know that a function was inlined.
            // Protectors do not play well with inlining, so we treat this as
            // a regular retag.
            if (CI.getCycle(CB->getParent())) {
              RI.stripProtector();
            } else {
              NumFnEntryRetags += 1;
            }
          }
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
