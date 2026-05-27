#include "BorrowSanitizer.h"
#include "Provenance.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/Analysis/DomTreeUpdater.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/StackLifetime.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/AttributeMask.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/EHPersonalities.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PatternMatch.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/AtomicOrdering.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/EscapeEnumerator.h"
#include "llvm/Transforms/Utils/Instrumentation.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"

#define BSAN_PREFIX "__bsan_"
#define RUST_PREFIX "__rust_"

#define BSAN(name) BSAN_PREFIX name
#define BSAN_STATIC(name) BSAN_STATIC_PREFIX name
#define RUST_FN(name) RUST_PREFIX name

using namespace llvm;
using namespace llvm::PatternMatch;

static cl::opt<bool> ClHandleAsmConservative(
    "bsan-asm-conservative",
    cl::desc("Conservatively handle inline assembly by setting all pointer "
             "outputs to wildcard Provenance"),
    cl::Hidden, cl::init(true));

bool BorrowSanitizer::needsBoundaryValidation(const Function *Callee) {
  return !Callee ||
         (Callee->isDeclaration() || Callee->hasExternalLinkage() ||
          Callee->hasExternalWeakLinkage() || Callee->hasAddressTaken());
}

bool BorrowSanitizer::shouldTrustFunction(const TargetLibraryInfo *TLI,
                                          const Value *V) {
  if (isAllocationFn(V, TLI)) {
    return true;
  }

  if (const CallBase *CB = dyn_cast<CallBase>(V)) {
    return getFreedOperand(CB, TLI);
  }

  if (const Function *F = dyn_cast<Function>(V)) {
    LibFunc LibFn;
    TLI->getLibFunc(*F, LibFn);
    return isLibFreeFunction(F, LibFn);
  }

  return false;
}

static Value *ptradd(IRBuilder<> &IRB, Value *Pointer, Value *Offset) {
  if (match(Offset, m_Zero()))
    return Pointer;
  return IRB.CreateGEP(IRB.getInt8Ty(), Pointer, Offset);
}

// We only instrument allocations that have a non-zero size.
bool BorrowSanitizer::shouldInstrumentAlloca(const DataLayout &DL,
                                             const AllocaInst &AI) {
  // Although Rust emits retags for ZSTs, tracking
  // allocations leads to false positive errors—probably
  // due to interactions with lowering.
  Type *AllocType = AI.getAllocatedType();
  std::optional<TypeSize> AllocSize = AI.getAllocationSize(DL);
  return (AllocType->isSized() && AllocSize.has_value() &&
          !AllocSize.value().isZero());
}

static bool inSCC(DominatorTree &DT, LoopInfo &LI, BasicBlock *BB) {
  if (LI.getLoopFor(BB))
    return true;
  // It's still possible for us to have irreducible control flow, in which
  // case LLVM would not recognize a loop, but it would still be possible for
  // us to enter this basic block again. We would use LLVM's CycleInfo instead,
  // which would catch this, but it does not support incremental updates yet.
  for (BasicBlock *SuccBB : successors(BB)) {
    if (isPotentiallyReachable(SuccBB, BB, nullptr, &DT, &LI)) {
      return true;
    }
  }
  return false;
}

namespace {
/// Helper class to attach debug information of the given instruction onto new
/// instructions inserted after.
class NextNodeIRBuilder : public IRBuilder<> {
public:
  explicit NextNodeIRBuilder(Instruction *IP) : IRBuilder<>(IP->getNextNode()) {
    SetCurrentDebugLocation(IP->getDebugLoc());
  }
};

class RetagInfo {
public:
  Value *Ptr;
  Value *ImArray;
  Value *PinArray;
  ConstantInt *Size;
  ConstantInt *Perms;

  RetagInfo(const CallBase *CB) {
    assert(CB->arg_size() == 5);
    Ptr = CB->getOperand(0);
    Size = cast<ConstantInt>(CB->getOperand(1));
    Perms = cast<ConstantInt>(CB->getOperand(2));
    ImArray = CB->getOperand(3);
    PinArray = CB->getOperand(4);
  }
  bool isProtected() {
    // The least significant bit of the permission indicates
    // if this is a function-entry retag.
    return (Perms->getZExtValue() & 0x1) != 0;
  }
};
} // namespace

static bool isRetag(const CallBase *CB) {
  Function *Callee = CB->getCalledFunction();
  return CB->arg_size() == 5 && Callee &&
         Callee->getName().starts_with(RUST_FN("retag"));
}

static bool isFnEntryRetag(const CallBase *CB) {
  if (isRetag(CB)) {
    return RetagInfo(CB).isProtected();
  }
  return false;
}

// BorrowSanitizer uses a shadow stack to track the provenance values
// that are accessible in memory and to pass provenance between functions.
// We need the stack to be a contiguous array of provenance values to make it
// easy to scan and avoid consuming excess memory. Note: we use a combination of
// allocas and mem2reg to efficiently track stack offsets. This greatly
// simplifies the implementation but the same can be accomplished using only phi
// nodes. The result is equivalent either way.
class ShadowStackAllocator {
private:
  // We track the total number of stack slots used by this
  // function with a single alloca that gets promoted to a register.
  AllocaInst *GlobalOffsetAlloc = nullptr;
  // All shadow stack operations are dominated
  // by function-entry retags. We need to know
  // how many of these happened to be able to
  // remove their protectors when the function
  // returns.
  AllocaInst *FnEntryOffset = nullptr;
  // If we need to allocate a slot for an instruction,
  // then we load the incoming offset at the beginning of
  // its basic block. We increment it for subsequent
  // allocations in the same block, and then store it
  // back at the end of the block.
  DenseMap<BasicBlock *, Value *> BlockOffsets;
  // All of the allocas that we insert can be promoted
  // to registers.
  SmallVector<AllocaInst *> PromoteableAllocas;
  // Creates a counter alloca in the entry block of the
  // function and initializes it to 0. Zero-initialization
  // is crucial, since not all paths through a function will
  // allocate shadow stack slots, but all paths will pop the
  // current stack frame.
  AllocaInst *createEntryAlloca(BasicBlock *BB, Value *Init) {
    BasicBlock *EntryBB = &BB->getParent()->getEntryBlock();
    IRBuilder<> EntryIRB(&EntryBB->front());
    AllocaInst *EntryAlloc = EntryIRB.CreateAlloca(Init->getType());
    PromoteableAllocas.push_back(EntryAlloc);
    EntryIRB.CreateStore(Init, EntryAlloc);
    return EntryAlloc;
  }
  // Updates the current number of function entry retags to the given
  // value, initializing the counter if it doesn't exist.
  void updateFnEntryOffset(IRBuilder<> &IRB, Value *Offset, Type *Ty) {
    if (!FnEntryOffset) {
      BasicBlock *CurrBB = IRB.GetInsertBlock();
      FnEntryOffset = createEntryAlloca(CurrBB, ConstantInt::get(Ty, 0));
    }
    IRB.CreateStore(Offset, FnEntryOffset);
  }
  // Returns the total number of stack slots currently allocated
  // in the given basic block.
  Value *&getCurrentOffset(DominatorTree &DT, LoopInfo &LI, IRBuilder<> &IRB,
                           Type *Ty) {
    BasicBlock *InsertBB = IRB.GetInsertBlock();

    // If we already have an offset, then no initialization is necessary.
    auto It = BlockOffsets.find(InsertBB);
    if (It != BlockOffsets.end()) {
      return It->second;
    }

    // Otherwise, this could be the first time we allocate a slot.
    // We need to ensure that the global counter is initialized.
    if (!GlobalOffsetAlloc)
      GlobalOffsetAlloc = createEntryAlloca(InsertBB, ConstantInt::get(Ty, 0));

    // If we have a single predecessor, then we can use their outgoing offset
    // as our incoming offset.
    if (BasicBlock *PredBB = InsertBB->getSinglePredecessor()) {
      auto OffsetIt = BlockOffsets.find(PredBB);
      if (OffsetIt != BlockOffsets.end()) {
        Value *Offset = OffsetIt->getSecond();
        BlockOffsets[InsertBB] = Offset;
        // If this is a linear chain of blocks, then we can skip storing
        // the offset at the end of the predecessor and wait until the end
        // of this block to update the global counter.
        if (PredBB->getSingleSuccessor()) {
          BlockOffsets.erase(PredBB);
        }
        return BlockOffsets[InsertBB];
      }
    }

    Value *Offset;
    Value *GlobalOffset = IRB.CreateLoad(Ty, GlobalOffsetAlloc);
    if (inSCC(DT, LI, InsertBB)) {
      Value *InitVal = ConstantInt::get(Ty, -1, true);
      AllocaInst *CachedOffsetAlloc = createEntryAlloca(InsertBB, InitVal);
      Value *CachedOffset = IRB.CreateLoad(Ty, CachedOffsetAlloc);
      Value *Flag = IRB.CreateICmpEQ(CachedOffset, InitVal);
      Offset = IRB.CreateSelect(Flag, GlobalOffset, CachedOffset);
      IRB.CreateStore(Offset, CachedOffsetAlloc);
    } else {
      Offset = GlobalOffset;
    }
    BlockOffsets[InsertBB] = Offset;
    return BlockOffsets[InsertBB];
  }

public:
  // Allocates the requested number of slots and returns the offset from
  // the top of the frame.
  Value *alloc(DominatorTree &DT, LoopInfo &LI, IRBuilder<> &IRB,
               ElementCount EC, Type *Ty, bool IsFnEntry) {
    Value *&Offset = getCurrentOffset(DT, LI, IRB, Ty);
    Value *Elems = IRB.CreateElementCount(Ty, EC);
    Offset = IRB.CreateAdd(Offset, Elems);
    if (IsFnEntry) {
      updateFnEntryOffset(IRB, Offset, Ty);
    }
    return Offset;
  }
  // Returns the current offset from the top of the frame. This is used
  // to update the stack pointer before calling functions and to get the
  // total number of function-entry retags before popping a stack frame.
  Value *getOutgoingOffset(DominatorTree &DT, LoopInfo &LI, IRBuilder<> &IRB,
                           Type *Ty, bool IsFnEntry) {
    // We always need to create a load here, even if we have not allocated
    // any stack slots yet. Our instrumentation pass does a depth-first
    // traversal of the CFG, so it is possible that we have taken a path to an
    // exit point that has bypassed a stack slot allocation that we will see in
    // the future.
    if (IsFnEntry) {
      if (!FnEntryOffset) {
        FnEntryOffset =
            createEntryAlloca(IRB.GetInsertBlock(), ConstantInt::get(Ty, 0));
      }
      return IRB.CreateLoad(Ty, FnEntryOffset);
    }
    return getCurrentOffset(DT, LI, IRB, Ty);
  }

  // Stores the final offset for each basic block and attempts to promote the
  // counters to registers.
  void patchStackSlots(DominatorTree &DT) {
    if (!GlobalOffsetAlloc)
      return;
    // Only blocks that allocate slots will be instrumented.
    for (auto &[BB, Offset] : BlockOffsets) {
      // Acyclic blocks always update the global offset,
      // since we will never visit them again.
      IRBuilder<> ExitIRB(BB->getTerminator());
      ExitIRB.CreateStore(Offset, GlobalOffsetAlloc);
    }
    PromoteMemToReg(PromoteableAllocas, DT);
  }
};

class BorrowSanitizerVisitor : public InstVisitor<BorrowSanitizerVisitor> {
  friend class InstVisitor<BorrowSanitizerVisitor>;
  BorrowSanitizer &BS;
  Function &F;
  LLVMContext *C;

  // Cached analysis results
  const TargetLibraryInfo *TLI;
  DominatorTree &DT;
  LoopInfo LI;

  // The end of the prologue of the function, where we initialize our
  // instrumentation. This is a call to llvm.donothing.
  Instruction *FnPrologueEnd;
  // If a stack allocation does not have a dedicated lifetime.start, then we
  // allocate metadata for it within the entry block. We use a liveness pass to
  // determine which allocations need to be freed, so no additional handling is
  // necessary to determine where to free these allocations, even if they do not
  // have a lifetime.end, either.
  SmallDenseSet<AllocaInst *> HasLifetimeStart;

  SmallVector<AllocaInst *, 8> StaticAllocaVec;

  // Pointers to the sections of the thread-local array where the
  // provenance values for each argument are stored. Whenever we need to get the
  // provenance for an argument, we take its pointer from this array and then
  // insert the necessary instructions to load it from thread-local storage
  // within the prologue of the function.
  SmallDenseMap<Argument *, SmallVector<std::pair<Value *, ElementCount>>>
      ArgumentProvenance;

  // With the exception of allocas, each value is associated with a unique
  // provenance value.
  ProvenanceMap BaseProvMap;

  // Pointer-type arguments with the byval attribute point to a different
  // allocation than was originally allocated for the argument in the calling
  // context. This means that provenance passed by the caller will not be valid.
  // Instead, we treat this similar to an alloca and ignore our caller's
  // provenance. However, we still need to account for it when assigning slots
  // in our thread-local storage.
  SmallVector<Value *, 2> ByValArgs;

  // If a PHI node is a pointer or a vector of pointers, then we need to emit
  // corresponding "shadow" PHI nodes for its provenance. To emit these PHI
  // nodes, we need to know the provenance for each argument at each incoming
  // block. We only have this information once we have finished instrumenting
  // each block. So, we temporarily store our shadow PHI nodes and wait until
  // the end of the pass to "patch in" the missing provenance values. While
  // these values are pending, the PHI node will contain "wildcard" provenance
  // values. This is necessary since multiple LLVM APIs are implemented under
  // the assumption that any arbitrary PHI node will have at least one incoming
  // block, and that all incoming values will be initialized. Leaving a PHI node
  // in an  invalid state in the middle of the instrumentation pass inevitably
  // leads to memory corruption.
  SmallVector<std::tuple<PHINode *, Provenance, unsigned int>> ProvPHINodes;

  SmallVector<CallBase *> Retags;
  unsigned NumFnEntryRetags = 0;

  // The start of the current frame of protected tags. This is the "top" of the
  // frame, since we decrement to allocate slots.
  Value *FrameTop = nullptr;
  Value *FrameVariadicTop = nullptr;
  Value *FrameHeaderBottom = nullptr;

  // We use LLVM's lifetime analysis to determine which allocas are alive at
  // every exit point.
  std::unique_ptr<StackLifetime> LifetimeInfo;
  ShadowStackAllocator ShadowStack;
  AllocaInst *MarkerAlloca = nullptr;

public:
  BorrowSanitizerVisitor(Function &F, BorrowSanitizer &BS,
                         const TargetLibraryInfo &TLI, DominatorTree &DT)
      : F(F), BS(BS), C(BS.C), TLI(&TLI), DT(DT) {}
  bool run() {
    DomTreeUpdater DTU(DT, DomTreeUpdater::UpdateStrategy::Lazy);
    EscapeEnumerator EE(F, "bsan_cleanup", true, &DTU);
    while (IRBuilder<> *AtExit = EE.Next()) {
    }
    DTU.flush();
    LI.analyze(DT);

    BasicBlock *EntryBlock = &F.getEntryBlock();
    IRBuilder<> EntryIRB(EntryBlock, EntryBlock->getFirstNonPHIIt());
    SmallVector<Instruction *, 64> Instructions;

    for (BasicBlock *BB : depth_first<BasicBlock *>(&F.getEntryBlock())) {
      for (Instruction &I : *BB) {
        if (I.getMetadata(LLVMContext::MD_nosanitize))
          continue;
        if (I.getOpcode() == Instruction::Alloca) {
          AllocaInst &AI = static_cast<AllocaInst &>(I);
          if (BS.shouldInstrumentAlloca(*BS.DL, AI) && AI.isStaticAlloca())
            StaticAllocaVec.push_back(&AI);
          continue;
        }
        if (auto *CB = dyn_cast<CallBase>(&I)) {
          if (isRetag(CB)) {
            Retags.push_back(CB);
            if (isFnEntryRetag(CB))
              NumFnEntryRetags += 1;
          }
          if (auto *LI = dyn_cast<LifetimeIntrinsic>(CB)) {
            if (CB->getIntrinsicID() == Intrinsic::lifetime_start) {
              AllocaInst *AI = findAllocaForValue(LI->getArgOperand(1), true);
              if (AI && BS.shouldInstrumentAlloca(*BS.DL, *AI)) {
                HasLifetimeStart.insert(AI);
              }
            }
          }
        }
        Instructions.push_back(&I);
      }
    }

    initStack(EntryIRB);

    for (Instruction *I : Instructions) {
      InstVisitor<BorrowSanitizerVisitor>::visit(*I);
    }

    patchShadowPHINodes();
    ShadowStack.patchStackSlots(DT);

    for (CallBase *CB : Retags) {
      if (CB->getType()->isPointerTy()) {
        CB->replaceAllUsesWith(CB->getOperand(0));
      }
      CB->eraseFromParent();
    }
    return true;
  }

private:
  // Will fail with an error if anything other than a scalar provenance value is
  // present. If no provenance has been assigned yet, then return a wildcard
  // provenance value.
  Provenance assertProvenanceScalar(BasicBlock *BB, ProvenanceKey Key) {
    std::optional<Provenance> OptProv = getProvenance(BB, Key);
    if (OptProv.has_value()) {
      Provenance Prov = OptProv.value();
      if (Prov.Elems.isVector()) {
        report_fatal_error(
            "Expected scalar provenance, but found vector provenance!");
      }
      return Prov;
    }
    return Provenance::wildcard(BS.PL, ElementCount::getFixed(1));
  }

  Provenance assertProvenance(IRBuilder<> &IRB, ElementCount Elems,
                              ProvenanceKey Key) {
    BasicBlock *BB = IRB.GetInsertBlock();
    return assertProvenance(IRB, BB, Elems, Key);
  }

  // Asserts that there is either a provenance value at the given index, or that
  // no provenance values have been loaded for the given value, in which case we
  // return the null provenance value. Used whenever we need a provenance value
  // but do not care whether it's a vector or scalar. Checks for consistency
  // against a given provenance component.
  Provenance assertProvenance(IRBuilder<> &IRB, BasicBlock *BB,
                              ElementCount Elems, ProvenanceKey Key) {
    std::optional<Provenance> OptProv = getProvenance(BB, Key);
    if (OptProv.has_value()) {
      Provenance Prov = OptProv.value();
      if (Prov.Elems != Elems) {
        report_fatal_error("Provenance type mismatch.");
      }
      return Prov;
    }
    return Provenance::wildcard(BS.PL, Elems);
  }

  // Asserts that there is either a provenance value at the given index, or that
  // no provenance values have been loaded for the given value. Does not return
  // the null provenance value. This should never be used directly, since it
  // does not check that the provenance value being returned is consistent with
  // the caller's assumption about whether or not a scalar or vector provenance
  // value is required.
  std::optional<Provenance> getProvenance(BasicBlock *BB, ProvenanceKey Key) {
    if (Provenance *Prov = BaseProvMap.find(Key)) {
      return *Prov;
    }
    if (Argument *Arg = dyn_cast<Argument>(Key.V)) {
      // We always need to load the provenance for arguments right at the
      // beginning of the function. Otherwise, subsequent function calls could
      // overwrite them before they can be read from the shadow stack.
      IRBuilder<> EntryIRB(FnPrologueEnd);
      auto It = ArgumentProvenance.find(Arg);
      if (It != ArgumentProvenance.end()) {
        auto &ProvVec = It->second;
        if (Key.Offset >= ArgumentProvenance[Arg].size()) {
          report_fatal_error("Invalid argument provenance!");
        }
        Value *ArgProvenancePtr = ProvVec[Key.Offset].first;
        ElementCount Elems = ProvVec[Key.Offset].second;
        Provenance ArgProvenance =
            Provenance::load(EntryIRB, BS.PL, ArgProvenancePtr, Elems);
        setProvenance(Key, ArgProvenance);
        return ArgProvenance;
      }
    }

    return std::nullopt;
  }

  void setProvenance(ProvenanceKey Key, Provenance Prov) {
    BaseProvMap.set(Key, Prov);
  }

  // Stores a provenance value into shadow memory, starting at the given object
  // address.
  void storeProvenanceToShadow(IRBuilder<> &IRB, Value *ObjAddr,
                               Provenance Prov, AtomicOrdering Ordering) {
    if (Prov.Elems.isVector()) {
      report_fatal_error("Vectors are not supported.");
    } else {
      Value *Shadow = IRB.CreateCall(BS.BsanFuncShadow, {ObjAddr});
      IRB.CreateCall(BS.BsanFuncRcStore, {Prov.Tag, Prov.Info, Shadow});
    }
  }

  // Loads a provenance value into shadow memory
  // starting at the given object address via a
  // temporary buffer
  Provenance loadProvenanceFromShadow(IRBuilder<> &IRB, ProvenanceDesc &Comp,
                                      Value *ObjAddr, AtomicOrdering Ordering) {
    if (Comp.Elems.isVector()) {
      report_fatal_error("Vectors are not supported.");
    } else {
      Value *Slot = allocStackSlot(IRB, false);
      Value *Shadow = IRB.CreateCall(BS.BsanFuncShadow, {ObjAddr});
      Provenance Prov = Provenance::load(IRB, BS.PL, Shadow);
      Prov.store(IRB, BS.PL, Slot);
      return Prov;
    }
  }

  // Populates the array of argument provenance pointers and initializes the
  // start and end of the function prologue.
  void initStack(IRBuilder<> &TopIRB) {
    FnPrologueEnd = TopIRB.CreateIntrinsic(Intrinsic::donothing, {});
    IRBuilder<> EntryIRB(FnPrologueEnd);

    FrameTop = EntryIRB.CreateLoad(BS.PtrTy, BS.ProvStack);
    Value *NumParamProv = BS.Zero;

    Value *VarArgProvCount = nullptr;
    if (F.isVarArg()) {
      VarArgProvCount = EntryIRB.CreateLoad(BS.IntptrTy, BS.VarArgCounter);
    }

    for (auto &Arg : F.args()) {
      if (Arg.hasAttribute(Attribute::ByVal)) {
        Type *Ty = Arg.getParamByValType();
        TypeSize TS = BS.DL->getTypeAllocSize(Ty);
        Value *Size = EntryIRB.CreateTypeSize(BS.IntptrTy, TS);
        Value *Tag = newBorrowTag(EntryIRB);
        Value *Info = EntryIRB.CreateCall(BS.BsanFuncReserveStackSlot, {});
        EntryIRB.CreateCall(BS.BsanFuncAllocStack, {&Arg, Size, Tag, Info});
        setProvenance(&Arg, Provenance(Tag, Info));
        ByValArgs.push_back(&Arg);
        NumParamProv = EntryIRB.CreateAdd(NumParamProv, BS.One);
      } else {
        SmallVector<ProvenanceDesc> ProvDesc =
            BS.PL.getProvenanceDesc(EntryIRB, Arg.getType());
        for (auto &Desc : ProvDesc) {
          Value *NumProv = EntryIRB.CreateElementCount(BS.IntptrTy, Desc.Elems);
          NumParamProv = EntryIRB.CreateAdd(NumParamProv, NumProv);
          Value *ByteOffset =
              EntryIRB.CreateMul(NumParamProv, BS.PL.ProvenanceSize);
          Value *CurrentArraySlot =
              ptradd(EntryIRB, FrameTop, EntryIRB.CreateNeg(ByteOffset));
          ArgumentProvenance[&Arg].push_back(
              std::make_pair(CurrentArraySlot, Desc.Elems));
        }
      }
    }

    Value *ByteOffset = EntryIRB.CreateMul(NumParamProv, BS.PL.ProvenanceSize);
    FrameHeaderBottom =
        ptradd(EntryIRB, FrameTop, EntryIRB.CreateNeg(ByteOffset));

    if (F.isVarArg()) {
      Value *VarArgByteOffset =
          EntryIRB.CreateMul(VarArgProvCount, BS.PL.ProvenanceSize);
      FrameVariadicTop = FrameHeaderBottom;
      FrameHeaderBottom = ptradd(EntryIRB, FrameVariadicTop,
                                 EntryIRB.CreateNeg(VarArgByteOffset));
      EntryIRB.CreateStore(BS.Zero, BS.VarArgCounter);
    }

    if (BS.needsBoundaryValidation(&F)) {
      if (!BS.shouldTrustFunction(TLI, &F)) {
        EntryIRB.CreateCall(BS.BsanFuncValidateParams,
                            {&F, FrameHeaderBottom, NumParamProv});
      }
    }

    if (StaticAllocaVec.size() > 0 || ByValArgs.size() > 0) {
      for (auto &Arg : ByValArgs) {
        BasicBlock *BB = EntryIRB.GetInsertBlock();
        Provenance Prov = assertProvenanceScalar(BB, Arg);
        Value *SlotOffset = EntryIRB.CreateMul(ConstantInt::get(BS.IntptrTy, 1),
                                               BS.PL.ProvenanceSize);
        FrameHeaderBottom =
            ptradd(EntryIRB, FrameHeaderBottom, EntryIRB.CreateNeg(SlotOffset));
        Prov.store(EntryIRB, BS.PL, FrameHeaderBottom);
      }
      for (auto [Idx, AI] : llvm::enumerate(StaticAllocaVec)) {
        Provenance Prov = createAllocaMetadata(EntryIRB, AI);
        if (!HasLifetimeStart.contains(AI)) {
          NextNodeIRBuilder IRB(AI);
          initAllocaMetadata(IRB, AI, Prov);
        }
        setProvenance(AI, Prov);
        Value *SlotOffset = EntryIRB.CreateMul(ConstantInt::get(BS.IntptrTy, 1),
                                               BS.PL.ProvenanceSize);
        FrameHeaderBottom =
            ptradd(EntryIRB, FrameHeaderBottom, EntryIRB.CreateNeg(SlotOffset));
        Prov.store(EntryIRB, BS.PL, FrameHeaderBottom);
      }
    }
  }

  void patchShadowPHINodes() {
    IRBuilder<> EntryIRB(FnPrologueEnd);
    for (auto &[PN, Prov, Idx] : ProvPHINodes) {
      for (auto [V, IncomingBlock] :
           llvm::zip(PN->incoming_values(), PN->blocks())) {
        Provenance IncomingProv =
            assertProvenance(EntryIRB, IncomingBlock, Prov.Elems, {V, Idx});
        Prov.addIncoming(IncomingBlock, IncomingProv);
      }
    }
  }

  Value *newBorrowTag(IRBuilder<> &IRB) {
    return IRB.CreateAtomicRMW(AtomicRMWInst::Add, BS.BorTagCounter, BS.One,
                               std::nullopt, AtomicOrdering::Monotonic);
  }

  Value *getLayoutArrayLength(Value *Start) {
    if (GlobalVariable *GV = dyn_cast<GlobalVariable>(Start)) {
      if (ConstantDataArray *CA =
              dyn_cast<ConstantDataArray>(GV->getInitializer())) {
        unsigned NumPointerSizedPairs =
            CA->getNumElements() / (BS.DL->getTypeAllocSize(BS.IntptrTy) * 2);
        return ConstantInt::get(BS.IntptrTy, NumPointerSizedPairs);
      }
    }
    return BS.Zero;
  }

  void instrumentRetagMem(CallBase &CB) {
    IRBuilder<> IRB(&CB);
    Value *Operand = CB.getOperand(0);
    Value *SrcAddr = IRB.CreateLoad(BS.PtrTy, Operand);
    Value *Shadow = IRB.CreateCall(BS.BsanFuncShadow, {Operand});
    Provenance SrcProv = Provenance::load(IRB, BS.PL, Shadow);
    Provenance RetaggedProv = instrumentRetag(IRB, CB, SrcAddr, SrcProv);
    IRB.CreateCall(BS.BsanFuncRcStore,
                   {RetaggedProv.Tag, RetaggedProv.Info, Shadow});
  }

  void instrumentRetagReg(CallBase &CB) {
    IRBuilder<> IRB(&CB);
    if (auto Prov = getProvenance(CB.getParent(), CB.getOperand(0))) {
      Provenance Retagged = instrumentRetag(IRB, CB, CB.getOperand(0), *Prov);
      setProvenance(&CB, Retagged);
    }
  }

  Provenance instrumentRetag(IRBuilder<> &IRB, CallBase &CB, Value *Target,
                             Provenance TargetProv) {
    RetagInfo RI(&CB);

    Value *ImArrayLen = getLayoutArrayLength(RI.ImArray);
    Value *PinArrayLen = getLayoutArrayLength(RI.PinArray);

    TargetProv.Tag =
        IRB.CreateCall(BS.BsanFuncRetag, {Target, RI.Size, RI.Perms, RI.ImArray,
                                          ImArrayLen, RI.PinArray, PinArrayLen,
                                          TargetProv.Tag, TargetProv.Info});

    Value *SlotPtr = allocStackSlot(IRB, RI.isProtected());
    TargetProv.store(IRB, BS.PL, SlotPtr);

    return TargetProv;
  }

  Value *allocStackSlot(IRBuilder<> &IRB, bool IsFnEntry,
                        ElementCount Elems = ElementCount::getFixed(1)) {
    Value *SlotOffset =
        ShadowStack.alloc(DT, LI, IRB, Elems, BS.IntptrTy, IsFnEntry);
    Value *ProvOffset = IRB.CreateMul(SlotOffset, BS.PL.ProvenanceSize);
    return ptradd(IRB, FrameHeaderBottom, IRB.CreateNeg(ProvOffset));
  }

  Value *getStackOffset(IRBuilder<> &IRB, bool IsFnEntry) {
    Value *CurrOffset =
        ShadowStack.getOutgoingOffset(DT, LI, IRB, BS.IntptrTy, IsFnEntry);
    Value *ProvOffset = IRB.CreateMul(CurrOffset, BS.PL.ProvenanceSize);
    return ptradd(IRB, FrameHeaderBottom, IRB.CreateNeg(ProvOffset));
  }

  using InstVisitor<BorrowSanitizerVisitor>::visit;

  void visitCallBase(CallBase &CB) {
    assert(!CB.getMetadata(LLVMContext::MD_nosanitize));
    assert(!isa<IntrinsicInst>(CB) && "intrinsics are handled elsewhere");

    Function *Callee = CB.getCalledFunction();
    if (Callee) {
      if (isRetag(&CB)) {
        if (CB.getType() == BS.PtrTy) {
          return instrumentRetagReg(CB);
        }
        return instrumentRetagMem(CB);
      }
    }

    if (CB.isInlineAsm()) {
      if (ClHandleAsmConservative)
        visitAsmInstruction(CB);
      return;
    }

    if (auto *Call = dyn_cast<CallInst>(&CB)) {
      // We are going to insert code that relies on the fact that the callee
      // will become a non-readonly function after it is instrumented by us. To
      // prevent this code from being optimized out, mark that function
      // non-readonly in advance.
      // TODO: We can likely do better than dropping memory() completely here.
      AttributeMask B;
      B.addAttribute(Attribute::Memory).addAttribute(Attribute::Speculatable);
      Call->removeFnAttrs(B);
      if (Function *Func = Call->getCalledFunction()) {
        Func->removeFnAttrs(B);
      }
    }

    // If we've made it here, then we don't have a hard-coded way to handle this
    // function. We need to pass its arguments into our thread-local array and
    // then read the provenance for the return value.
    IRBuilder<> Before(&CB);

    Value *StackOffset;
    // if this is `mustail`, then we want to pop the frame,
    // and store the arguments within the frame header, as if the
    // call instruction that we are instrumenting was the next instruction
    // after this function returned.
    if (CB.isMustTailCall()) {
      popFrame(Before, CB, nullptr);
      StackOffset = FrameTop;
    } else {
      // Otherwise, we compute the current offset into the shadow stack.
      StackOffset = getStackOffset(Before, false);
      Before.CreateStore(StackOffset, BS.ProvStack);
    }

    // Store the provenance for each argument into the thread-local storage for
    // parameters. The process for computing provenance components is
    // deterministic, so we can guarantee that the callee will expect a
    // provenance value everywhere it's been stored here, unless we're dealing
    // with a situation where function bindings are incorrect, which is
    // undefined behavior.
    Value *NumParamProv = BS.Zero;
    Value *VarArgProvCount = BS.Zero;
    bool IsVarArg = CB.getFunctionType()->isVarArg();
    unsigned NumFixedParams = CB.getFunctionType()->getNumParams();

    for (const auto &[i, Arg] : llvm::enumerate(CB.args())) {
      SmallVector<ProvenanceDesc> ProvDesc =
          BS.PL.getProvenanceDesc(Before, Arg->getType());
      for (const auto &[Idx, Desc] : llvm::enumerate(ProvDesc)) {
        Value *NumProv = Before.CreateElementCount(BS.IntptrTy, Desc.Elems);
        NumParamProv = Before.CreateAdd(NumParamProv, NumProv);

        if (IsVarArg && i >= NumFixedParams) {
          VarArgProvCount = Before.CreateAdd(VarArgProvCount, NumProv);
        }

        Value *ByteOffset =
            Before.CreateMul(NumParamProv, BS.PL.ProvenanceSize);

        Value *Slot = ptradd(Before, StackOffset, Before.CreateNeg(ByteOffset));

        Provenance ProvSrc = assertProvenance(Before, Desc.Elems, {Arg, Idx});
        ProvSrc.store(Before, BS.PL, Slot);
      }
    }

    if (IsVarArg) {
      Before.CreateStore(VarArgProvCount, BS.VarArgCounter);
    }

    // Skip the epilogue for musttail calls, which need to be adjacent to `ret`.
    if (CB.isMustTailCall()) {
      return;
    }

    // We need to do some extra work here to compute where to insert our
    // instructions, since some function calls occur within terminators.
    Instruction *NextInst;
    if (auto *II = dyn_cast<InvokeInst>(&CB)) {
      if (II->getNormalDest()->getSinglePredecessor()) {
        NextInst = &II->getNormalDest()->front();
      } else {
        NextInst =
            &SplitEdge(II->getParent(), II->getNormalDest(), &DT, &LI)->front();
      }
    } else {
      assert(CB.getIterator() != CB.getParent()->end());
      NextInst = CB.getNextNode();
    }
    IRBuilder<> After(NextInst);
    After.SetCurrentDebugLocation(CB.getDebugLoc());

    Value *NumReturnProv = BS.Zero;
    SmallVector<Value *> ProvenancePointers;

    SmallVector<ProvenanceDesc> ReturnDesc =
        BS.PL.getProvenanceDesc(Before, CB.getType());

    if (CB.getType()->isSized()) {
      // Unsized return types do not have provenance, so we can skip handling
      // the return array.

      // Load each provenance component for the return type from the
      // thread-local return value array. Also, compute the byte-width of the
      // provenance components that we expect to be here. If the function that
      // we are calling is uninstrumented, then we need ensure that the return
      // array is populated with default values.
      for (const auto &[Idx, Desc] : llvm::enumerate(ReturnDesc)) {
        Value *Slot = allocStackSlot(Before, false, Desc.Elems);
        ProvenancePointers.push_back(Slot);
        Value *NumProv = Before.CreateElementCount(BS.IntptrTy, Desc.Elems);
        NumReturnProv = Before.CreateAdd(NumReturnProv, NumProv);
      }
    }
    // We need to validate thread-local storage before we load provenance
    // values from it, but we also need to know the number of provenance
    // values associated with the return value to perform initialization.
    Value *Slot = getStackOffset(Before, false);
    if (BS.needsBoundaryValidation(Callee)) {
      Value *Marker;

      if (BS.shouldTrustFunction(TLI, &CB)) {
        Marker = Before.CreateCall(BS.BsanFuncMark,
                                   {ConstantPointerNull::get(BS.PtrTy)});
        After.CreateStore(Marker, BS.Marker);
      } else {
        Marker = Before.CreateCall(BS.BsanFuncMark, {CB.getCalledOperand()});
        After.CreateCall(BS.BsanFuncValidateRetval,
                         {Marker, Slot, NumReturnProv});
      }

      if (auto *II = dyn_cast<InvokeInst>(&CB)) {
        if (!MarkerAlloca) {
          IRBuilder<> EntryIRB(FnPrologueEnd);
          MarkerAlloca = EntryIRB.CreateAlloca(BS.PtrTy);
          EntryIRB.CreateStore(ConstantPointerNull::get(BS.PtrTy),
                               MarkerAlloca);
        }
        Before.CreateStore(Marker, MarkerAlloca);
        BasicBlock *UnwindDest = II->getUnwindDest();
        IRBuilder<> UnwindIRB(UnwindDest, UnwindDest->getFirstInsertionPt());
        Value *ToRestore = UnwindIRB.CreateLoad(BS.PtrTy, MarkerAlloca);
        UnwindIRB.CreateStore(ToRestore, BS.Marker);
      }
    }
    for (const auto &[Idx, Ptr] : llvm::enumerate(ProvenancePointers)) {
      ElementCount Elems = ReturnDesc[Idx].Elems;
      Provenance Prov = Provenance::load(After, BS.PL, Ptr, Elems);
      setProvenance({&CB, Idx}, Prov);
    }
  }

  void visitAsmInstruction(CallBase &CB) {
    IRBuilder<> IRB(&CB);
    InlineAsm *IA = cast<InlineAsm>(CB.getCalledOperand());

    int NumRetOutputs = 0;
    Type *RetTy = CB.getType();
    if (!RetTy->isVoidTy()) {
      if (auto *ST = dyn_cast<StructType>(RetTy)) {
        NumRetOutputs = ST->getNumElements();
      } else {
        NumRetOutputs = 1;
      }
    }

    InlineAsm::ConstraintInfoVector Constraints = IA->ParseConstraints();
    unsigned NumOutputs = llvm::count_if(Constraints, [](const auto &Info) {
      return Info.Type == InlineAsm::isOutput;
    });

    NumOutputs -= NumRetOutputs;

    for (int Idx = 0; Idx < NumOutputs; Idx++) {
      Value *Operand = CB.getOperand(Idx);
      SmallVector<ProvenanceDesc> Components =
          BS.PL.getProvenanceDesc(IRB, Operand->getType());
      for (const auto &[Idx, Comp] : llvm::enumerate(Components)) {
        setProvenance({Operand, Idx}, Provenance::wildcard(BS.PL));
      }
    }
  }

  Provenance createScalarProvenancePHI(IRBuilder<> &IRB,
                                       iterator_range<pred_iterator> Blocks) {
    unsigned NumIncoming = std::distance(Blocks.begin(), Blocks.end());
    PHINode *TagNode = IRB.CreatePHI(BS.IntptrTy, NumIncoming, "_bsphi_tag");
    TagNode->dropDbgRecords();
    PHINode *InfoNode = IRB.CreatePHI(BS.PtrTy, NumIncoming, "_bsphi_info");
    InfoNode->dropDbgRecords();

    Provenance Wildcard = Provenance::wildcard(BS.PL);
    for (BasicBlock *BB : Blocks) {
      TagNode->addIncoming(Wildcard.Tag, BB);
      InfoNode->addIncoming(Wildcard.Info, BB);
    }
    return Provenance(TagNode, InfoNode);
  }

  Provenance createProvenancePHI(IRBuilder<> &IRB, ProvenanceDesc Comp,
                                 iterator_range<pred_iterator> Blocks) {
    if (Comp.Elems.isVector()) {
      report_fatal_error("Vectors are not supported.");
    }
    return createScalarProvenancePHI(IRB, Blocks);
  }

  void visitPHINode(PHINode &PN) {
    IRBuilder<> IRB(&PN);
    unsigned NumIncoming = PN.getNumIncomingValues();
    SmallVector<ProvenanceDesc> Components =
        BS.PL.getProvenanceDesc(IRB, PN.getType());
    for (auto [Idx, Comp] : llvm::enumerate(Components)) {
      Provenance Prov =
          createProvenancePHI(IRB, Comp, predecessors(PN.getParent()));
      setProvenance({&PN, Idx}, Prov);
      ProvPHINodes.push_back(std::make_tuple(&PN, Prov, Idx));
    }
  }

  void updateStackPointer(Instruction &I) {
    IRBuilder<> Before(&I);
    Value *StackOffset = getStackOffset(Before, false);
    Before.CreateStore(StackOffset, BS.ProvStack);
  }

  // Certain intrinsics and floating point conversions end up
  // being codegened into calls to instrumented components of
  // compiler-rt. We need to ensure that the stack pointer is
  // not clobbered when this happens.
  void visitFPToSIInst(CastInst &I) { updateStackPointer(I); }
  void visitFPToUIInst(CastInst &I) { updateStackPointer(I); }
  void visitSIToFPInst(CastInst &I) { updateStackPointer(I); }
  void visitUIToFPInst(CastInst &I) { updateStackPointer(I); }
  void visitFPExtInst(CastInst &I) { updateStackPointer(I); }
  void visitFPTruncInst(CastInst &I) { updateStackPointer(I); }

  // We can skip intrinsics that do not update the stack pointer.
  bool canSkipIntrinsic(IntrinsicInst &I) {
    return I.isDebugOrPseudoInst() || I.isLaunderOrStripInvariantGroup() ||
           I.isAssumeLikeIntrinsic() || I.isLifetimeStartOrEnd();
  }

  void visitIntrinsicInst(IntrinsicInst &I) {
    switch (I.getIntrinsicID()) {
    case Intrinsic::lifetime_start: {
      return instrumentLifetimeStart(I);
    } break;
    case Intrinsic::lifetime_end: {
      return instrumentLifetimeEnd(I);
    } break;
    }

    if (canSkipIntrinsic(I))
      return;

    updateStackPointer(I);
  }

  Provenance createAllocaMetadata(IRBuilder<> &IRB, AllocaInst *AI) {
    TypeSize TS = AI->getAllocationSize(*BS.DL).value();
    Value *Size = IRB.CreateTypeSize(BS.IntptrTy, TS);
    Value *Tag = newBorrowTag(IRB);
    Value *Info = IRB.CreateCall(BS.BsanFuncReserveStackSlot, {});
    return Provenance(Tag, Info);
  }

  void initAllocaMetadata(IRBuilder<> &IRB, AllocaInst *AI, Provenance Prov) {
    TypeSize TS = AI->getAllocationSize(*BS.DL).value();
    Value *Size = IRB.CreateTypeSize(BS.IntptrTy, TS);
    IRB.CreateCall(BS.BsanFuncAllocStack, {AI, Size, Prov.Tag, Prov.Info});
  }

  Provenance createAndInitAllocaMetadata(IRBuilder<> &IRB, AllocaInst *AI) {
    Provenance Prov = createAllocaMetadata(IRB, AI);
    initAllocaMetadata(IRB, AI, Prov);
    return Prov;
  }

  void instrumentLifetimeStart(IntrinsicInst &II) {
    AllocaInst *AI = findAllocaForValue(II.getArgOperand(0), true);
    IRBuilder<> IRB(&II);
    Provenance CurrentProv = assertProvenanceScalar(II.getParent(), AI);
    IRB.CreateCall(BS.BsanFuncDeallocStack,
                   {AI, CurrentProv.Tag, CurrentProv.Info});
    initAllocaMetadata(IRB, AI, CurrentProv);
  }

  void instrumentLifetimeEnd(IntrinsicInst &II) {
    AllocaInst *AI = findAllocaForValue(II.getArgOperand(0), true);
    IRBuilder<> IRB(&II);
    Provenance Root = assertProvenanceScalar(II.getParent(), AI);
    IRB.CreateCall(BS.BsanFuncDeallocStack, {AI, Root.Tag, Root.Info});
  }

  void visitMemSetInst(MemSetInst &I) {
    IRBuilder<> IRB(&I);
    Value *Val = IRB.CreateIntCast(I.getValue(), IRB.getInt32Ty(), false);
    Value *Size = IRB.CreateIntCast(I.getLength(), BS.IntptrTy, false);
    insertWriteCheck(IRB, I.getDest(), Size);
    IRB.CreateCall(BS.BsanFuncMemSet, {I.getDest(), Val, Size});
    I.eraseFromParent();
  }

  void visitMemMoveInst(MemMoveInst &I) {
    IRBuilder<> IRB(&I);
    Value *Size = IRB.CreateIntCast(I.getLength(), BS.IntptrTy, false);
    insertReadCheck(IRB, I.getSource(), Size);
    insertWriteCheck(IRB, I.getDest(), Size);
    IRB.CreateCall(BS.BsanFuncMemMove, {I.getDest(), I.getSource(), Size});
    I.eraseFromParent();
  }

  void visitMemCpyInst(MemCpyInst &I) {
    IRBuilder<> IRB(&I);
    Value *Size = IRB.CreateIntCast(I.getLength(), BS.IntptrTy, false);
    insertReadCheck(IRB, I.getSource(), Size);
    insertWriteCheck(IRB, I.getDest(), Size);
    IRB.CreateCall(BS.BsanFuncMemCpy, {I.getDest(), I.getSource(), Size});
    I.eraseFromParent();
  }

  void insertReadCheck(IRBuilder<> &IRB, Value *Ptr, Value *Size) {
    if (auto Prov = getProvenance(IRB.GetInsertBlock(), Ptr)) {
      IRB.CreateCall(BS.BsanFuncRead, {Ptr, Size, (*Prov).Tag, (*Prov).Info});
    }
  }

  void insertWriteCheck(IRBuilder<> &IRB, Value *Ptr, Value *Size) {
    if (auto Prov = getProvenance(IRB.GetInsertBlock(), Ptr)) {
      IRB.CreateCall(BS.BsanFuncWrite, {Ptr, Size, (*Prov).Tag, (*Prov).Info});
    }
  }

  void visitLoadInst(LoadInst &LI) {
    if (LI.isAtomic())
      return;

    IRBuilder<> IRB(&LI);
    Value *Ptr = LI.getPointerOperand();

    Value *Size =
        IRB.CreateTypeSize(BS.IntptrTy, BS.DL->getTypeStoreSize(LI.getType()));

    SmallVector<ProvenanceDesc> Components =
        BS.PL.getProvenanceDesc(IRB, LI.getType());

    Value *Base = LI.getPointerOperand();
    for (const auto &[Idx, Comp] : llvm::enumerate(Components)) {
      Value *ByteOffset = Comp.ByteOffset;
      Value *ObjAddr = ptradd(IRB, Base, ByteOffset);
      Provenance Prov =
          loadProvenanceFromShadow(IRB, Comp, ObjAddr, LI.getOrdering());
      setProvenance({&LI, Idx}, Prov);
    }
    insertReadCheck(IRB, Ptr, Size);
  }

  bool shouldClearProvenance(IRBuilder<> &IRB, StoreInst &SI) { return true; }

  void visitStoreInst(StoreInst &SI) {
    if (SI.isAtomic())
      return;

    IRBuilder<> PrevIRB(&SI);
    Value *Ptr, *Val;
    Ptr = SI.getPointerOperand();
    Val = SI.getValueOperand();

    Value *EntireSize = PrevIRB.CreateTypeSize(
        BS.IntptrTy, BS.DL->getTypeStoreSize(Val->getType()));
    insertWriteCheck(PrevIRB, Ptr, EntireSize);

    NextNodeIRBuilder IRB(&SI);

    bool Clear = shouldClearProvenance(IRB, SI);

    Value *Base = SI.getPointerOperand();
    SmallVector<ProvenanceDesc> ProvDesc =
        BS.PL.getProvenanceDesc(IRB, Val->getType());

    Value *Offset = BS.Zero;

    for (const auto &[Idx, Desc] : llvm::enumerate(ProvDesc)) {
      Value *ByteOffset = Desc.ByteOffset;
      if (Clear) {
        if (Offset != Desc.ByteOffset) {
          Value *CurrOffset = Offset;
          Value *GapSize = IRB.CreateSub(ByteOffset, CurrOffset);
          Value *BaseAddr = ptradd(IRB, Base, CurrOffset);
          clearProvenance(IRB, BaseAddr, GapSize, SI.getOrdering());
        }
        Offset = IRB.CreateAdd(Desc.ByteOffset, Desc.ByteWidth);
      }
      Value *ObjAddr = ptradd(IRB, Base, ByteOffset);
      Provenance Prov =
          assertProvenance(IRB, Desc.Elems, {SI.getValueOperand(), Idx});
      storeProvenanceToShadow(IRB, ObjAddr, Prov, SI.getOrdering());
    }

    if (Clear) {
      Value *OffsetVal = Offset;
      Value *Remaining = IRB.CreateSub(EntireSize, OffsetVal);
      Value *RemainingAddr = ptradd(IRB, Base, OffsetVal);
      clearProvenance(IRB, RemainingAddr, Remaining, SI.getOrdering());
    }
  }

  void clearProvenance(IRBuilder<> &IRB, Value *Base, Value *Size,
                       AtomicOrdering Ordering) {
    if (ConstantInt *CI = dyn_cast<ConstantInt>(Size)) {
      uint64_t Value = CI->getZExtValue();
      if (Value == 0)
        return;
      IRB.CreateCall(BS.BsanFuncShadowClear, {Base, Size});
    } else {
      report_fatal_error("Scalable vectors are not supported!");
    }
  }

  void visitGetElementPtrInst(GetElementPtrInst &I) {
    // Pointer arithmetic does not affect provenance.
    // We can propagage the provenance of the input to the output value.
    if (auto Prov = getProvenance(I.getParent(), I.getPointerOperand())) {
      setProvenance(&I, *Prov);
    }
  }

  void visitAddrSpaceCastInst(AddrSpaceCastInst &I) {
    // Address space casts do not affect provenance.
    // We can propagage the provenance of the input to the output value.
    if (auto Prov = getProvenance(I.getParent(), I.getPointerOperand())) {
      setProvenance(&I, *Prov);
    }
  }

  void visitBitCastInst(BitCastInst &I) {
    // Bitcasts propagate provenance.
    // TODO: The arguments to a bitcast are never aggregates, but they can
    // be vectors, which we do not support yet.
    Value *Src = I.getOperand(0);
    if (Src->getType()->isPointerTy() && I.getType()->isPointerTy()) {
      if (auto Prov = getProvenance(I.getParent(), Src)) {
        setProvenance(&I, *Prov);
      }
    }
  }

  // Computes the offset in terms of provenance components for an index into an
  // aggregate or array value. Used for implementing `extractvalue` and
  // `insertvalue`.
  std::pair<Type *, unsigned> getProvenanceOffset(IRBuilder<> &IRB, Type *Ty,
                                                  unsigned Idx) {
    if (auto *ST = dyn_cast<StructType>(Ty)) {
      unsigned Offset = 0;
      for (unsigned CurrIdx = 0; CurrIdx < Idx; ++CurrIdx) {
        Type *ElemType = ST->getElementType(CurrIdx);
        SmallVector<ProvenanceDesc> ProvDesc =
            BS.PL.getProvenanceDesc(IRB, ElemType);
        Offset += ProvDesc.size();
      }
      return {ST->getElementType(Idx), Offset};
    }

    if (auto *AT = dyn_cast<ArrayType>(Ty)) {
      SmallVector<ProvenanceDesc> ProvDesc =
          BS.PL.getProvenanceDesc(IRB, AT->getElementType());
      return {AT->getElementType(), ProvDesc.size() * Idx};
    }

    report_fatal_error("Cannot index into a non-struct or non-array type.");
  }

  void visitExtractValueInst(ExtractValueInst &EI) {
    IRBuilder<> IRB(&EI);
    Value *AggregateSrc = EI.getAggregateOperand();

    SmallVector<ProvenanceDesc> DestProvDesc =
        BS.PL.getProvenanceDesc(IRB, EI.getType());

    Type *CurrType = AggregateSrc->getType();
    uint64_t StartIdx = 0;
    for (auto &Idx : EI.indices()) {
      unsigned IdxOffset = 0;
      std::tie(CurrType, IdxOffset) = getProvenanceOffset(IRB, CurrType, Idx);
      StartIdx += IdxOffset;
    }

    for (auto [Offset, Desc] : llvm::enumerate(DestProvDesc)) {
      if (auto Prov = getProvenance(IRB.GetInsertBlock(),
                                    {AggregateSrc, StartIdx + Offset})) {
        setProvenance({&EI, Offset}, *Prov);
      }
    }
  }

  void visitInsertValueInst(InsertValueInst &II) {
    IRBuilder<> IRB(&II);
    BaseProvMap.transfer(II.getAggregateOperand(), &II);
    Value *ToInsert = II.getInsertedValueOperand();
    SmallVector<ProvenanceDesc> SrcProvDesc =
        BS.PL.getProvenanceDesc(IRB, ToInsert->getType());

    Type *CurrType = II.getType();
    uint64_t StartIdx = 0;
    for (auto &Idx : II.indices()) {
      unsigned IdxOffset = 0;
      std::tie(CurrType, IdxOffset) = getProvenanceOffset(IRB, CurrType, Idx);
      StartIdx += IdxOffset;
    }

    for (auto [Offset, Desc] : llvm::enumerate(SrcProvDesc)) {
      if (auto Prov = getProvenance(IRB.GetInsertBlock(), {ToInsert, Offset})) {
        setProvenance({&II, StartIdx + Offset}, *Prov);
      }
    }
  }

  void visitSelectInst(SelectInst &SI) {
    IRBuilder<> IRB(&SI);
    SmallVector<ProvenanceDesc> ProvDesc =
        BS.PL.getProvenanceDesc(IRB, SI.getType());

    for (auto [Idx, Desc] : llvm::enumerate(ProvDesc)) {
      if (Desc.Elems.isVector()) {
        report_fatal_error("Vectors are not supported.");
      } else {
        BasicBlock *BB = SI.getParent();
        Provenance ProvL = assertProvenanceScalar(BB, {SI.getTrueValue(), Idx});
        Provenance ProvR =
            assertProvenanceScalar(BB, {SI.getFalseValue(), Idx});

        Value *Tag, *Info;
        if (ProvL != ProvR) {
          Tag = IRB.CreateSelect(SI.getCondition(), ProvL.Tag, ProvR.Tag);
          Info = IRB.CreateSelect(SI.getCondition(), ProvL.Info, ProvR.Info);
        } else {
          Tag = ProvL.Tag;
          Info = ProvL.Info;
        }
        setProvenance({&SI, Idx}, Provenance(Tag, Info));
      }
    }
  }

  void popFrame(IRBuilder<> &IRB, Instruction &I, Value *RetVal) {
    BasicBlock *BB = IRB.GetInsertBlock();

    if (StaticAllocaVec.size() > 0 || ByValArgs.size() > 0 ||
        NumFnEntryRetags) {
      Value *AllocaSize = ConstantInt::get(BS.IntptrTy, StaticAllocaVec.size() +
                                                            ByValArgs.size());
      Value *NumProtectors =
          ShadowStack.getOutgoingOffset(DT, LI, IRB, BS.IntptrTy, true);
      Value *Offset = IRB.CreateMul(NumProtectors, BS.PL.ProvenanceSize);
      Value *FrameBottom =
          ptradd(IRB, FrameHeaderBottom, IRB.CreateNeg(Offset));
      IRB.CreateCall(BS.BsanFuncPopFrame,
                     {FrameBottom, NumProtectors, AllocaSize});
    }

    IRB.CreateStore(FrameTop, BS.ProvStack);

    if (RetVal) {
      SmallVector<ProvenanceDesc> ProvDesc =
          BS.PL.getProvenanceDesc(IRB, RetVal->getType());

      Value *NumReturnProv = BS.Zero;
      for (const auto &[Idx, Desc] : llvm::enumerate(ProvDesc)) {
        Value *NumProv = IRB.CreateElementCount(BS.IntptrTy, Desc.Elems);
        NumReturnProv = IRB.CreateAdd(NumReturnProv, NumProv);

        Value *ByteWidth = IRB.CreateMul(NumReturnProv, BS.PL.ProvenanceSize);
        Value *Slot = ptradd(IRB, FrameTop, IRB.CreateNeg(ByteWidth));

        Provenance Prov = assertProvenance(IRB, Desc.Elems, {RetVal, Idx});
        Prov.store(IRB, BS.PL, Slot);
      }
    }
  }

  void visitReturnInst(ReturnInst &I) {
    // musttail calls already pop the frame before the callsite.
    if (auto *CB = dyn_cast_or_null<CallBase>(I.getPrevNode()))
      if (CB->isMustTailCall())
        return;
    IRBuilder<> IRB(&I);
    popFrame(IRB, I, I.getReturnValue());
  }

  void visitResumeInst(ResumeInst &I) {
    IRBuilder<> IRB(&I);
    popFrame(IRB, I, I.getValue());
  }
};

Instruction *BorrowSanitizer::createBsanModuleDtor(Module &M) {
  IRBuilder<> IRB(M.getContext());

  BsanDtorFunction = Function::createWithDefaultAttr(
      FunctionType::get(IRB.getVoidTy(), false), GlobalValue::InternalLinkage,
      0, "bsan.module_dtor", &M);
  BsanDtorFunction->addFnAttr(Attribute::NoUnwind);

  BasicBlock *BsanDtorBB = BasicBlock::Create(*C, "", BsanDtorFunction);
  ReturnInst *BsanDtorRet = ReturnInst::Create(*C, BsanDtorBB);

  auto *FnTy = FunctionType::get(IRB.getVoidTy(), false);
  FunctionCallee DeinitFn = M.getOrInsertFunction(BSAN("deinit"), FnTy);

  IRB.SetInsertPoint(BsanDtorRet);
  CallInst *DeinitCall = IRB.CreateCall(DeinitFn, {});

  appendToUsed(M, {BsanDtorFunction});
  return DeinitCall;
}

bool BorrowSanitizer::instrumentModule(Module &M) {
  // TODO: add version check.
  std::tie(BsanCtorFunction, std::ignore) = createSanitizerCtorAndInitFunctions(
      M, "bsan.module_ctor", BSAN("init"), /*InitArgTypes=*/{},
      /*InitArgs=*/{}, "");

  bool CtorComdat = false;
  createBsanModuleDtor(M);

  IRBuilder<> IRB(BsanCtorFunction->getEntryBlock().getTerminator());
  instrumentGlobals(IRB, M, CtorComdat);

  assert(BsanCtorFunction && BsanDtorFunction);
  const int Priority = 1;

  // Put the constructor and destructor in comdat if both
  // (1) global instrumentation is not TU-specific
  // (2) target is ELF.
  if (CtorComdat && TargetTriple.isOSBinFormatELF()) {
    BsanCtorFunction->setComdat(M.getOrInsertComdat("bsan.module_ctor"));
    appendToGlobalCtors(M, BsanCtorFunction, Priority, BsanCtorFunction);

    BsanDtorFunction->setComdat(M.getOrInsertComdat("bsan.module_dtor"));
    appendToGlobalDtors(M, BsanDtorFunction, Priority, BsanDtorFunction);
  } else {
    appendToGlobalCtors(M, BsanCtorFunction, Priority);
    appendToGlobalDtors(M, BsanDtorFunction, Priority);
  }
  return true;
}

static Constant *getOrInsertTLSGlobal(Module &M, StringRef Name, Type *Ty) {
  return M.getOrInsertGlobal(Name, Ty, [&] {
    return new GlobalVariable(
        M, Ty, false, GlobalVariable::ExternalLinkage, nullptr, Name, nullptr,
        GlobalVariable::InitialExecTLSModel, std::nullopt, true);
  });
}
static Constant *getOrInsertGlobal(Module &M, StringRef Name, Type *Ty) {
  return M.getOrInsertGlobal(Name, Ty, [&] {
    return new GlobalVariable(
        M, Ty, false, GlobalVariable::ExternalLinkage, nullptr, Name, nullptr,
        GlobalVariable::NotThreadLocal, std::nullopt, true);
  });
}

BorrowSanitizer::GlobalDescription
BorrowSanitizer::getGlobalDescription(GlobalVariable *G) const {
  GlobalDescription Skip = {true, std::nullopt};
  Type *Ty = G->getValueType();

  if (G->hasSection()) {
    StringRef Section = G->getSection();
    if (Section.starts_with(".preinit_array") ||
        Section.starts_with(".init_array") ||
        Section.starts_with(".fini_array")) {
      Constant *Init = G->getInitializer()->stripPointerCasts();
      if (Function *F = dyn_cast<Function>(Init)) {
        return {true, F};
      }
    }
  }

  if (!G->hasInitializer())
    return Skip;

  if (auto *Init = G->getInitializer()) {
    Value *Func = Init->stripPointerCasts();
    if (auto *F = dyn_cast<Function>(Func)) {
      Skip.AssocFn = F;
    }
  }
  if (!Ty->isSized())
    return Skip;
  if (G->isThreadLocal())
    return Skip;
  return {true, Skip.AssocFn};
}

void BorrowSanitizer::instrumentGlobals(IRBuilder<> &IRB, Module &M,
                                        bool CtorComdat) {}

void BorrowSanitizer::initializeCallbacks(Module &M,
                                          const TargetLibraryInfo &TLI) {
  if (CallbacksInitialized) {
    return;
  }

  IRBuilder<> IRB(*C);

  AttributeList AL;

  Type *Int32Ty = Type::getInt32Ty(*C);
  Type *Int8Ty = Type::getInt8Ty(*C);

  AL = AL.addFnAttribute(*C, Attribute::NoUnwind);

  BsanFuncRetag = M.getOrInsertFunction(BSAN("retag"), AL, IntptrTy, PtrTy,
                                        IntptrTy, Int8Ty, PtrTy, IntptrTy,
                                        PtrTy, IntptrTy, IntptrTy, PtrTy);

  BsanFuncPopFrame = M.getOrInsertFunction(
      BSAN("pop_frame"), AL, IRB.getVoidTy(), PtrTy, IntptrTy, IntptrTy);

  BsanFuncRead = M.getOrInsertFunction(BSAN("read"), AL, IRB.getVoidTy(), PtrTy,
                                       IntptrTy, IntptrTy, PtrTy);

  BsanFuncWrite = M.getOrInsertFunction(BSAN("write"), AL, IRB.getVoidTy(),
                                        PtrTy, IntptrTy, IntptrTy, PtrTy);

  BsanFuncAllocStack =
      M.getOrInsertFunction(BSAN("alloc_stack"), AL, IRB.getVoidTy(), PtrTy,
                            IntptrTy, IntptrTy, PtrTy);
  BsanFuncDeallocStack = M.getOrInsertFunction(
      BSAN("dealloc_stack"), AL, IRB.getVoidTy(), PtrTy, IntptrTy, PtrTy);

  BsanFuncMark = M.getOrInsertFunction(BSAN("mark"), AL, PtrTy, PtrTy);

  BsanFuncValidateParams = M.getOrInsertFunction(
      BSAN("validate_params"), AL, IRB.getVoidTy(), PtrTy, PtrTy, IntptrTy);

  BsanFuncValidateRetval = M.getOrInsertFunction(
      BSAN("validate_retval"), AL, IRB.getVoidTy(), PtrTy, PtrTy, IntptrTy);

  BsanFuncShadow = M.getOrInsertFunction(BSAN("shadow"), AL, PtrTy, PtrTy);

  BsanFuncRcStore = M.getOrInsertFunction(BSAN("rc_store"), AL, IRB.getVoidTy(),
                                          IntptrTy, PtrTy, PtrTy);

  BsanFuncShadowClear = M.getOrInsertFunction(BSAN("shadow_clear"), AL,
                                              IRB.getVoidTy(), PtrTy, IntptrTy);

  BsanFuncMemCpy = M.getOrInsertFunction(BSAN("memcpy"), AL, IRB.getVoidTy(),
                                         PtrTy, PtrTy, IntptrTy);

  BsanFuncMemMove = M.getOrInsertFunction(BSAN("memmove"), AL, IRB.getVoidTy(),
                                          PtrTy, PtrTy, IntptrTy);

  BsanFuncMemSet = M.getOrInsertFunction(BSAN("memset"), AL, IRB.getVoidTy(),
                                         PtrTy, Int32Ty, IntptrTy);

  BsanFuncReserveStackSlot =
      M.getOrInsertFunction(BSAN("reserve_stack_slot"),
                            FunctionType::get(PtrTy, /*isVarArg=*/false), AL);

  BsanFuncDestroyStackSlot = M.getOrInsertFunction(BSAN("destroy_stack_slot"),
                                                   AL, IRB.getVoidTy(), PtrTy);

  EHPersonality Pers = getDefaultEHPersonality(TargetTriple);
  DefaultPersonalityFn =
      M.getOrInsertFunction(getEHPersonalityName(Pers),
                            FunctionType::get(Type::getInt32Ty(*C), true));

  createUserspaceApi(M, TLI);
  CallbacksInitialized = true;
}

void BorrowSanitizer::createUserspaceApi(Module &M,
                                         const TargetLibraryInfo &TLI) {
  IRBuilder<> IRB(*C);
  Marker = getOrInsertTLSGlobal(M, BSAN("marker"), PtrTy);
  VarArgCounter = getOrInsertTLSGlobal(M, BSAN("var_arg_ctr"), IntptrTy);
  ProvStack = getOrInsertTLSGlobal(M, BSAN("shadow_stack"), PtrTy);
  BorTagCounter = getOrInsertGlobal(M, BSAN("bor_tag_ctr"), IntptrTy);
}

bool BorrowSanitizer::instrumentFunction(Function &F,
                                         FunctionAnalysisManager &FAM) {
  if (F.empty()) {
    return false;
  }

  if (F.getLinkage() == GlobalValue::AvailableExternallyLinkage) {
    return false;
  }

  if (F.getName().starts_with(BSAN_PREFIX)) {
    return false;
  }

  if (F.getName().starts_with(RUST_FN("retag"))) {
    return false;
  }

  if (F.isPresplitCoroutine()) {
    return false;
  }

  if (F.hasFnAttribute(Attribute::DisableSanitizerInstrumentation)) {
    return false;
  }

  const TargetLibraryInfo &TLI = FAM.getResult<TargetLibraryAnalysis>(F);
  DominatorTree &DT = FAM.getResult<DominatorTreeAnalysis>(F);

  initializeCallbacks(*F.getParent(), TLI);
  BorrowSanitizerVisitor Visitor(F, *this, TLI, DT);

  AttributeMask B;
  B.addAttribute(Attribute::Memory).addAttribute(Attribute::Speculatable);
  F.removeFnAttrs(B);

  Visitor.run();

  F.addFnAttr(Attribute::DisableSanitizerInstrumentation);
  return true;
}