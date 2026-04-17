#include "BorrowSanitizer.h"
#include "Declarations.h"
#include "Provenance.h"
#include "Retag.h"
#include "llvm/Analysis/DomTreeUpdater.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/StackLifetime.h"
#include "llvm/Analysis/ValueTracking.h"
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

using namespace llvm;
using namespace llvm::PatternMatch;

/*
 * CLI Argument for handling inline assembly
 */
static cl::opt<bool> ClHandleAsmConservative(
    "bsan-asm-conservative",
    cl::desc("Conservatively handle inline assembly by setting all pointer "
             "outputs to wildcard Provenance"),
    cl::Hidden, cl::init(true));

namespace {
/// Helper class to attach debug information of the given instruction onto new
/// instructions inserted after.
class NextNodeIRBuilder : public IRBuilder<> {
public:
  explicit NextNodeIRBuilder(Instruction *IP) : IRBuilder<>(IP->getNextNode()) {
    SetCurrentDebugLocation(IP->getDebugLoc());
  }
};

Value *ptradd(IRBuilder<> &IRB, Value *Pointer, Value *Offset) {
  if (match(Offset, m_Zero()))
    return Pointer;
  return IRB.CreateGEP(IRB.getInt8Ty(), Pointer, Offset);
}

// We only instrument allocations that have a non-zero size.
bool shouldInstrumentAlloca(const DataLayout &DL, const AllocaInst &AI) {
  // Although Rust emits retags for ZSTs, tracking
  // allocations leads to false positive errors—probably
  // due to interactions with lowering.
  Type *AllocType = AI.getAllocatedType();
  std::optional<TypeSize> AllocSize = AI.getAllocationSize(DL);
  return (AllocType->isSized() && AllocSize.has_value() &&
          !AllocSize.value().isZero());
}

bool needsTLSValidation(const Function *Callee) {
  return !Callee ||
         (Callee->isDeclaration() || Callee->hasExternalLinkage() ||
          Callee->hasExternalWeakLinkage() || Callee->hasAddressTaken());
}

bool shouldTrustFunction(const TargetLibraryInfo *TLI, const Value *V) {
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

// Recursively populates a given vector with the list of descriptions of where
// provenance values live within a type.
std::tuple<Value *, Value *>
getProvenanceDesc(IRBuilder<> &IRB, const DataLayout *DL,
                  SmallVector<ProvenanceDesc> &ProvDesc, Type *ParentTy,
                  Type *CurrentTy, Value *ByteOffset, Value *ProvOffset) {
  Value *TypeSize =
      IRB.CreateTypeSize(IRB.getIntPtrTy(*DL), DL->getTypeAllocSize(CurrentTy));
  Value *NextProvOffset = ProvOffset;
  switch (CurrentTy->getTypeID()) {
  case Type::PointerTyID: {
    ProvenanceDesc Desc(ByteOffset, TypeSize, ElementCount::get(1, false));
    ProvDesc.push_back(Desc);
    Value *Elems = IRB.CreateElementCount(IRB.getIntPtrTy(*DL), Desc.Elems);
    NextProvOffset = IRB.CreateAdd(ProvOffset, Elems);
  } break;
  case Type::StructTyID: {
    StructType *ST = cast<StructType>(CurrentTy);
    Value *CurrByteOffset = ByteOffset;
    for (Type *ElemType : ST->elements()) {
      auto [BOffset, POffset] =
          getProvenanceDesc(IRB, DL, ProvDesc, ParentTy, ElemType,
                            CurrByteOffset, NextProvOffset);
      CurrByteOffset = BOffset;
      NextProvOffset = POffset;
    }
  } break;
  case Type::ArrayTyID: {
    ArrayType *AT = cast<ArrayType>(CurrentTy);
    Value *CurrByteOffset = ByteOffset;
    for (unsigned Idx = 0; Idx < AT->getNumElements(); ++Idx) {
      auto [BOffset, POffset] =
          getProvenanceDesc(IRB, DL, ProvDesc, ParentTy, AT->getElementType(),
                            CurrByteOffset, NextProvOffset);
      CurrByteOffset = BOffset;
      NextProvOffset = POffset;
    }
  } break;
  default:
    break;
  }
  Value *NextByteOffset = IRB.CreateAdd(ByteOffset, TypeSize);
  return std::make_tuple(NextByteOffset, NextProvOffset);
}

// Returns the descriptions for where provenance values are stored for a type.
SmallVector<ProvenanceDesc> getProvenanceDesc(IRBuilder<> &IRB,
                                              const DataLayout *DL, Type *Ty) {
  SmallVector<ProvenanceDesc> Desc;
  ConstantInt *Zero = ConstantInt::get(IRB.getIntPtrTy(*DL), 0);
  getProvenanceDesc(IRB, DL, Desc, Ty, Ty, Zero, Zero);
  return Desc;
}

// Computes the offset in terms of provenance components for an index into an
// aggregate or array value. Used for implementing `extractvalue` and
// `insertvalue`.
std::tuple<Type *, uint64_t>
offsetIntoProvenanceIndex(IRBuilder<> &IRB, const DataLayout *DL,
                          Type *CurrentTy, uint64_t Idx,
                          uint64_t PrevOffset = 0) {
  switch (CurrentTy->getTypeID()) {
  case Type::StructTyID: {
    StructType *ST = cast<StructType>(CurrentTy);
    assert(Idx < ST->getNumElements() &&
           "Index out of bounds for struct type.");
    uint64_t Offset = PrevOffset;
    for (unsigned CurrIdx = 0; CurrIdx < Idx; ++CurrIdx) {
      Type *ElemType = ST->getElementType(CurrIdx);
      SmallVector<ProvenanceDesc> ProvDesc =
          getProvenanceDesc(IRB, DL, ElemType);
      Offset += ProvDesc.size();
    }
    return std::make_tuple(ST->getElementType(Idx), Offset);
  } break;
  case Type::ArrayTyID: {
    ArrayType *AT = cast<ArrayType>(CurrentTy);
    assert(Idx < AT->getNumElements() && "Index out of bounds for array type.");
    SmallVector<ProvenanceDesc> ProvDesc =
        getProvenanceDesc(IRB, DL, AT->getElementType());
    return std::make_tuple(AT->getElementType(), PrevOffset + ProvDesc.size());
  } break;
  default: {
    report_fatal_error("Cannot index into a non-struct or non-array type.");
  }
  }
}

} // namespace

// Tracks the current offset within the shadow stack.
class ShadowStackAllocator {
private:
  AllocaInst *TotalOffset = nullptr;
  DenseMap<BasicBlock *, Value *> BlockOffsets;

public:
  Value *&getCurrentOffset(BasicBlock *InsertBB, Type *Ty) {
    Value *&BlockOffset = BlockOffsets[InsertBB];
    if (!TotalOffset) {
      BasicBlock *EntryBB = &InsertBB->getParent()->getEntryBlock();
      IRBuilder<> EntryIRB(&EntryBB->front());
      TotalOffset = EntryIRB.CreateAlloca(Ty);

      Value *Zero = ConstantInt::get(Ty, 0);
      EntryIRB.CreateStore(Zero, TotalOffset);
      BlockOffset = Zero;
    }

    if (!BlockOffset) {
      IRBuilder<> FrontIRB(InsertBB, InsertBB->getFirstInsertionPt());
      BlockOffset = FrontIRB.CreateLoad(Ty, TotalOffset);
    }

    return BlockOffset;
  }

  // Allocates the requested number of slots and returns the offset from the top
  // of the frame.
  Value *alloc(IRBuilder<> &IRB, ElementCount EC, Type *Ty) {
    Value *&Offset = getCurrentOffset(IRB.GetInsertBlock(), Ty);
    Value *Elems = IRB.CreateElementCount(Ty, EC);
    Offset = IRB.CreateAdd(Offset, Elems);
    return Offset;
  }

  // Returns the current offset from the top of the frame.
  Value *getOutgoingOffset(BasicBlock *BB, Type *Ty) {
    return getCurrentOffset(BB, Ty);
  }

  void patchStackSlots(DominatorTree &DT) {
    if (!TotalOffset)
      return;
    for (auto &[BB, Offset] : BlockOffsets) {
      IRBuilder<> ExitIRB(BB->getTerminator());
      ExitIRB.CreateStore(Offset, TotalOffset);
    }
    PromoteMemToReg({TotalOffset}, DT);
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

  // The end of the "prologue" of the function, where we initialize our
  // instrumentation. This is a call to `llvm.donothing()`.
  Instruction *FnPrologueEnd;

  // All relevant instructions in reverse postorder
  SmallVector<Instruction *, 64> Instructions;

  // If a stack allocation does not have a dedicated `lifetime.start`, then we
  // allocate metadata for it within the entry block. We use a liveness pass to
  // determine which allocations need to be freed, so no additional handling is
  // necessary to determine where to free these allocations, even if they do not
  // have a `lifetime.end`, either.
  DenseSet<AllocaInst *> HasLifetimeStart;
  SmallVector<AllocaInst *, 8> StaticAllocaVec;

  // Pointers to the sections of the thread-local array (BS.ParamTLS) where the
  // provenance values for each argument are stored. Whenever we need to get the
  // provenance for an argument, we take its pointer from this array and then
  // insert the necessary instructions to load it from thread-local storage
  // within the prologue of the function.
  DenseMap<Argument *, SmallVector<ProvenancePtr>> ArgumentProvenance;

  // With the exception of `allocas`, each value is associated with a unique
  // provenance value. Provenanced values are indexed by each provenance
  // carrying component. For example, if `ProvenanceComponents[V]` has length 3,
  // then `ProvenanceMap[std::make_pair(V, 2)]` would return the third
  // provenance value within `V`.
  ProvenanceMap BaseProvMap;

  // Pointer-type arguments with the `byval` attribute point to a different
  // allocation than was originally allocated for the argument in the calling
  // context. This means that provenance passed by the caller will not be valid.
  // Instead, we treat this similar to an `alloca` and ignore our caller's
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
  // The number of function-entry retags. If none occur, then we can skip
  // creating and popping a frame to contain protected tags.
  unsigned NumFnEntryRetags = 0;

  // The start of the current frame of protected tags. This is the "top" of the
  // frame, since we decrement to allocate slots.
  Value *FrameTop = nullptr;

  // We use LLVM's lifetime analysis to determine which `allocas` are alive at
  // every exit point.
  std::unique_ptr<StackLifetime> LifetimeInfo;

  ShadowStackAllocator FnEntrySlots;

public:
  BorrowSanitizerVisitor(Function &F, BorrowSanitizer &BS,
                         const TargetLibraryInfo &TLI, DominatorTree &DT)
      : F(F), BS(BS), C(BS.C), TLI(&TLI), DT(DT) {}
  bool run() {
    DomTreeUpdater DTU(DT, DomTreeUpdater::UpdateStrategy::Lazy);
    removeUnreachableBlocks(F, &DTU);
    EscapeEnumerator EE(F, "bsan_cleanup", true, &DTU);
    while (IRBuilder<> *AtExit = EE.Next()) {
    }
    DTU.flush();

    BasicBlock *EntryBlock = &F.getEntryBlock();
    IRBuilder<> EntryIRB(EntryBlock, EntryBlock->getFirstNonPHIIt());

    populateBlocks(EntryIRB);

    initStack(EntryIRB);

    for (Instruction *I : Instructions) {
      InstVisitor<BorrowSanitizerVisitor>::visit(*I);
    }

    patchShadowPHINodes();
    FnEntrySlots.patchStackSlots(DT);

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
  ProvenanceScalar assertProvenanceScalar(BasicBlock *BB, ProvenanceKey Key) {
    std::optional<Provenance> OptProv = getProvenance(BB, Key);
    if (OptProv.has_value()) {
      Provenance Prov = OptProv.value();
      if (Prov.Elems.isVector()) {
        report_fatal_error(
            "Expected scalar provenance, but found vector provenance!");
      } else {
        ProvenanceScalar Scalar = Prov.assertScalar();
        return Scalar;
      }
    }
    return BS.WildcardProvenance;
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
    return Provenance::wildcard(IRB, BS.PL, Elems);
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
      // overwrite them before they can be read from TLS
      IRBuilder<> EntryIRB(FnPrologueEnd);
      if (ArgumentProvenance.count(Arg)) {
        if (Key.Offset >= ArgumentProvenance[Arg].size()) {
          report_fatal_error("Invalid argument provenance!");
        }
        ProvenancePtr ArgProvenancePtr = ArgumentProvenance[Arg][Key.Offset];
        Provenance ArgProvenance =
            Provenance::load(EntryIRB, BS.PL, ArgProvenancePtr);
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
    ProvenancePtr ProvPtr;
    if (Prov.Elems.isVector()) {
      report_fatal_error("Vectors are not supported.");
    } else {
      ProvenanceScalar Scalar = Prov.assertScalar();
      Value *ShadowPointer = IRB.CreateCall(BS.BsanFuncShadowStore,
                                            {Scalar.Tag, Scalar.Info, ObjAddr});
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
      Value *Tmp = IRB.CreateAlloca(BS.PL.ProvenanceTy, nullptr);
      IRB.CreateCall(BS.BsanFuncShadowLoad, {ObjAddr, Tmp});
      ProvenancePtrScalar ProvPtr(IRB, BS.PL, Tmp);
      return Provenance::load(IRB, BS.PL, ProvPtr);
    }
  }

  void populateBlocks(IRBuilder<> &IRB) {
    for (BasicBlock *BB :
         ReversePostOrderTraversal<BasicBlock *>(&F.getEntryBlock())) {
      for (Instruction &I : *BB) {
        if (I.getMetadata(LLVMContext::MD_nosanitize))
          continue;
        if (I.getOpcode() == Instruction::Alloca) {
          AllocaInst &AI = static_cast<AllocaInst &>(I);
          if (shouldInstrumentAlloca(*BS.DL, AI) && AI.isStaticAlloca())
            StaticAllocaVec.push_back(&AI);
          continue;
        }

        if (CallBase *CB = dyn_cast<CallBase>(&I)) {
          if (isRetag(CB)) {
            Retags.push_back(CB);
            if (isFnEntryRetag(CB)) {
              NumFnEntryRetags += 1;
            }
          }
          if (IntrinsicInst *I = dyn_cast<IntrinsicInst>(CB)) {
            if (CB->getIntrinsicID() == Intrinsic::lifetime_start) {
              AllocaInst *AI = findAllocaForValue(I->getArgOperand(1), true);
              if (!AI)
                continue;
              if (!shouldInstrumentAlloca(*BS.DL, *AI))
                continue;
              HasLifetimeStart.insert(AI);
            }
          }
        }
        Instructions.push_back(&I);
      }
    }
  }

  // Populates the array of argument provenance pointers and initializes the
  // start and end of the function prologue.
  void initStack(IRBuilder<> &EntryIRB) {
    Value *NumParamProv = BS.Zero;
    for (auto &Arg : F.args()) {
      if (Arg.hasAttribute(Attribute::ByVal)) {
        Type *Ty = Arg.getParamByValType();
        TypeSize TS = BS.DL->getTypeAllocSize(Ty);
        Value *Size = EntryIRB.CreateTypeSize(BS.IntptrTy, TS);
        Value *Tag = newBorrowTag(EntryIRB);
        Value *Info = EntryIRB.CreateCall(BS.BsanFuncReserveStackSlot, {});
        EntryIRB.CreateCall(BS.BsanFuncAllocStack, {&Arg, Size, Tag, Info});
        setProvenance(&Arg, ProvenanceScalar(Tag, Info));
        ByValArgs.push_back(&Arg);
        NumParamProv = EntryIRB.CreateAdd(NumParamProv, BS.One);
      } else {
        SmallVector<ProvenanceDesc> ProvDesc =
            getProvenanceDesc(EntryIRB, BS.DL, Arg.getType());
        for (auto &Desc : ProvDesc) {
          Value *CurrentArrayByteOffset =
              EntryIRB.CreateMul(NumParamProv, BS.PL.ProvenanceSize);
          Value *CurrentArraySlot =
              ptradd(EntryIRB, BS.ParamTLS, CurrentArrayByteOffset);
          ProvenancePtr Ptr =
              ProvenancePtr(EntryIRB, BS.PL, CurrentArraySlot, Desc.Elems);
          ArgumentProvenance[&Arg].push_back(Ptr);

          Value *NumProv = EntryIRB.CreateElementCount(BS.IntptrTy, Desc.Elems);
          NumParamProv = EntryIRB.CreateAdd(NumParamProv, NumProv);
        }
      }
    }

    if (needsTLSValidation(&F)) {
      if (!shouldTrustFunction(TLI, &F)) {
        EntryIRB.CreateCall(BS.BsanFuncValidateParamTLS, {&F, NumParamProv});
      }
    }

    FrameTop = EntryIRB.CreateLoad(BS.PtrTy, BS.ProvStack);

    if (StaticAllocaVec.size() > 0) {
      for (AllocaInst *AI : StaticAllocaVec) {
        if (HasLifetimeStart.contains(AI)) {
          setProvenance(AI, createAllocaMetadata(EntryIRB, AI));
        } else {
          ProvenanceScalar Prov = createAllocaMetadata(EntryIRB, AI);
          NextNodeIRBuilder IRB(AI);
          initAllocaMetadata(IRB, AI, Prov);
          setProvenance(AI, Prov);
        }
      }
    }
    FnPrologueEnd = EntryIRB.CreateIntrinsic(Intrinsic::donothing, {});
    LifetimeInfo = std::make_unique<StackLifetime>(
        F, StaticAllocaVec, StackLifetime::LivenessType::May);
    LifetimeInfo->run();
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

  void instrumentRetagMem(CallBase &CB) {
    IRBuilder<> IRB(&CB);
    Value *Operand = CB.getOperand(0);
    Value *SrcAddr = IRB.CreateLoad(BS.PtrTy, Operand, true);

    Value *Tmp = IRB.CreateAlloca(BS.PL.ProvenanceTy, nullptr);
    IRB.CreateCall(BS.BsanFuncShadowLoad, {Operand, Tmp});
    ProvenancePtrScalar SrcProvPtr(IRB, BS.PL, Tmp);
    ProvenanceScalar SrcProv = ProvenanceScalar::load(IRB, BS.PL, SrcProvPtr);
    ProvenanceScalar RetaggedProv = instrumentRetag(IRB, CB, SrcAddr, SrcProv);
    IRB.CreateCall(BS.BsanFuncShadowStore,
                   {RetaggedProv.Tag, RetaggedProv.Info, Operand});
  }

  void instrumentRetagReg(CallBase &CB) {
    IRBuilder<> IRB(&CB);
    ProvenanceScalar Prov =
        assertProvenanceScalar(CB.getParent(), CB.getOperand(0));
    ProvenanceScalar Retagged =
        instrumentRetag(IRB, CB, CB.getOperand(0), Prov);
    setProvenance(&CB, Retagged);
  }

  ProvenanceScalar instrumentRetag(IRBuilder<> &IRB, CallBase &CB,
                                   Value *Target, ProvenanceScalar TargetProv) {
    if (TargetProv != BS.WildcardProvenance) {
      RetagInfo RI(&CB);

      Value *ImArrayLen = BS.Zero;
      if (GlobalVariable *GV = dyn_cast<GlobalVariable>(RI.ImArray)) {
        if (ConstantDataArray *CA =
                dyn_cast<ConstantDataArray>(GV->getInitializer())) {
          uint64_t NumPointerSizedPairs =
              CA->getNumElements() / (BS.DL->getTypeAllocSize(BS.IntptrTy) * 2);
          ImArrayLen = ConstantInt::get(BS.IntptrTy, NumPointerSizedPairs);
        }
      }

      TargetProv.Tag = IRB.CreateCall(
          BS.BsanFuncRetag,
          {Target, RI.Size, RI.IsProtected, RI.IsFreeze, RI.IsUnpin, RI.PtrKind,
           RI.ImArray, ImArrayLen, TargetProv.Tag, TargetProv.Info});

      if (RI.IsProtected->getZExtValue() != 0) {
        Value *SlotPtr = allocStackSlot(IRB);
        TargetProv.store(IRB, BS.PL, SlotPtr);
      }
    }
    return TargetProv;
  }

  Value *allocStackSlot(IRBuilder<> &IRB,
                        ElementCount Elems = ElementCount::getFixed(1)) {

    Value *SlotOffset = FnEntrySlots.alloc(IRB, Elems, BS.IntptrTy);
    Value *ProvOffset = IRB.CreateMul(SlotOffset, BS.PL.ProvenanceSize);
    return ptradd(IRB, FrameTop, IRB.CreateNeg(ProvOffset));
  }

  Value *getStackOffset(IRBuilder<> &IRB) {
    Value *CurrOffset =
        FnEntrySlots.getOutgoingOffset(IRB.GetInsertBlock(), BS.IntptrTy);
    Value *ProvOffset = IRB.CreateMul(CurrOffset, BS.PL.ProvenanceSize);
    return ptradd(IRB, FrameTop, IRB.CreateNeg(ProvOffset));
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

    // If we've made it here, then we don't have a hard-coded way to handle this
    // function. We need to pass its arguments into our thread-local array and
    // then read the provenance for the return value.
    IRBuilder<> Before(&CB);
    Value *StackOffset = getStackOffset(Before);
    Before.CreateStore(StackOffset, BS.ProvStack);

    // Store the provenance for each argument into the thread-local storage for
    // parameters. The process for computing provenance components is
    // deterministic, so we can guarantee that the callee will expect a
    // provenance value everywhere it's been stored here, unless we're dealing
    // with a situation where function bindings are incorrect, which is
    // undefined behavior.
    Value *ParamByteWidth = BS.Zero;
    for (const auto &[i, Arg] : llvm::enumerate(CB.args())) {
      SmallVector<ProvenanceDesc> ProvDesc =
          getProvenanceDesc(Before, BS.DL, Arg->getType());
      for (const auto &[Idx, Desc] : llvm::enumerate(ProvDesc)) {
        Value *Slot = ptradd(Before, BS.ParamTLS, ParamByteWidth);

        Provenance ProvSrc = assertProvenance(Before, Desc.Elems, {Arg, Idx});
        ProvenancePtr Dest = ProvenancePtr(Before, BS.PL, Slot, Desc.Elems);
        ProvSrc.store(Before, BS.PL, Dest);

        Value *NumProv = Before.CreateElementCount(BS.IntptrTy, Desc.Elems);
        Value *ByteWidth = Before.CreateMul(NumProv, BS.PL.ProvenanceSize);
        ParamByteWidth = Before.CreateAdd(ParamByteWidth, ByteWidth);
      }
    }

    // We need to do some extra work here to compute where to insert our
    // instructions, since some function calls occur within terminators.
    Instruction *NextInst;
    if (auto *II = dyn_cast<InvokeInst>(&CB)) {
      if (II->getNormalDest()->getSinglePredecessor()) {
        NextInst = &II->getNormalDest()->front();
      } else {
        NextInst =
            &SplitEdge(II->getParent(), II->getNormalDest(), &DT)->front();
      }
    } else {
      assert(CB.getIterator() != CB.getParent()->end());
      NextInst = CB.getNextNode();
    }
    IRBuilder<> After(NextInst);
    After.SetCurrentDebugLocation(CB.getDebugLoc());

    Value *NumReturnProv = BS.Zero;
    SmallVector<std::pair<unsigned, ProvenancePtr>> ProvenancePointers;

    if (CB.getType()->isSized()) {
      // Unsized return types do not have provenance, so we can skip handling
      // the return array.
      SmallVector<ProvenanceDesc> ReturnDesc =
          getProvenanceDesc(Before, BS.DL, CB.getType());

      // Load each provenance component for the return type from the
      // thread-local return value array. Also, compute the byte-width of the
      // provenance components that we expect to be here. If the function that
      // we are calling is uninstrumented, then we need ensure that the return
      // array is populated with default values.
      Value *RetvalByteWidth = BS.Zero;
      for (const auto &[Idx, Desc] : llvm::enumerate(ReturnDesc)) {
        Value *Slot = ptradd(After, BS.RetvalTLS, RetvalByteWidth);

        ProvenancePtr Ptr = ProvenancePtr(After, BS.PL, Slot, Desc.Elems);
        ProvenancePointers.push_back({Idx, Ptr});

        Value *NumProv = Before.CreateElementCount(BS.IntptrTy, Desc.Elems);
        Value *ByteWidth = Before.CreateMul(NumProv, BS.PL.ProvenanceSize);
        RetvalByteWidth = Before.CreateAdd(RetvalByteWidth, ByteWidth);
        NumReturnProv = Before.CreateAdd(NumReturnProv, NumProv);
      }
    }
    // We need to validate thread-local storage before we load provenance
    // values from it, but we also need to know the number of provenance
    // values associated with the return value to perform initialization.
    if (needsTLSValidation(Callee)) {
      if (shouldTrustFunction(TLI, &CB)) {
        Value *Marker = Before.CreateCall(BS.BsanFuncMarkTLS,
                                          {ConstantPointerNull::get(BS.PtrTy)});
        After.CreateStore(Marker, BS.TLSMarker);
      } else {
        Value *Marker =
            Before.CreateCall(BS.BsanFuncMarkTLS, {CB.getCalledOperand()});
        After.CreateCall(BS.BsanFuncValidateRetvalTLS, {Marker, NumReturnProv});
      }
    }
    for (auto &[Idx, Ptr] : ProvenancePointers) {
      setProvenance({&CB, Idx}, Provenance::load(After, BS.PL, Ptr));
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
          getProvenanceDesc(IRB, BS.DL, Operand->getType());
      for (const auto &[Idx, Comp] : llvm::enumerate(Components)) {
        setProvenance({Operand, Idx}, BS.WildcardProvenance);
      }
    }
  }

  ProvenanceScalar
  createScalarProvenancePHI(IRBuilder<> &IRB,
                            iterator_range<pred_iterator> Blocks) {
    unsigned NumIncoming = std::distance(Blocks.begin(), Blocks.end());
    PHINode *TagNode = IRB.CreatePHI(BS.IntptrTy, NumIncoming, "_bsphi_tag");
    TagNode->dropDbgRecords();
    PHINode *InfoNode = IRB.CreatePHI(BS.PtrTy, NumIncoming, "_bsphi_info");
    InfoNode->dropDbgRecords();

    for (BasicBlock *BB : Blocks) {
      TagNode->addIncoming(BS.WildcardProvenance.Tag, BB);
      InfoNode->addIncoming(BS.WildcardProvenance.Info, BB);
    }
    return ProvenanceScalar(TagNode, InfoNode);
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
        getProvenanceDesc(IRB, BS.DL, PN.getType());
    for (auto [Idx, Comp] : llvm::enumerate(Components)) {
      Provenance Prov =
          createProvenancePHI(IRB, Comp, predecessors(PN.getParent()));
      setProvenance({&PN, Idx}, Prov);
      ProvPHINodes.push_back(std::make_tuple(&PN, Prov, Idx));
    }
  }

  void visitIntrinsicInst(IntrinsicInst &I) {
    switch (I.getIntrinsicID()) {
    case Intrinsic::lifetime_start: {
      instrumentLifetimeStart(I);
    } break;
    case Intrinsic::lifetime_end: {
      instrumentLifetimeEnd(I);
    } break;
    }
  }

  ProvenanceScalar createAllocaMetadata(IRBuilder<> &IRB, AllocaInst *AI) {
    TypeSize TS = AI->getAllocationSize(*BS.DL).value();
    Value *Size = IRB.CreateTypeSize(BS.IntptrTy, TS);
    Value *Tag = newBorrowTag(IRB);
    Value *Info = IRB.CreateCall(BS.BsanFuncReserveStackSlot, {});
    return ProvenanceScalar(Tag, Info);
  }

  void initAllocaMetadata(IRBuilder<> &IRB, AllocaInst *AI,
                          ProvenanceScalar Prov) {
    TypeSize TS = AI->getAllocationSize(*BS.DL).value();
    Value *Size = IRB.CreateTypeSize(BS.IntptrTy, TS);
    IRB.CreateCall(BS.BsanFuncAllocStack, {AI, Size, Prov.Tag, Prov.Info});
  }

  ProvenanceScalar createAndInitAllocaMetadata(IRBuilder<> &IRB,
                                               AllocaInst *AI) {
    ProvenanceScalar Prov = createAllocaMetadata(IRB, AI);
    initAllocaMetadata(IRB, AI, Prov);
    return Prov;
  }

  void instrumentLifetimeStart(IntrinsicInst &II) {
    AllocaInst *AI = findAllocaForValue(II.getArgOperand(1), true);
    IRBuilder<> IRB(&II);
    ProvenanceScalar CurrentProv = assertProvenanceScalar(II.getParent(), AI);
    if (CurrentProv != BS.WildcardProvenance) {
      IRB.CreateCall(BS.BsanFuncDeallocStack,
                     {AI, CurrentProv.Tag, CurrentProv.Info});
    }
    initAllocaMetadata(IRB, AI, CurrentProv);
  }

  void instrumentLifetimeEnd(IntrinsicInst &II) {
    AllocaInst *AI = findAllocaForValue(II.getArgOperand(1), true);
    IRBuilder<> IRB(&II);
    ProvenanceScalar Root = assertProvenanceScalar(II.getParent(), AI);
    if (Root != BS.WildcardProvenance) {
      IRB.CreateCall(BS.BsanFuncDeallocStack, {AI, Root.Tag, Root.Info});
    }
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
    ProvenanceScalar Prov = assertProvenanceScalar(IRB.GetInsertBlock(), Ptr);
    if (Prov != BS.WildcardProvenance) {
      IRB.CreateCall(BS.BsanFuncRead, {Ptr, Size, Prov.Tag, Prov.Info});
    }
  }

  void insertWriteCheck(IRBuilder<> &IRB, Value *Ptr, Value *Size) {
    ProvenanceScalar Prov = assertProvenanceScalar(IRB.GetInsertBlock(), Ptr);
    if (Prov != BS.WildcardProvenance) {
      IRB.CreateCall(BS.BsanFuncWrite, {Ptr, Size, Prov.Tag, Prov.Info});
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
        getProvenanceDesc(IRB, BS.DL, LI.getType());
    Value *Base = LI.getPointerOperand();
    for (const auto &[Idx, Comp] : llvm::enumerate(Components)) {
      Value *ByteOffset = Comp.ByteOffset.getValue(IRB, BS.IntptrTy);
      Value *ObjAddr = ptradd(IRB, Base, ByteOffset);
      Provenance Prov =
          loadProvenanceFromShadow(IRB, Comp, ObjAddr, LI.getOrdering());
      setProvenance({&LI, Idx}, Prov);
    }
    insertReadCheck(IRB, Ptr, Size);
  }

  bool shouldClearProvenance(IRBuilder<> &IRB, StoreInst &SI) {
    Value *Dest = SI.getPointerOperand()->stripPointerCastsAndAliases();
    if (AllocaInst *AI = dyn_cast<AllocaInst>(Dest)) {
      TypeSize TS = AI->getAllocationSize(*BS.DL).value();
      if (TS.isFixed()) {
        DynSize Size(IRB.CreateTypeSize(BS.IntptrTy, TS));
        std::optional<unsigned> ConstSize = Size.constant();
        if (ConstSize.has_value()) {
          return ConstSize.value() > BS.PtrSize;
        }
      }
    }
    return true;
  }

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
        getProvenanceDesc(IRB, BS.DL, Val->getType());

    DynSize Offset = DynSize(BS.Zero);

    for (const auto &[Idx, Desc] : llvm::enumerate(ProvDesc)) {
      Value *ByteOffset = Desc.ByteOffset.getValue(IRB, BS.IntptrTy);
      if (Clear) {
        if (Offset != Desc.ByteOffset) {
          Value *CurrOffset = Offset.getValue(IRB, BS.IntptrTy);
          Value *GapSize = IRB.CreateSub(ByteOffset, CurrOffset);
          Value *BaseAddr = ptradd(IRB, Base, CurrOffset);
          clearProvenance(IRB, BaseAddr, GapSize, SI.getOrdering());
        }
        Offset = Desc.ByteOffset.add(Desc.ByteWidth);
      }
      Value *ObjAddr = ptradd(IRB, Base, ByteOffset);
      Provenance Prov =
          assertProvenance(IRB, Desc.Elems, {SI.getValueOperand(), Idx});
      storeProvenanceToShadow(IRB, ObjAddr, Prov, SI.getOrdering());
    }

    if (Clear) {
      Value *OffsetVal = Offset.getValue(IRB, BS.IntptrTy);
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
    // Pointer arithmetic does not affect provenance, so we can propagage the
    // provenance of the input to the output value.
    ProvenanceScalar Prov =
        assertProvenanceScalar(I.getParent(), I.getPointerOperand());
    setProvenance(&I, Prov);
  }

  void visitIntToPtrInst(IntToPtrInst &I) {
    // Pointers converted from integers receive a wildcard provenance value.
    // This is overly permissive, but certain certain Rust programs that do
    // *not* use integer to pointer casts are still compiled to use `inttoptr`.
    // Since these conversions are not present in MIR, Miri will not report an
    // error in strict provenance mode, but we will have false positives unless
    // we allow all accesses through these pointers.
    setProvenance(&I, BS.WildcardProvenance);
  }

  void visitExtractValueInst(ExtractValueInst &EI) {
    IRBuilder<> IRB(&EI);
    Value *AggregateSrc = EI.getAggregateOperand();

    SmallVector<ProvenanceDesc> DestProvDesc =
        getProvenanceDesc(IRB, BS.DL, EI.getType());

    Type *CurrType = AggregateSrc->getType();
    uint64_t StartingIdx = 0;
    for (auto &Idx : EI.indices()) {
      std::tie(CurrType, StartingIdx) =
          offsetIntoProvenanceIndex(IRB, BS.DL, CurrType, Idx, StartingIdx);
    }

    for (auto [Offset, Desc] : llvm::enumerate(DestProvDesc)) {
      Provenance Prov = assertProvenance(IRB, Desc.Elems,
                                         {AggregateSrc, StartingIdx + Offset});
      setProvenance({&EI, Offset}, Prov);
    }
  }

  void visitInsertValueInst(InsertValueInst &II) {
    IRBuilder<> IRB(&II);
    BaseProvMap.transfer(II.getAggregateOperand(), &II);
    Value *ToInsert = II.getInsertedValueOperand();
    SmallVector<ProvenanceDesc> SrcProvDesc =
        getProvenanceDesc(IRB, BS.DL, ToInsert->getType());

    Type *CurrType = II.getType();
    uint64_t StartingIdx = 0;
    for (auto &Idx : II.indices()) {
      std::tie(CurrType, StartingIdx) =
          offsetIntoProvenanceIndex(IRB, BS.DL, CurrType, Idx, StartingIdx);
    }

    for (auto [Offset, Desc] : llvm::enumerate(SrcProvDesc)) {
      Provenance Prov = assertProvenance(IRB, Desc.Elems, {ToInsert, Offset});
      setProvenance({&II, StartingIdx + Offset}, Prov);
    }
  }

  void visitSelectInst(SelectInst &SI) {
    IRBuilder<> IRB(&SI);
    SmallVector<ProvenanceDesc> ProvDesc =
        getProvenanceDesc(IRB, BS.DL, SI.getType());

    for (auto [Idx, Desc] : llvm::enumerate(ProvDesc)) {
      if (Desc.Elems.isVector()) {
        report_fatal_error("Vectors are not supported.");
      } else {
        BasicBlock *BB = SI.getParent();
        ProvenanceScalar ProvL =
            assertProvenanceScalar(BB, {SI.getTrueValue(), Idx});
        ProvenanceScalar ProvR =
            assertProvenanceScalar(BB, {SI.getFalseValue(), Idx});

        Value *Tag = IRB.CreateSelect(SI.getCondition(), ProvL.Tag, ProvR.Tag);
        Value *Info =
            IRB.CreateSelect(SI.getCondition(), ProvL.Info, ProvR.Info);
        setProvenance({&SI, Idx}, ProvenanceScalar(Tag, Info));
      }
    }
  }

  void popFrame(IRBuilder<> &IRB, Instruction &I, Value *RetVal) {
    BasicBlock *BB = IRB.GetInsertBlock();
    if (RetVal) {
      SmallVector<ProvenanceDesc> ProvDesc =
          getProvenanceDesc(IRB, BS.DL, RetVal->getType());

      Value *RetvalByteWidth = BS.Zero;
      for (const auto &[Idx, Desc] : llvm::enumerate(ProvDesc)) {
        Value *Slot = ptradd(IRB, BS.RetvalTLS, RetvalByteWidth);
        Provenance Prov = assertProvenance(IRB, Desc.Elems, {RetVal, Idx});
        ProvenancePtr Dest = ProvenancePtr(IRB, BS.PL, Slot, Desc.Elems);
        Prov.store(IRB, BS.PL, Dest);
        Value *NumProv = IRB.CreateElementCount(BS.IntptrTy, Desc.Elems);
        Value *ByteWidth = IRB.CreateMul(NumProv, BS.PL.ProvenanceSize);
        RetvalByteWidth = IRB.CreateAdd(RetvalByteWidth, ByteWidth);
      }
    }

    if (NumFnEntryRetags) {
      Value *FrameLen =
          FnEntrySlots.getOutgoingOffset(IRB.GetInsertBlock(), BS.IntptrTy);
      Value *Offset = IRB.CreateMul(FrameLen, BS.PL.ProvenanceSize);
      Value *FrameBottom = ptradd(IRB, FrameTop, IRB.CreateNeg(Offset));
      IRB.CreateCall(BS.BsanFuncPopFrame, {FrameBottom, FrameLen});
    }
    IRB.CreateStore(FrameTop, BS.ProvStack);

    if (StaticAllocaVec.size() > 0) {
      for (AllocaInst *AI : StaticAllocaVec) {
        ProvenanceScalar Root = assertProvenanceScalar(BB, AI);
        if (LifetimeInfo->isAliveAfter(AI, &I)) {
          IRB.CreateCall(BS.BsanFuncDeallocStack, {AI, Root.Tag, Root.Info});
        }
        IRB.CreateCall(BS.BsanFuncDestroyStackSlot, {Root.Info});
      }
    }

    for (auto &Ptr : ByValArgs) {
      ProvenanceScalar Root = assertProvenanceScalar(BB, Ptr);
      IRB.CreateCall(BS.BsanFuncDeallocStack, {Ptr, Root.Tag, Root.Info});
      IRB.CreateCall(BS.BsanFuncDestroyStackSlot, {Root.Info});
    }
  }

  void visitReturnInst(ReturnInst &I) {
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
      0, kBsanModuleDtorName, &M);
  BsanDtorFunction->addFnAttr(Attribute::NoUnwind);

  BasicBlock *BsanDtorBB = BasicBlock::Create(*C, "", BsanDtorFunction);
  ReturnInst *BsanDtorRet = ReturnInst::Create(*C, BsanDtorBB);

  auto *FnTy = FunctionType::get(IRB.getVoidTy(), false);
  FunctionCallee DeinitFn = M.getOrInsertFunction(kBsanFuncDeinitName, FnTy);

  IRB.SetInsertPoint(BsanDtorRet);
  CallInst *DeinitCall = IRB.CreateCall(DeinitFn, {});

  appendToUsed(M, {BsanDtorFunction});
  return DeinitCall;
}

bool BorrowSanitizer::instrumentModule(Module &M) {
  // TODO: add version check.
  std::tie(BsanCtorFunction, std::ignore) = createSanitizerCtorAndInitFunctions(
      M, kBsanModuleCtorName, kBsanFuncInitName, /*InitArgTypes=*/{},
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
    BsanCtorFunction->setComdat(M.getOrInsertComdat(kBsanModuleCtorName));
    appendToGlobalCtors(M, BsanCtorFunction, Priority, BsanCtorFunction);

    BsanDtorFunction->setComdat(M.getOrInsertComdat(kBsanModuleDtorName));
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

  AL = AL.addFnAttribute(*C, Attribute::NoUnwind);

  BsanFuncRetag = M.getOrInsertFunction(
      kBsanFuncRetagName, AL, IntptrTy, PtrTy, IntptrTy, Int8Ty, Int8Ty, Int8Ty,
      Int8Ty, PtrTy, IntptrTy, IntptrTy, PtrTy);

  BsanFuncPopFrame = M.getOrInsertFunction(kBsanFuncPopFrame, AL,
                                           IRB.getVoidTy(), PtrTy, IntptrTy);

  BsanFuncRead = M.getOrInsertFunction(kBsanFuncReadName, AL, IRB.getVoidTy(),
                                       PtrTy, IntptrTy, IntptrTy, PtrTy);

  BsanFuncWrite = M.getOrInsertFunction(kBsanFuncWriteName, AL, IRB.getVoidTy(),
                                        PtrTy, IntptrTy, IntptrTy, PtrTy);

  BsanFuncAllocStack =
      M.getOrInsertFunction(kBsanFuncAllocStackName, AL, IRB.getVoidTy(), PtrTy,
                            IntptrTy, IntptrTy, PtrTy);
  BsanFuncDeallocStack = M.getOrInsertFunction(
      kBsanFuncDeallocStackName, AL, IRB.getVoidTy(), PtrTy, IntptrTy, PtrTy);

  BsanFuncMarkTLS =
      M.getOrInsertFunction(kBsanFuncMarkTLSName, AL, PtrTy, PtrTy);

  BsanFuncValidateParamTLS = M.getOrInsertFunction(
      kBsanFuncValidateParamTLSName, AL, IRB.getVoidTy(), PtrTy, IntptrTy);

  BsanFuncValidateRetvalTLS = M.getOrInsertFunction(
      kBsanFuncValidateRetvalTLSName, AL, IRB.getVoidTy(), PtrTy, IntptrTy);

  BsanFuncShadowLoad = M.getOrInsertFunction(kBsanFuncGetShadowLoadName, AL,
                                             IRB.getVoidTy(), PtrTy, PtrTy);

  BsanFuncShadowStore = M.getOrInsertFunction(
      kBsanFuncGetShadowStoreName, AL, IRB.getVoidTy(), IntptrTy, PtrTy, PtrTy);

  BsanFuncShadowClear = M.getOrInsertFunction(kBsanFuncShadowClearName, AL,
                                              IRB.getVoidTy(), PtrTy, IntptrTy);

  BsanFuncMemCpy = M.getOrInsertFunction(
      kBsanFuncMemCpyName, AL, IRB.getVoidTy(), PtrTy, PtrTy, IntptrTy);

  BsanFuncMemMove = M.getOrInsertFunction(
      kBsanFuncMemMoveName, AL, IRB.getVoidTy(), PtrTy, PtrTy, IntptrTy);

  BsanFuncMemSet = M.getOrInsertFunction(
      kBsanFuncMemSetName, AL, IRB.getVoidTy(), PtrTy, Int32Ty, IntptrTy);

  BsanFuncReserveStackSlot =
      M.getOrInsertFunction(kBsanFuncReserveStackSlotName,
                            FunctionType::get(PtrTy, /*isVarArg=*/false), AL);

  BsanFuncDestroyStackSlot = M.getOrInsertFunction(
      kBsanFuncDestroyStackSlotName, AL, IRB.getVoidTy(), PtrTy);

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
  RetvalTLS = getOrInsertTLSGlobal(M, kBsanRetvalTLSName,
                                   ArrayType::get(PL.ProvenanceTy, kTLSSize));
  ParamTLS = getOrInsertTLSGlobal(M, kBsanParamTLSName,
                                  ArrayType::get(PL.ProvenanceTy, kTLSSize));
  TLSMarker = getOrInsertTLSGlobal(M, kBsanTLSMarkerName, PtrTy);
  ProvStack = getOrInsertTLSGlobal(M, kBsanProvStackName, PtrTy);
  BorTagCounter = getOrInsertGlobal(M, kBsanBorTagCounterName, IntptrTy);
}

bool BorrowSanitizer::instrumentFunction(Function &F,
                                         FunctionAnalysisManager &FAM) {
  if (F.empty()) {
    return false;
  }

  if (F.getLinkage() == GlobalValue::AvailableExternallyLinkage) {
    return false;
  }

  if (F.getName().starts_with(kBsanPrefix)) {
    return false;
  }

  if (F.getName().starts_with(kBsanRustIntrinsicRetagPrefix)) {
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
  Visitor.run();

  F.addFnAttr(Attribute::DisableSanitizerInstrumentation);
  return true;
}
