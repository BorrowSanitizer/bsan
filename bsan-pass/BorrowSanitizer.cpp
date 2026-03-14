#include "BorrowSanitizer.h"
#include "Declarations.h"
#include "Provenance.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/StackLifetime.h"
#include "llvm/Analysis/StackSafetyAnalysis.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/EHPersonalities.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/AtomicOrdering.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/EscapeEnumerator.h"
#include "llvm/Transforms/Utils/Instrumentation.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

class RetagInfo {
public:
  Value *Ptr;
  Value *ImArray;
  ConstantInt *Size;
  ConstantInt *IsProtected;
  ConstantInt *IsFreeze;
  ConstantInt *IsUnpin;
  ConstantInt *PtrKind;
  RetagInfo(CallBase *CB) {
    assert(CB->arg_size() == 7);
    Ptr = CB->getOperand(0);
    ImArray = CB->getOperand(1);
    Size = cast<ConstantInt>(CB->getOperand(2));
    IsProtected = cast<ConstantInt>(CB->getOperand(3));
    IsFreeze = cast<ConstantInt>(CB->getOperand(4));
    IsUnpin = cast<ConstantInt>(CB->getOperand(5));
    PtrKind = cast<ConstantInt>(CB->getOperand(6));
  }
};

class BorrowSanitizerVisitor : public InstVisitor<BorrowSanitizerVisitor> {
  friend class InstVisitor<BorrowSanitizerVisitor>;
  BorrowSanitizer &BS;

  Function &F;
  DIBuilder DIB;
  LLVMContext *C;

  DominatorTree &DT;
  const TargetLibraryInfo *TLI;

  // The end of the function's prologue, which is a call to `llvm.donothing()`.
  Instruction *FnPrologueEnd;

  // The current basic block that we are visiting.
  BasicBlock *CurrentBlock;

  // We iterate over instructions in chunks for each block corresponding to a
  // depth-first traversal of the CFG. This is necessary to maintain per-block
  // metadata for the provenance of stack allocations.
  SmallVector<std::tuple<BasicBlock *, SmallVector<Instruction *>>>
      Instructions;
  // If a stack allocation does not have a dedicated `lifetime.start`, then we
  // allocate metadata for it within the entry block. We use a liveness pass to
  // determine which allocations need to be freed, so no additional handling is
  // necessary to determine where to free these allocations, even if they do not
  // have a `lifetime.end`, either.
  DenseMap<AllocaInst *, SmallVector<IntrinsicInst *>> HasLifetimeStart;

  // Alloca instructions. For the moment, static allocas are handled the same as
  // dynamic ones, but we will adjust this behavior in the future to support
  // optimizations such as combining static stack allocations into a single,
  // larger allocation (see AddressSanitizer).
  SmallVector<AllocaInst *, 8> StaticAllocaVec;

  // The number of function-entry retags. If none occur, then we can skip
  // creating and popping a frame to contain protected tags.

  // Pointers to the sections of the thread-local array (BS.ParamTLS) where the
  // provenance values for each argument are stored. Whenever we need to get the
  // provenance for an argument, we take its pointer from this array and then
  // insert the necessary instructions to load it from thread-local storage
  // within the prologue of the function.
  DenseMap<Argument *, SmallVector<ProvenancePointer>> ArgumentProvenance;

  // The provenance-carrying components of each type, cached for performance.
  DenseMap<Type *, SmallVector<ProvenanceComponent>> ProvenanceComponents;

  // With the exception of `allocas`, each value is associated with a unique
  // provenance value. Provenanced values are indexed by each provenance
  // carrying component. For example, if `ProvenanceComponents[V]` has length 3,
  // then `ProvenanceMap[std::make_pair(V, 2)]` would return the third
  // provenance value within `V`.
  ProvenanceMap BaseProvMap;

  // Most allocations have a single `lifetime.start`. We assign a single
  // provenance value to these allocations starting from the entry block. It is
  // left uninitialized until the `lifetime.start`. Uninitialized provenance
  // values have the same semantics as invalid ones, so we can still detect UB
  // for accesses outside of the lifetime. This is necessary; otherwise,
  // ~thousands~ of PHI nodes can be emitted for certain edge-case functions.
  DenseMap<Value *, std::pair<Value *, ProvenanceScalar>> SingletonAllocaMap;

  // If an `alloca` has multiple `lifetime.start` instructions, then we need to
  // track each one separately, because any access might be mutually dominated
  // by more than one `lifetime.start`.
  DenseMap<BasicBlock *, DenseMap<AllocaInst *, ProvenanceScalar>>
      AllocaProvMap;
  // Sometimes, a GEP is issued for an alloca before its `lifetime.start`. The
  // Rust-view of `lifetime.start` indicates that the result of this GEP should
  // be invalid, but the LLVM view seems to permit this. For now, we defer
  // initializing the provenance of a GEP for an `alloca` until we need to use
  // it to validate an operation. Instead of setting the provenance for these
  // GEPs, we indicate in this map that they alias an `alloca`. Then, when we
  // need to get the provenance for the GEP, we look to see if it's an alias for
  // an `alloca`. If so, we return the provenance for the `alloca` based on
  // whichever block that we're instrumenting. This interaction is only
  // necessary for the edge cases where the `alloca` has multiple
  // `lifetime.start`.
  DenseMap<Value *, AllocaInst *> AllocaAliases;

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

  // Since `allocas` have multiple provenance values, the provenance for any
  // `alloca` in a basic block will depend on its provenance in all of the
  // incoming basic blocks.
  SmallVector<std::tuple<BasicBlock *, AllocaInst *, ProvenanceScalar>>
      AllocaProvPHINodes;

  // Operand retag intrinsics (`__rust_retag_operand`), which need
  // to be replaced with their first argument (the pointer being retagged).
  SmallVector<CallBase *> RetagRegVec;

  // Place retag intrinsics (`__rust_retag_place`), which update the shadow
  // provenance value for their first argument, which is a place containing
  // the pointer receiving the retag.
  SmallVector<CallBase *> RetagMemVec;

  // The number of "function-entry" retags, of any kind.
  unsigned NumFnEntryRetags = 0;

  // The start of the current frame of protected tags. This is the "top" of the
  // frame, since we decrement from the beginning of the chunk. The thread-local
  // frame pointer is reset to this value when the function returns.
  Value *FrameTop = nullptr;

  // We use LLVM's lifetime analysis to determine which `allocas` are alive at
  // every exit point.
  std::unique_ptr<StackLifetime> LifetimeInfo;

public:
  BorrowSanitizerVisitor(Function &F, BorrowSanitizer &BS,
                         const TargetLibraryInfo &TLI, DominatorTree &DT)
      : F(F), BS(BS), DIB(*F.getParent(), /*AllowUnresolved*/ false), C(BS.C),
        TLI(&TLI), CurrentBlock(&F.getEntryBlock()), DT(DT) {
    removeUnreachableBlocks(F);
  }

  bool run() {
    // Before a function returns, we need to deallocate the metadata for
    // each of its stack allocations and remove any protected tags. For this,
    // we need a cleanup block before each `ret` or `resume` instruction.
    // TODO: wait to create these blocks until we know that the function has
    // protected tags and stack allocations that need to be deinitialized.
    EscapeEnumerator EE(F, "bsan_cleanup", true);
    while (IRBuilder<> *AtExit = EE.Next()) {
    }

    BasicBlock *EntryBlock = &F.getEntryBlock();
    IRBuilder<> EntryIRB(EntryBlock, EntryBlock->getFirstNonPHIIt());

    populateBlocks(EntryIRB);

    initStack(EntryIRB);

    for (auto const &[BB, Insts] : Instructions) {
      CurrentBlock = BB;
      for (Instruction *I : Insts) {
        InstVisitor<BorrowSanitizerVisitor>::visit(*I);
      }
    }

    patchShadowPHINodes();
    patchAllocaPHINodes();
    removeRetagIntrinsics();

    return true;
  }

private:
  Value *addPointer(IRBuilder<> &IRB, const DataLayout *DL, Value *Pointer,
                    Value *Offset) {
    if (ConstantInt *CI = dyn_cast<ConstantInt>(Offset))
      if (CI->isZero())
        return Pointer;
    Value *Base = IRB.CreatePointerCast(Pointer, IRB.getIntPtrTy(*DL));
    Base = IRB.CreateAdd(Base, Offset);
    return IRB.CreateIntToPtr(Base, IRB.getPtrTy());
  }

  Value *subtractPointer(IRBuilder<> &IRB, const DataLayout *DL, Value *Pointer,
                         Value *Offset) {
    if (ConstantInt *CI = dyn_cast<ConstantInt>(Offset))
      if (CI->isZero())
        return Pointer;
    Value *Base = IRB.CreatePointerCast(Pointer, IRB.getIntPtrTy(*DL));
    Base = IRB.CreateSub(Base, Offset);
    return IRB.CreateIntToPtr(Base, IRB.getPtrTy());
  }

  ProvenanceScalar assertProvenanceScalar(Value *V) {
    return assertProvenanceScalar({V, 0});
  }

  ProvenanceScalar assertProvenanceScalar(ProvenanceKey Key) {
    return assertProvenanceScalar(CurrentBlock, Key);
  }

  ProvenanceScalar assertProvenanceScalar(BasicBlock *BB, Value *V) {
    return assertProvenanceScalar(BB, {V, 0});
  }

  // Will fail with an error if anything other than a scalar provenance value is
  // present. If no provenance has been assigned yet, then the null provenance
  // value is returned.
  ProvenanceScalar assertProvenanceScalar(BasicBlock *BB, ProvenanceKey Key) {
    std::optional<Provenance> OptProv = getProvenance(BB, Key);
    if (OptProv.has_value()) {
      Provenance Prov = OptProv.value();
      if (Prov.isScalar()) {
        ProvenanceScalar Scalar = Prov.assertScalar();
        return Scalar;
      }
      report_fatal_error(
          "Expected scalar provenance, but found vector provenance!");
    }
    return BS.WildcardProvenance;
  }

  ProvenanceVector assertProvenanceVector(IRBuilder<> &IRB, Value *V,
                                          ElementCount E) {
    return assertProvenanceVector(IRB, {V, 0}, E);
  }

  ProvenanceVector assertProvenanceVector(IRBuilder<> &IRB, ProvenanceKey Key,
                                          ElementCount E) {
    return assertProvenanceVector(IRB, CurrentBlock, Key, E);
  }

  // Will fail with an error if anything other than a vector provenance value is
  // present. If no provenance has been assigned yet, then the null provenance
  // value is returned.
  ProvenanceVector assertProvenanceVector(IRBuilder<> &IRB, BasicBlock *BB,
                                          ProvenanceKey Key, ElementCount E) {
    std::optional<Provenance> OptProv = getProvenance(BB, Key);
    if (OptProv.has_value()) {
      Provenance Prov = OptProv.value();
      if (Prov.isVector()) {
        return Prov.assertVector();
      }
      report_fatal_error(
          "Expected vector provenance, but found scalar provenance!");
    }
    return ProvenanceVector::wildcard(IRB, BS.PL, E);
  }

  Provenance assertProvenance(IRBuilder<> &IRB, ProvenanceComponent &Comp,
                              Value *V) {
    return assertProvenance(IRB, Comp, {V, 0});
  }

  Provenance assertProvenance(IRBuilder<> &IRB, ProvenanceComponent &Comp,
                              ProvenanceKey Key) {
    return assertProvenance(IRB, CurrentBlock, Comp.Kind, Comp.Elems, Key);
  }

  // Asserts that there is either a provenance value at the given index, or that
  // no provenance values have been loaded for the given value, in which case we
  // return the null provenance value. Used whenever we need a provenance value
  // but do not care whether it's a vector or scalar. Checks for consistency
  // against a given provenance component.
  Provenance assertProvenance(IRBuilder<> &IRB, BasicBlock *BB,
                              ProvenanceKind Kind, ElementCount &Elems,
                              ProvenanceKey Key) {
    std::optional<Provenance> OptProv = getProvenance(BB, Key);
    if (OptProv.has_value()) {
      Provenance Prov = OptProv.value();
      if (Prov.Kind != Kind) {
        report_fatal_error("Provenance type mismatch.");
      }
      return Prov;
    }
    return Provenance::wildcard(IRB, BS.PL, Elems, Kind);
  }

  // Asserts that there is either a provenance value at the given index, or that
  // no provenance values have been loaded for the given value. Does not return
  // the null provenance value. This should never be used directly, since it
  // does not check that the provenance value being returned is consistent with
  // the caller's assumption about whether or not a scalar or vector provenance
  // value is required.
  std::optional<Provenance> getProvenance(BasicBlock *BB, ProvenanceKey Key) {
    if (BaseProvMap.contains(Key)) {
      return BaseProvMap.get(Key);
    }

    if (AllocaAliases.contains(Key.first)) {
      AllocaInst *AI = AllocaAliases[Key.first];
      return getProvenance(BB, {AI, 0});
    }

    if (AllocaInst *AI = dyn_cast<AllocaInst>(Key.first)) {
      return getAllocaProvenance(BB, AI);
    }

    if (Argument *Arg = dyn_cast<Argument>(Key.first)) {
      // We always need to load the provenance for arguments right at the
      // beginning of the function. Otherwise, subsequent function calls could
      // overwrite them before they can be read from TLS
      IRBuilder<> EntryIRB(FnPrologueEnd);
      if (ArgumentProvenance.count(Arg)) {
        if (Key.second >= ArgumentProvenance[Arg].size()) {
          report_fatal_error("Invalid argument provenance!");
        }
        ProvenancePointer ArgProvenancePtr =
            ArgumentProvenance[Arg][Key.second];
        Provenance ArgProvenance =
            Provenance::load(EntryIRB, BS.PL, ArgProvenancePtr);
        setProvenance(Key, ArgProvenance);
        return ArgProvenance;
      }
    }

    return std::nullopt;
  }

  ProvenanceScalar assertAllocaProvenance(BasicBlock *BB, AllocaInst *AI) {
    if (AllocaProvMap.contains(BB) && AllocaProvMap[BB].contains(AI)) {
      return AllocaProvMap[BB][AI];
    }

    if (BasicBlock *Pred = BB->getSinglePredecessor()) {
      return assertAllocaProvenance(Pred, AI);
    }

    report_fatal_error("Unable to resolve incoming provenance.");
  }

  ProvenanceScalar getAllocaProvenance(BasicBlock *BB, AllocaInst *AI) {
    if (!shouldInstrumentAlloca(*AI))
      return BS.WildcardProvenance;

    if (SingletonAllocaMap.contains(AI)) {
      const auto [Size, Prov] = SingletonAllocaMap[AI];
      return Prov;
    }

    DenseSet<BasicBlock *> Visited;
    return getAllocaProvenanceRecurse(BB, AI, Visited);
  }

  ProvenanceScalar getAllocaProvenanceRecurse(BasicBlock *BB, AllocaInst *AI,
                                              DenseSet<BasicBlock *> &Visited) {
    if (Visited.contains(BB))
      return BS.WildcardProvenance;

    Visited.insert(BB);

    if (AllocaProvMap.contains(BB) && AllocaProvMap[BB].contains(AI)) {
      return AllocaProvMap[BB][AI];
    }

    if (BasicBlock *Pred = BB->getSinglePredecessor()) {
      ProvenanceScalar ProvPred = getAllocaProvenanceRecurse(Pred, AI, Visited);
      AllocaProvMap[BB][AI] = ProvPred;
      return ProvPred;
    }

    for (BasicBlock *Pred : predecessors(BB)) {
      getAllocaProvenanceRecurse(Pred, AI, Visited);
    }

    IRBuilder<> IRB(&(BB->front()));
    ProvenanceScalar ProvPHI = createScalarProvenancePHI(IRB, predecessors(BB));
    AllocaProvMap[BB][AI] = ProvPHI;
    AllocaProvPHINodes.push_back(std::make_tuple(BB, AI, ProvPHI));
    return ProvPHI;
  }

  void setProvenance(Value *V, Provenance Prov) { setProvenance({V, 0}, Prov); }

  void setProvenance(ProvenanceKey Key, Provenance Prov) {
    BaseProvMap.set(Key, Prov);
  }

  // Returns the list of provenance-carrying components for a type.
  SmallVector<ProvenanceComponent> *getProvenanceComponents(IRBuilder<> &IRB,
                                                            Type *Ty) {
    if (!ProvenanceComponents.contains(Ty))
      populateProvenanceComponents(IRB, ProvenanceComponents[Ty], Ty, Ty,
                                   BS.Zero, BS.Zero);
    return &ProvenanceComponents[Ty];
  }

  // Recursively populates a given vector with the list of provenance-carrying
  // components for a type. A `ProvenanceComponent` contains all of the static
  // information that we need about the location of each pointer within a type.
  std::tuple<Value *, Value *> populateProvenanceComponents(
      IRBuilder<> &IRB, SmallVector<ProvenanceComponent> &Components,
      Type *ParentTy, Type *CurrentTy, Value *ByteOffset, Value *ProvOffset) {
    Value *TypeSize =
        IRB.CreateTypeSize(BS.IntptrTy, BS.DL->getTypeAllocSize(CurrentTy));
    Value *NextProvOffset = ProvOffset;
    switch (CurrentTy->getTypeID()) {
    case Type::PointerTyID: {
      ProvenanceComponent Comp(ByteOffset, TypeSize, ProvOffset, BS.One,
                               ElementCount::get(1, false),
                               ProvenanceKind::Scalar);
      Components.push_back(Comp);
      NextProvOffset = IRB.CreateAdd(ProvOffset, BS.One);
    } break;
    case Type::StructTyID: {
      StructType *ST = cast<StructType>(CurrentTy);
      Value *CurrByteOffset = ByteOffset;
      for (Type *ElemType : ST->elements()) {
        auto [BOffset, POffset] =
            populateProvenanceComponents(IRB, Components, ParentTy, ElemType,
                                         CurrByteOffset, NextProvOffset);
        CurrByteOffset = BOffset;
        NextProvOffset = POffset;
      }
    } break;
    case Type::ArrayTyID: {
      ArrayType *AT = cast<ArrayType>(CurrentTy);
      Value *CurrByteOffset = ByteOffset;
      for (unsigned Idx = 0; Idx < AT->getNumElements(); ++Idx) {
        auto [BOffset, POffset] = populateProvenanceComponents(
            IRB, Components, ParentTy, AT->getElementType(), CurrByteOffset,
            NextProvOffset);
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

  // Computes the offset in terms of provenance components for an index into an
  // aggregate or array value. Used for implementing `extractvalue` and
  // `insertvalue`.
  std::tuple<Type *, uint64_t>
  offsetIntoProvenanceIndex(IRBuilder<> &IRB, Type *CurrentTy, uint64_t Idx,
                            uint64_t PrevOffset = 0) {
    switch (CurrentTy->getTypeID()) {
    case Type::StructTyID: {
      StructType *ST = cast<StructType>(CurrentTy);
      assert(Idx < ST->getNumElements() &&
             "Index out of bounds for struct type.");
      uint64_t Offset = PrevOffset;
      for (unsigned CurrIdx = 0; CurrIdx < Idx; ++CurrIdx) {
        Type *ElemType = ST->getElementType(CurrIdx);
        SmallVector<ProvenanceComponent> *Components =
            getProvenanceComponents(IRB, ElemType);
        Offset += Components->size();
      }
      return std::make_tuple(ST->getElementType(Idx), Offset);
    } break;
    case Type::ArrayTyID: {
      ArrayType *AT = cast<ArrayType>(CurrentTy);
      assert(Idx < AT->getNumElements() &&
             "Index out of bounds for array type.");
      SmallVector<ProvenanceComponent> *Components =
          getProvenanceComponents(IRB, AT->getElementType());
      return std::make_tuple(AT->getElementType(),
                             PrevOffset + Components->size());
    } break;
    default: {
      report_fatal_error("Cannot index into a non-struct or non-array type.");
    }
    }
  }

  // Stores a provenance value into shadow memory, starting at the given object
  // address.
  void storeProvenanceToShadow(IRBuilder<> &IRB, Value *ObjAddr,
                               Provenance Prov, AtomicOrdering Ordering) {
    ProvenancePointer ProvPtr;
    if (Prov.isVector()) {
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
  Provenance loadProvenanceFromShadow(IRBuilder<> &IRB,
                                      ProvenanceComponent &Comp,
                                      Value *ObjAddr) {
    if (Comp.isVector()) {
      report_fatal_error("Vectors are not supported.");
    } else {
      Value *Tmp = IRB.CreateAlloca(BS.PL.ProvenanceTy, nullptr);
      IRB.CreateCall(BS.BsanFuncShadowLoad, {ObjAddr, Tmp});
      ProvenancePointerScalar ProvPtr(IRB, BS.PL, Tmp);
      return Provenance::load(IRB, BS.PL, ProvPtr);
    }
  }

  void populateBlocks(IRBuilder<> &IRB) {
    for (BasicBlock *BB :
         ReversePostOrderTraversal<BasicBlock *>(&F.getEntryBlock())) {
      SmallVector<Instruction *> Insts;
      for (Instruction &I : *BB) {
        if (I.getMetadata(LLVMContext::MD_nosanitize))
          continue;

        if (I.getOpcode() == Instruction::Alloca) {
          AllocaInst &AI = static_cast<AllocaInst &>(I);
          if (shouldInstrumentAlloca(AI) && AI.isStaticAlloca())
            StaticAllocaVec.push_back(&AI);
          continue;
        }

        if (CallBase *CB = dyn_cast<CallBase>(&I)) {
          if (isRetag(CB)) {
            if (isFnEntryRetag(CB)) {
              NumFnEntryRetags += 1;
            }
            if (CB->getType() == BS.PtrTy) {
              RetagRegVec.push_back(CB);
            } else {
              RetagMemVec.push_back(CB);
            }
          }
          if (IntrinsicInst *I = dyn_cast<IntrinsicInst>(CB)) {
            if (CB->getIntrinsicID() == Intrinsic::lifetime_start) {
              AllocaInst *AI = findAllocaForValue(I->getArgOperand(1), true);
              if (!AI)
                continue;
              HasLifetimeStart[AI].push_back(I);
            }
          }
        }
        Insts.push_back(&I);
      }
      Instructions.push_back(std::make_tuple(BB, Insts));
    }
  }

  bool isCalledFromUninstContext(Function &F) {
    return BS.ExternCalledFns.contains(&F);
  }

  // Populates the array of argument provenance pointers and initializes the
  // start and end of the function prologue.
  void initStack(IRBuilder<> &EntryIRB) {
    if (!isCalledFromUninstContext(F)) {
      Value *TotalNumProvenanceValues = BS.Zero;
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
          TotalNumProvenanceValues =
              EntryIRB.CreateAdd(TotalNumProvenanceValues, BS.One);
        } else {
          SmallVector<ProvenanceComponent> *Components =
              getProvenanceComponents(EntryIRB, Arg.getType());
          for (auto &C : *Components) {
            Value *CurrentArrayByteOffset = EntryIRB.CreateMul(
                TotalNumProvenanceValues, BS.PL.ProvenanceSize);
            Value *CurrentArraySlot = addPointer(EntryIRB, BS.DL, BS.ParamTLS,
                                                 CurrentArrayByteOffset);
            ProvenancePointer Ptr =
                C.getPointerToProvenance(EntryIRB, BS.PL, CurrentArraySlot);
            ArgumentProvenance[&Arg].push_back(Ptr);
            TotalNumProvenanceValues = EntryIRB.CreateAdd(
                TotalNumProvenanceValues, C.NumProvenanceValues);
          }
        }
      }
    }

    FrameTop = EntryIRB.CreateLoad(BS.PtrTy, BS.ProvStack, true);

    if (StaticAllocaVec.size() > 0) {
      for (AllocaInst *AI : StaticAllocaVec) {
        if (HasLifetimeStart.contains(AI)) {
          if (HasLifetimeStart[AI].size() > 1) {
            AllocaProvMap[EntryIRB.GetInsertBlock()][AI] = BS.InvalidProvenance;
          } else {
            SingletonAllocaMap[AI] = createAllocaMetadata(EntryIRB, AI);
          }
        } else {
          IRBuilder<> IRB(AI->getNextNode());
          BaseProvMap.set({AI, 0}, createAndInitAllocaMetadata(IRB, AI));
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
        Provenance IncomingProv = assertProvenance(
            EntryIRB, IncomingBlock, Prov.Kind, Prov.Elems, {V, Idx});
        Prov.addIncoming(IncomingBlock, IncomingProv);
      }
    }
  }

  void patchAllocaPHINodes() {
    SmallVector<PHINode *> Worklist;
    for (const auto &[BB, AI, Prov] : AllocaProvPHINodes) {
      PHINode *TagNode = cast<PHINode>(Prov.Tag);
      Worklist.push_back(TagNode);
      PHINode *InfoNode = cast<PHINode>(Prov.Info);
      Worklist.push_back(InfoNode);

      for (BasicBlock *IncomingBlock : predecessors(BB)) {
        ProvenanceScalar IncomingProv =
            assertAllocaProvenance(IncomingBlock, AI);
        TagNode->setIncomingValueForBlock(IncomingBlock, IncomingProv.Tag);
        InfoNode->setIncomingValueForBlock(IncomingBlock, IncomingProv.Info);
      }
    }
    eliminatePHINodes(Worklist);
  }

  void eliminatePHINodes(SmallVectorImpl<PHINode *> &Worklist) {
    DenseSet<PHINode *> PHIToDelete;
    do {
      PHIToDelete.clear();
      SmallVector<PHINode *> PendingWorklist;
      for (PHINode *PN : Worklist) {
        if (Value *Replacement = PN->hasConstantValue()) {
          PN->replaceAllUsesWith(Replacement);
          PHIToDelete.insert(PN);
        } else {
          PendingWorklist.push_back(PN);
        }
      }
      for (PHINode *PN : PHIToDelete) {
        PN->eraseFromParent();
      }
      Worklist = std::move(PendingWorklist);
    } while (!PHIToDelete.empty());
  }

  void removeRetagIntrinsics() {
    for (CallBase *CB : RetagRegVec) {
      CB->replaceAllUsesWith(CB->getOperand(0));
      CB->eraseFromParent();
    }
    for (CallBase *CB : RetagMemVec) {
      CB->eraseFromParent();
    }
  }

  Value *newBorrowTag(IRBuilder<> &IRB) {
    return IRB.CreateAtomicRMW(AtomicRMWInst::Add, BS.BorTagCounter, BS.One,
                               std::nullopt, AtomicOrdering::Monotonic);
  }

  // We only instrument allocations that have a non-zero size.
  bool shouldInstrumentAlloca(AllocaInst &AI) {
    // Although Rust emits retags for ZSTs, tracking
    // allocations leads to false positive errors—probably
    // due to interactions with lowering.
    return (AI.getAllocatedType()->isSized() &&
            !BS.getAllocaSizeInBytes(AI).isZero());
  }

  bool isRetag(CallBase *CB) {
    Function *Callee = CB->getCalledFunction();
    return CB->arg_size() == 7 && Callee &&
           Callee->getName().starts_with(kBsanRustIntrinsicRetagPrefix);
  }

  bool isFnEntryRetag(CallBase *CB) {
    if (isRetag(CB)) {
      RetagInfo RI(CB);
      return RI.IsProtected->getZExtValue() != 0;
    }
    return false;
  }

  void handleDebugFunction(CallBase &CB, Function *F) {
    IRBuilder<> IRB(&CB);
    auto Name = F->getName();

    FunctionCallee Callee;
    ProvenanceScalar Prov = assertProvenanceScalar(CB.getArgOperand(0));

    if (Name == kBsanFuncAssertProvenanceInvalid) {
      Callee = BS.BsanFuncAssertProvenanceInvalid;
    } else if (Name == kBsanFuncAssertProvenanceValid) {
      Callee = BS.BsanFuncAssertProvenanceValid;
    } else if (Name == kBsanFuncAssertProvenanceNull) {
      Callee = BS.BsanFuncAssertProvenanceNull;
    } else if (Name == kBsanFuncAssertProvenanceWildcard) {
      Callee = BS.BsanFuncAssertProvenanceWildcard;
    } else if (Name == kBsanFuncDebugPrint) {
      Callee = BS.BsanFuncDebugPrint;
    } else if (Name == kBsanFuncDebugPrintBorrowState) {
      Callee = BS.BsanFuncDebugPrintBorrowState;
    } else if (Name == kBsanFuncDebugTreeSize) {
      Callee = BS.BsanFuncDebugTreeSize;
    } else if (Name == kBsanFuncDebugSnapshot) {
      Callee = BS.BsanFuncDebugSnapshot;
    } else if (Name == kBsanFuncDebugPrintDiff) {
      Callee = BS.BsanFuncDebugPrintDiff;
    } else {
      report_fatal_error("Unknown debug function: " + Twine(Name) + "\n");
    }

    IRB.CreateCall(Callee, {Prov.Tag, Prov.Info});
    CB.eraseFromParent();
  }

  void instrumentRetagMem(CallBase &CB) {
    IRBuilder<> IRB(&CB);
    Value *Operand = CB.getOperand(0);
    Value *SrcAddr = IRB.CreateLoad(BS.PtrTy, Operand, true);

    Value *Tmp = IRB.CreateAlloca(BS.PL.ProvenanceTy, nullptr);
    IRB.CreateCall(BS.BsanFuncShadowLoad, {Operand, Tmp});
    ProvenancePointerScalar SrcProvPtr(IRB, BS.PL, Tmp);
    ProvenanceScalar SrcProv = Provenance::loadScalar(
        IRB, BS.PL, SrcProvPtr, AtomicOrdering::NotAtomic);

    ProvenanceScalar RetaggedProv = instrumentRetag(IRB, CB, SrcAddr, SrcProv);
    IRB.CreateCall(BS.BsanFuncShadowStore,
                   {RetaggedProv.Tag, RetaggedProv.Info, Operand});
  }

  void instrumentRetagReg(CallBase &CB) {
    IRBuilder<> IRB(&CB);
    ProvenanceScalar Prov = assertProvenanceScalar(CB.getOperand(0));
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
        Value *PrevSlot = IRB.CreateLoad(BS.PtrTy, BS.ProvStack, true);
        Value *NextProvSlot =
            subtractPointer(IRB, BS.DL, PrevSlot, BS.PL.ProvenanceSize);
        TargetProv.store(IRB, BS.PL, NextProvSlot);
        IRB.CreateStore(NextProvSlot, BS.ProvStack, true);
      }
    }
    return TargetProv;
  }

  bool needsTLSValidation(Function *Callee) {
    return !Callee ||
           (Callee->isDeclaration() || Callee->hasExternalLinkage() ||
            Callee->hasExternalWeakLinkage() || Callee->hasAddressTaken());
  }

  bool shouldTrustCallee(CallBase *CB) {
    return isAllocationFn(CB, TLI) || getFreedOperand(CB, TLI);
  }

  void trustCallee(IRBuilder<> &IRB) { IRB.CreateStore(BS.One, BS.TrustFlag); }

  void untrustCallee(IRBuilder<> &IRB) {
    IRB.CreateStore(BS.Zero, BS.TrustFlag);
  }

  using InstVisitor<BorrowSanitizerVisitor>::visit;

  void visitCallBase(CallBase &CB) {
    assert(!CB.getMetadata(LLVMContext::MD_nosanitize));
    assert(!isa<IntrinsicInst>(CB) && "intrinsics are handled elsewhere");

    Function *Callee = CB.getCalledFunction();
    if (Callee) {
      if (Callee->getName().starts_with(kBsanDebugPrefix)) {
        return handleDebugFunction(CB, Callee);
      }
      if (Callee->getName().starts_with(kBsanPrefix)) {
        return;
      }
      if (isRetag(&CB)) {
        if (CB.getType() == BS.PtrTy) {
          return instrumentRetagReg(CB);
        }
        return instrumentRetagMem(CB);
      }
    }

    if (CB.isInlineAsm())
      return;

    // If we've made it here, then we don't have a hard-coded way to handle this
    // function. We need to pass its arguments into our thread-local array and
    // then read the provenance for the return value.
    IRBuilder<> Before(&CB);

    bool Trust = shouldTrustCallee(&CB);
    if (Trust) {
      trustCallee(Before);
    }
    // Store the provenance for each argument into the thread-local storage for
    // parameters. The process for computing provenance components is
    // deterministic, so we can guarantee that the callee will expect a
    // provenance value everywhere it's been stored here, unless we're dealing
    // with a situation where function bindings are incorrect, which is
    // undefined behavior.
    Value *ParamByteWidth = BS.Zero;
    for (const auto &[i, Arg] : llvm::enumerate(CB.args())) {
      SmallVector<ProvenanceComponent> *Components =
          getProvenanceComponents(Before, Arg->getType());
      for (const auto &[Idx, Comp] : llvm::enumerate(*Components)) {
        Value *Slot = addPointer(Before, BS.DL, BS.ParamTLS, ParamByteWidth);

        Provenance ProvSrc = assertProvenance(Before, Comp, {Arg, Idx});
        ProvenancePointer Dest =
            ProvenancePointer(Before, BS.PL, Slot, Comp.Elems, ProvSrc.Kind);
        ProvSrc.store(Before, BS.PL, Dest);

        Value *ByteWidth =
            Before.CreateMul(Comp.NumProvenanceValues, BS.PL.ProvenanceSize);
        ParamByteWidth = Before.CreateAdd(ParamByteWidth, ByteWidth);
      }
    }

    // We need to do some extra work here to compute where to insert our
    // instructions, since some function calls occur within terminators.
    IRBuilder<> After = switchToInsertionPointAfterCall(&CB);

    if (Trust) {
      untrustCallee(After);
    }

    Value *NumProvenanceValues = BS.Zero;
    SmallVector<std::pair<unsigned, ProvenancePointer>> ProvenancePointers;

    if (CB.getType()->isSized()) {
      // Unsized return types do not have provenance, so we can skip handling
      // the return array.
      SmallVector<ProvenanceComponent> *ReturnComponents =
          getProvenanceComponents(Before, CB.getType());

      // Load each provenance component for the return type from the
      // thread-local return value array. Also, compute the byte-width of the
      // provenance components that we expect to be here. If the function that
      // we are calling is uninstrumented, then we need ensure that the return
      // array is populated with default values.
      Value *RetvalByteWidth = BS.Zero;
      for (const auto &[Idx, Comp] : llvm::enumerate(*ReturnComponents)) {
        Value *Slot = addPointer(After, BS.DL, BS.RetvalTLS, RetvalByteWidth);

        ProvenancePointer Ptr = Comp.getPointerToProvenance(After, BS.PL, Slot);
        ProvenancePointers.push_back({Idx, Ptr});

        Value *ByteWidth =
            Before.CreateMul(Comp.NumProvenanceValues, BS.PL.ProvenanceSize);
        RetvalByteWidth = Before.CreateAdd(RetvalByteWidth, ByteWidth);
        NumProvenanceValues =
            Before.CreateAdd(NumProvenanceValues, Comp.NumProvenanceValues);
      }
      // We need to validate thread-local storage before we load provenance
      // values from it, but we also need to know the number of provenance
      // values associated with the return value to perform initialization.
      if (!Trust && needsTLSValidation(Callee)) {
        if (NumProvenanceValues != BS.Zero) {
          After.CreateMemSet(BS.RetvalTLS, ConstantInt::get(BS.Int8Ty, 0),
                             RetvalByteWidth, MaybeAlign(1));
        }
      }

      for (auto &[Idx, Ptr] : ProvenancePointers) {
        setProvenance({&CB, Idx}, Provenance::load(After, BS.PL, Ptr));
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

  Provenance createProvenancePHI(IRBuilder<> &IRB, ProvenanceComponent Comp,
                                 iterator_range<pred_iterator> Blocks) {
    if (Comp.isVector()) {
      report_fatal_error("Vectors are not supported.");
    }
    return createScalarProvenancePHI(IRB, Blocks);
  }

  void visitPHINode(PHINode &PN) {
    IRBuilder<> IRB(&PN);
    unsigned NumIncoming = PN.getNumIncomingValues();
    SmallVector<ProvenanceComponent> *Components =
        getProvenanceComponents(IRB, PN.getType());
    for (auto [Idx, Comp] : llvm::enumerate(*Components)) {
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

  std::pair<Value *, ProvenanceScalar> createAllocaMetadata(IRBuilder<> &IRB,
                                                            AllocaInst *AI) {
    TypeSize TS = BS.getAllocaSizeInBytes(*AI);
    Value *Size = IRB.CreateTypeSize(BS.IntptrTy, TS);
    Value *Tag = newBorrowTag(IRB);
    Value *Info = IRB.CreateCall(BS.BsanFuncReserveStackSlot, {});
    return std::make_pair(Size, ProvenanceScalar(Tag, Info));
  }

  void initAllocaMetadata(IRBuilder<> &IRB, AllocaInst *AI, Value *Size,
                          ProvenanceScalar Prov) {
    IRB.CreateCall(BS.BsanFuncAllocStack, {AI, Size, Prov.Tag, Prov.Info});
  }

  ProvenanceScalar createAndInitAllocaMetadata(IRBuilder<> &IRB,
                                               AllocaInst *AI) {
    const auto [Size, Prov] = createAllocaMetadata(IRB, AI);
    initAllocaMetadata(IRB, AI, Size, Prov);
    return Prov;
  }

  void instrumentLifetimeStart(IntrinsicInst &II) {
    AllocaInst *AI = findAllocaForValue(II.getArgOperand(1), true);
    if (!AI)
      return;
    IRBuilder<> IRB(&II);

    ProvenanceScalar CurrentProv = getAllocaProvenance(CurrentBlock, AI);
    if (CurrentProv != BS.WildcardProvenance) {
      IRB.CreateCall(BS.BsanFuncDeallocStack,
                     {AI, CurrentProv.Tag, CurrentProv.Info});
    }
    if (!shouldInstrumentAlloca(*AI))
      return;
    if (SingletonAllocaMap.contains(AI)) {
      const auto [Size, Prov] = SingletonAllocaMap[AI];
      initAllocaMetadata(IRB, AI, Size, Prov);
    } else {
      AllocaProvMap[CurrentBlock][AI] = createAndInitAllocaMetadata(IRB, AI);
    }
  }

  void instrumentLifetimeEnd(IntrinsicInst &II) {
    AllocaInst *AI = findAllocaForValue(II.getArgOperand(1), true);
    if (!AI)
      return;
    IRBuilder<> IRB(&II);

    ProvenanceScalar Root = assertProvenanceScalar(AI);
    if (Root != BS.WildcardProvenance) {
      IRB.CreateCall(BS.BsanFuncDeallocStack, {AI, Root.Tag, Root.Info});
    }
  }
  // Whenever we memset, we need to clear the corresponding shadow memory
  // section This should be removed when interceptors are implemented.
  void visitMemSetInst(MemSetInst &I) {
    IRBuilder<> IRB(&I);
    Value *Val = IRB.CreateIntCast(I.getValue(), IRB.getInt32Ty(), false);
    Value *Size = IRB.CreateIntCast(I.getLength(), BS.IntptrTy, false);
    insertWriteCheck(IRB, I.getDest(), Size);
    IRB.CreateCall(BS.BsanFuncMemSet, {I.getDest(), Val, Size});
    I.eraseFromParent();
  }

  // Whenever we memcpy, we need to copy the corresponding shadow memory section
  // This should be removed when interceptors are implemented.
  void visitMemMoveInst(MemMoveInst &I) {
    IRBuilder<> IRB(&I);
    Value *Size = IRB.CreateIntCast(I.getLength(), BS.IntptrTy, false);
    insertReadCheck(IRB, I.getSource(), Size);
    insertWriteCheck(IRB, I.getDest(), Size);
    IRB.CreateCall(BS.BsanFuncMemMove, {I.getDest(), I.getSource(), Size});
    I.eraseFromParent();
  }

  // Whenever we memcpy, we need to copy the corresponding shadow memory section
  // This should be removed when interceptors are implemented.
  void visitMemCpyInst(MemCpyInst &I) {
    IRBuilder<> IRB(&I);
    Value *Size = IRB.CreateIntCast(I.getLength(), BS.IntptrTy, false);
    insertReadCheck(IRB, I.getSource(), Size);
    insertWriteCheck(IRB, I.getDest(), Size);
    IRB.CreateCall(BS.BsanFuncMemCpy, {I.getDest(), I.getSource(), Size});
    I.eraseFromParent();
  }

  // Inserts a check to validate a read access.
  void insertReadCheck(IRBuilder<> &IRB, Value *Ptr, Value *Size) {
    ProvenanceScalar Prov = assertProvenanceScalar(Ptr);
    if (Prov != BS.WildcardProvenance) {
      IRB.CreateCall(BS.BsanFuncRead, {Ptr, Size, Prov.Tag, Prov.Info});
    }
  }

  // Inserts a check to validate a write access.
  void insertWriteCheck(IRBuilder<> &IRB, Value *Ptr, Value *Size) {
    ProvenanceScalar Prov = assertProvenanceScalar(Ptr);
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
    // Load provenance for the value from shadow memory.
    SmallVector<ProvenanceComponent> *Components =
        getProvenanceComponents(IRB, LI.getType());
    Value *Base = LI.getPointerOperand();
    for (const auto &[Idx, Comp] : llvm::enumerate(*Components)) {
      ShadowFootprint Footprint = Comp.Footprint;
      Value *ObjAddr = addPointer(IRB, BS.DL, Base, Footprint.ByteOffset);
      Provenance Prov = loadProvenanceFromShadow(IRB, Comp, ObjAddr);
      setProvenance({&LI, Idx}, Prov);
    }
    insertReadCheck(IRB, Ptr, Size);
  }

  void visitStoreInst(StoreInst &SI) {
    if (SI.isAtomic())
      return;

    IRBuilder<> IRB(&SI);
    Value *Ptr, *Val;
    Ptr = SI.getPointerOperand();
    Val = SI.getValueOperand();

    Value *Size = IRB.CreateTypeSize(BS.IntptrTy,
                                     BS.DL->getTypeStoreSize(Val->getType()));
    insertWriteCheck(IRB, Ptr, Size);

    IRBuilder<> NextIRB(SI.getNextNode());
    // Store provenance for the value into shadow memory.
    Value *Base = SI.getPointerOperand();
    SmallVector<ProvenanceComponent> *Components =
        getProvenanceComponents(NextIRB, Val->getType());

    for (const auto &[Idx, Comp] : llvm::enumerate(*Components)) {
      ShadowFootprint Footprint = Comp.Footprint;
      Value *ObjAddr = addPointer(NextIRB, BS.DL, Base, Footprint.ByteOffset);

      Provenance Prov;
      ProvenanceKey Key = {SI.getValueOperand(), Idx};
      if (Comp.isVector()) {
        Prov = assertProvenanceVector(NextIRB, Key, Comp.Elems);
      } else {
        Prov = assertProvenanceScalar(Key);
      }
      storeProvenanceToShadow(NextIRB, ObjAddr, Prov, SI.getOrdering());
    }
  }

  void visitGetElementPtrInst(GetElementPtrInst &I) {
    // Pointer arithmetic does not affect provenance, so we can propagage the
    // provenance of the input to the output value.
    if (AllocaAliases.contains(I.getPointerOperand())) {
      AllocaAliases[&I] = AllocaAliases[I.getPointerOperand()];
    } else if (AllocaInst *AI = dyn_cast<AllocaInst>(I.getPointerOperand())) {
      AllocaAliases[&I] = AI;
    } else {
      ProvenanceScalar Prov = assertProvenanceScalar(I.getPointerOperand());
      setProvenance(&I, Prov);
    }
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

    SmallVector<ProvenanceComponent> *SrcComponents =
        getProvenanceComponents(IRB, AggregateSrc->getType());
    SmallVector<ProvenanceComponent> *DestComponents =
        getProvenanceComponents(IRB, EI.getType());

    Type *CurrType = AggregateSrc->getType();

    // For each index into the aggregate, compute and add the offset for the
    // provenance component index. The final value will point to the start of
    // the series of provenance components that we need to extract from the
    // aggregate.
    uint64_t StartingIdx = 0;
    for (auto &Idx : EI.indices()) {
      std::tie(CurrType, StartingIdx) =
          offsetIntoProvenanceIndex(IRB, CurrType, Idx, StartingIdx);
    }

    for (auto [Offset, Comp] : llvm::enumerate(*DestComponents)) {
      Provenance Prov =
          assertProvenance(IRB, Comp, {AggregateSrc, StartingIdx + Offset});
      setProvenance({&EI, Offset}, Prov);
    }
  }

  void visitInsertValueInst(InsertValueInst &II) {
    IRBuilder<> IRB(&II);

    BaseProvMap.transferToValue(II.getAggregateOperand(), &II);

    Value *ToInsert = II.getInsertedValueOperand();
    SmallVector<ProvenanceComponent> *SrcComponents =
        getProvenanceComponents(IRB, ToInsert->getType());

    Type *CurrType = II.getType();
    uint64_t StartingIdx = 0;

    // For each index into the aggregate, compute and add the offset for the
    // provenance component index. The final value will be the base index that
    // we need to use for inserting each loaded provenance value from the value
    // that's being inserted.
    for (auto &Idx : II.indices()) {
      std::tie(CurrType, StartingIdx) =
          offsetIntoProvenanceIndex(IRB, CurrType, Idx, StartingIdx);
    }

    for (auto [Offset, Comp] : llvm::enumerate(*SrcComponents)) {
      Provenance Prov = assertProvenance(IRB, Comp, {ToInsert, Offset});
      setProvenance({&II, StartingIdx + Offset}, Prov);
    }
  }

  void visitSelectInst(SelectInst &SI) {
    IRBuilder<> IRB(&SI);
    SmallVector<ProvenanceComponent> *Components =
        getProvenanceComponents(IRB, SI.getType());

    // A select instruction returns one of two inputs depending on a boolean
    // value. This means that if the output type has provenance, then we need to
    // conditionally assign the result a provenance value.
    for (auto [Idx, Comp] : llvm::enumerate(*Components)) {
      if (Comp.isVector()) {
        report_fatal_error("Vectors are not supported.");
      } else {
        // For scalable provenance, we just select on each of the three
        // components.
        ProvenanceScalar ProvL =
            assertProvenanceScalar({SI.getTrueValue(), Idx});
        ProvenanceScalar ProvR =
            assertProvenanceScalar({SI.getFalseValue(), Idx});

        Value *Tag = IRB.CreateSelect(SI.getCondition(), ProvL.Tag, ProvR.Tag);
        Value *Info =
            IRB.CreateSelect(SI.getCondition(), ProvL.Info, ProvR.Info);
        setProvenance({&SI, Idx}, ProvenanceScalar(Tag, Info));
      }
    }
  }

  void popFrame(IRBuilder<> &IRB, Instruction &I, Value *RetVal) {
    if (RetVal && !isCalledFromUninstContext(F)) {
      SmallVector<ProvenanceComponent> *Components =
          getProvenanceComponents(IRB, RetVal->getType());

      Value *RetvalByteWidth = BS.Zero;
      for (const auto &[Idx, Comp] : llvm::enumerate(*Components)) {
        Value *Slot = addPointer(IRB, BS.DL, BS.RetvalTLS, RetvalByteWidth);

        Provenance Prov = assertProvenance(IRB, Comp, {RetVal, Idx});
        ProvenancePointer Dest =
            ProvenancePointer(IRB, BS.PL, Slot, Comp.Elems, Prov.Kind);
        Prov.store(IRB, BS.PL, Dest);

        Value *ByteWidth =
            IRB.CreateMul(Comp.NumProvenanceValues, BS.PL.ProvenanceSize);
        RetvalByteWidth = IRB.CreateAdd(RetvalByteWidth, ByteWidth);
      }
    }

    if (NumFnEntryRetags) {
      Value *FrameBottom = IRB.CreateLoad(BS.PtrTy, BS.ProvStack, true);
      Value *FrameLen =
          IRB.CreatePtrDiff(BS.PL.ProvenanceTy, FrameTop, FrameBottom);
      IRB.CreateCall(BS.BsanFuncPopFrame, {FrameBottom, FrameLen});
      IRB.CreateStore(FrameTop, BS.ProvStack, true);
    }

    if (StaticAllocaVec.size() > 0) {
      for (AllocaInst *AI : StaticAllocaVec) {
        ProvenanceScalar Root = assertProvenanceScalar(AI);
        if (LifetimeInfo->isAliveAfter(AI, &I)) {
          IRB.CreateCall(BS.BsanFuncDeallocStack, {AI, Root.Tag, Root.Info});
          IRB.CreateCall(BS.BsanFuncDestroyStackSlot, {Root.Info});
        }
      }
    }
    for (auto &Ptr : ByValArgs) {
      ProvenanceScalar Root = assertProvenanceScalar(Ptr);
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

  IRBuilder<> switchToInsertionPointAfterCall(CallBase *CB) {
    Instruction *NextInst;
    if (auto *II = dyn_cast<InvokeInst>(CB)) {
      if (II->getNormalDest()->getSinglePredecessor()) {
        NextInst = &II->getNormalDest()->front();
      } else {
        NextInst = &SplitEdge(II->getParent(), II->getNormalDest())->front();
      }
    } else {
      assert(CB->getIterator() != CB->getParent()->end());
      NextInst = CB->getNextNode();
    }
    BasicBlock *Pred = CurrentBlock;
    CurrentBlock = NextInst->getParent();
    return IRBuilder<>(NextInst);
  }
};

Instruction *BorrowSanitizer::createBsanModuleDtor(Module &M) {
  IRBuilder<> IRB(M.getContext());

  BsanDtorFunction = Function::createWithDefaultAttr(
      FunctionType::get(IRB.getVoidTy(), false), GlobalValue::InternalLinkage,
      0, kBsanModuleDtorName, &M);
  BsanDtorFunction->addFnAttr(Attribute::NoUnwind);

  ExternCalledFns.insert(BsanDtorFunction);

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

  BsanCtorFunction->addFnAttr(Attribute::DisableSanitizerInstrumentation);
  BsanDtorFunction->addFnAttr(Attribute::DisableSanitizerInstrumentation);

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
                                        bool CtorComdat) {
  for (auto &G : M.globals()) {
    GlobalDescription GD = getGlobalDescription(&G);
    if (GD.AssocFn.has_value()) {
      ExternCalledFns.insert(GD.AssocFn.value());
    }
  }

  auto RecordExternCalled = [&](Constant *C) {
    // Elements of LLVM's @llvm.global_ctors and @llvm.global_dtors
    // arrays are structs with three fields: the priority, a function pointer,
    // and the data passed to the function. At the moment, we only care about
    // the second operand: the function. We need to indicate to the
    // instrumentation pass that all parameters to this function will have
    // wildcard provenance.
    // TODO: When can we trust the data that is passed to a constructor or
    // destructor?
    if (ConstantStruct *CS = dyn_cast<ConstantStruct>(C)) {
      if (Function *F = dyn_cast<Function>(CS->getOperand(1))) {
        ExternCalledFns.insert(F);
      }
    }
    return C;
  };

  transformGlobalCtors(M, RecordExternCalled);
  transformGlobalDtors(M, RecordExternCalled);
}

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

  BsanFuncMarkTLS = M.getOrInsertFunction(
      kBsanFuncMarkTLSName, FunctionType::get(PtrTy, /*isVarArg=*/false), AL);

  BsanFuncValidateParamTLS = M.getOrInsertFunction(
      kBsanFuncValidateParamTLSName, AL, IRB.getVoidTy(), IntptrTy);

  BsanFuncValidateRetvalTLS = M.getOrInsertFunction(
      kBsanFuncValidateRetvalTLSName, AL, IRB.getVoidTy(), IntptrTy, PtrTy);

  BsanFuncShadowLoad = M.getOrInsertFunction(kBsanFuncGetShadowLoadName, AL,
                                             IRB.getVoidTy(), PtrTy, PtrTy);

  BsanFuncShadowStore = M.getOrInsertFunction(
      kBsanFuncGetShadowStoreName, AL, IRB.getVoidTy(), IntptrTy, PtrTy, PtrTy);

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

  BsanFuncAssertProvenanceNull = M.getOrInsertFunction(
      kBsanFuncAssertProvenanceNull, AL, IRB.getVoidTy(), IntptrTy, PtrTy);

  BsanFuncAssertProvenanceWildcard = M.getOrInsertFunction(
      kBsanFuncAssertProvenanceWildcard, AL, IRB.getVoidTy(), IntptrTy, PtrTy);

  BsanFuncAssertProvenanceValid = M.getOrInsertFunction(
      kBsanFuncAssertProvenanceValid, AL, IRB.getVoidTy(), IntptrTy, PtrTy);

  BsanFuncAssertProvenanceInvalid = M.getOrInsertFunction(
      kBsanFuncAssertProvenanceInvalid, AL, IRB.getVoidTy(), IntptrTy, PtrTy);

  BsanFuncDebugPrint = M.getOrInsertFunction(kBsanFuncDebugPrint, AL,
                                             IRB.getVoidTy(), IntptrTy, PtrTy);

  BsanFuncDebugPrintBorrowState = M.getOrInsertFunction(
      kBsanFuncDebugPrintBorrowState, AL, IRB.getVoidTy(), IntptrTy, PtrTy);

  BsanFuncDebugTreeSize = M.getOrInsertFunction(
      kBsanFuncDebugTreeSize, AL, IRB.getVoidTy(), IntptrTy, PtrTy);

  BsanFuncDebugSnapshot = M.getOrInsertFunction(
      kBsanFuncDebugSnapshot, AL, IRB.getVoidTy(), IntptrTy, PtrTy);

  BsanFuncDebugPrintDiff = M.getOrInsertFunction(
      kBsanFuncDebugPrintDiff, AL, IRB.getVoidTy(), IntptrTy, PtrTy);

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
  ProvStack = getOrInsertTLSGlobal(M, kBsanProvStackName, PtrTy);
  TrustFlag = getOrInsertTLSGlobal(M, kBsanTrustFlagName, IntptrTy);
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
