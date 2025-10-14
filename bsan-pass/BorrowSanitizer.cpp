#include "BorrowSanitizer.h"
#include "Declarations.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/DomTreeUpdater.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/StackLifetime.h"
#include "llvm/Analysis/StackSafetyAnalysis.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/EHPersonalities.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/EscapeEnumerator.h"
#include "llvm/Transforms/Utils/Instrumentation.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

// Command-line flags:
static cl::opt<bool>
    ClWithComdat("bsan-with-comdat",
                 cl::desc("Place BSan constructors in comdat sections"),
                 cl::Hidden, cl::init(true));

static cl::opt<bool>
    ClUseStackSafety("bsan-use-stack-safety", cl::Hidden, cl::init(true),
                     cl::Hidden, cl::desc("Use Stack Safety analysis results"),
                     cl::Optional);

static cl::opt<bool>
    ClTrustExtern("bsan-trust-extern", cl::Hidden, cl::init(true), cl::Hidden,
                  cl::desc("Trust external functions to be instrumented."),
                  cl::Optional);

class BorrowSanitizerVisitor : public InstVisitor<BorrowSanitizerVisitor> {
  friend class InstVisitor<BorrowSanitizerVisitor>;
  Function &F;
  BorrowSanitizer &BS;
  DIBuilder DIB;
  LLVMContext *C;

  DominatorTree &DT;
  const TargetLibraryInfo *TLI;

  // The first instruction in the body of the function, which is set to be
  // a call to __bsan_push_frame.
  Instruction *FnPrologueStart;
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
  unsigned NumFnEntryRetags = 0;

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
  DenseMap<AllocaInst *, std::pair<Value *, ProvenanceScalar>>
      SingletonAllocaMap;

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
  // given `alloca` in a particular block will depend on all of its incoming
  // blocks.
  SmallVector<std::tuple<BasicBlock *, AllocaInst *, ProvenanceScalar>>
      AllocaProvPHINodes;

  // After inserting our instrumentation, we remove our retag intrinsics.
  SmallVector<CallBase *> ToRemove;

  SmallVector<CallBase *> ToReplace;

  // We use LLVM's lifetime analysis to determine which `allocas` are alive at
  // every exit point.
  std::unique_ptr<StackLifetime> LifetimeInfo;

public:
  BorrowSanitizerVisitor(Function &F, BorrowSanitizer &BS,
                         const TargetLibraryInfo &TLI, DominatorTree &DT)
      : F(F), BS(BS), DIB(*F.getParent(), /*AllowUnresolved*/ false), C(BS.C),
        TLI(&TLI), CurrentBlock(&F.getEntryBlock()), DT(DT) {}

  bool run() {
    EscapeEnumerator EE(F, "bsan_cleanup", true);
    while (IRBuilder<> *AtExit = EE.Next()) {
    }

    for (BasicBlock *BB :
         ReversePostOrderTraversal<BasicBlock *>(&F.getEntryBlock())) {
      populateBlock(BB);
    }

    if (Instructions.empty())
      return false;

    initStack();

    for (auto const &[BB, Insts] : Instructions) {
      CurrentBlock = BB;
      for (Instruction *I : Insts) {
        InstVisitor<BorrowSanitizerVisitor>::visit(*I);
      }
    }

    patchPHINodes();

    for (CallBase *CB : ToRemove) {
      CB->eraseFromParent();
    }
    for (CallBase *CB : ToReplace) {
      CB->replaceAllUsesWith(CB->getOperand(0));
      CB->eraseFromParent();
    }
    return true;
  }

private:
  Value *offsetPointer(IRBuilder<> &IRB, const DataLayout *DL, Value *Pointer,
                       Value *Offset) {
    if (ConstantInt *CI = dyn_cast<ConstantInt>(Offset))
      if (CI->isZero())
        return Pointer;
    Value *Base = IRB.CreatePointerCast(Pointer, IRB.getIntPtrTy(*DL));
    Base = IRB.CreateAdd(Base, Offset);
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
      IRBuilder<> EntryIRB(FnPrologueStart);
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

    case Type::FixedVectorTyID: {
      FixedVectorType *VT = cast<FixedVectorType>(CurrentTy);
      Value *CurrByteOffset = ByteOffset;
      if (VT->getElementType()->isPointerTy()) {
        for (unsigned Idx = 0; Idx < VT->getElementCount().getFixedValue();
             ++Idx) {
          auto [BOffset, POffset] = populateProvenanceComponents(
              IRB, Components, ParentTy, VT->getElementType(), CurrByteOffset,
              NextProvOffset);
          CurrByteOffset = BOffset;
          NextProvOffset = POffset;
        }
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
                               Provenance Prov) {

    ProvenancePointer ProvPtr;
    if (Prov.isVector()) {
      Value *IdDest, *TagDest, *InfoDest;
      std::tie(IdDest, TagDest, InfoDest) =
          allocateProvenanceVectors(IRB, Prov.Elems);

      ProvenancePointer ProvPtr = ProvenancePointer(
          IdDest, TagDest, InfoDest, Prov.Elems, ProvenanceKind::Vector);
      Prov.store(IRB, BS.PL, ProvPtr);

      Value *ElemCount = IRB.CreateElementCount(BS.IntptrTy, Prov.Elems);
      IRB.CreateCall(BS.BsanFuncShadowStoreVector,
                     {ObjAddr, ElemCount, IdDest, TagDest, InfoDest});
    } else {
      Value *ShadowPointer =
          IRB.CreateCall(BS.BsanFuncGetShadowDest, {ObjAddr});
      ProvenancePointer Dest =
          ProvenancePointerScalar(IRB, BS.PL, ShadowPointer);
      Prov.store(IRB, BS.PL, Dest);
    }
  }

  // Loads a provenance value into shadow memory starting at the given object
  // address.
  Provenance loadProvenanceFromShadow(IRBuilder<> &IRB,
                                      ProvenanceComponent &Comp,
                                      Value *ObjAddr) {
    ProvenancePointer ProvPtr;
    if (Comp.isVector()) {
      // We're dealing with a scalable vector of pointers.
      // First, we create vectors to store each of the three components
      // of provenance values. We can't create an array of provenance values
      // because the vector might be scalable, and arrays need to have a static
      // size.
      Value *IdVector, *TagVector, *InfoVector;
      std::tie(IdVector, TagVector, InfoVector) =
          allocateProvenanceVectors(IRB, Comp.Elems);

      // When we load a vector from shadow memory, we split each of the
      // provenance values into their components, storing them into each of the
      // component vector allocas. We need to use intermediate allocas so that
      // our runtime helper function can handle vectors of any size.
      IRB.CreateCall(
          BS.BsanFuncShadowLoadVector,
          {ObjAddr, Comp.NumProvenanceValues, IdVector, TagVector, InfoVector});

      ProvPtr =
          ProvenancePointerVector(IdVector, TagVector, InfoVector, Comp.Elems);
    } else {
      Value *ShadowPointer = IRB.CreateCall(BS.BsanFuncGetShadowSrc, {ObjAddr});
      ProvPtr = ProvenancePointerScalar(IRB, BS.PL, ShadowPointer);
    }
    return Provenance::load(IRB, BS.PL, ProvPtr);
  }

  // Allocates vectors of each provenance component for a vector provenance
  // value.
  std::tuple<Value *, Value *, Value *>
  allocateProvenanceVectors(IRBuilder<> &IRB, ElementCount Elems) {
    Value *IdVector = IRB.CreateAlloca(VectorType::get(BS.IntptrTy, Elems));
    Value *TagVector = IRB.CreateAlloca(VectorType::get(BS.IntptrTy, Elems));
    Value *InfoVector = IRB.CreateAlloca(VectorType::get(BS.PtrTy, Elems));
    return std::make_tuple(IdVector, TagVector, InfoVector);
  }

  // The main function of the instrumentation pass.
  void populateBlock(BasicBlock *BB) {
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
        if (isFnEntryRetag(CB))
          NumFnEntryRetags += 1;
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

  // Populates the array of argument provenance pointers and initializes the
  // start and end of the function prologue.
  void initStack() {
    BasicBlock *EntryBlock = &F.getEntryBlock();
    IRBuilder<> EntryIRB(EntryBlock, EntryBlock->getFirstNonPHIIt());

    Value *TotalNumProvenanceValues = BS.Zero;
    for (auto &Arg : F.args()) {
      SmallVector<ProvenanceComponent> *Components =
          getProvenanceComponents(EntryIRB, Arg.getType());
      for (auto &C : *Components) {
        Value *CurrentArrayByteOffset =
            EntryIRB.CreateMul(TotalNumProvenanceValues, BS.ProvenanceSize);
        Value *CurrentArraySlot =
            offsetPointer(EntryIRB, BS.DL, BS.ParamTLS, CurrentArrayByteOffset);
        ProvenancePointer Ptr =
            C.getPointerToProvenance(EntryIRB, BS.PL, CurrentArraySlot);
        ArgumentProvenance[&Arg].push_back(Ptr);
        TotalNumProvenanceValues =
            EntryIRB.CreateAdd(TotalNumProvenanceValues, C.NumProvenanceValues);
      }
    }
    if (NumFnEntryRetags > 0) {
      EntryIRB.CreateCall(BS.BsanFuncPushRetagFrame, {});
    }

    if (StaticAllocaVec.size() > 0) {
      EntryIRB.CreateCall(BS.BsanFuncPushAllocaFrame, {});
      for (AllocaInst *AI : StaticAllocaVec) {
        if (HasLifetimeStart.contains(AI)) {
          if (HasLifetimeStart[AI].size() > 1) {
            AllocaProvMap[EntryBlock][AI] = BS.InvalidProvenance;
          } else {
            SingletonAllocaMap[AI] = createAllocaMetadata(EntryIRB, AI);
          }
        } else {
          IRBuilder<> IRB(AI->getNextNode());
          BaseProvMap.set({AI, 0}, createAndInitAllocaMetadata(IRB, AI));
        }
      }
    }

    FnPrologueStart = EntryIRB.CreateIntrinsic(Intrinsic::donothing, {});
    LifetimeInfo = std::make_unique<StackLifetime>(
        F, StaticAllocaVec, StackLifetime::LivenessType::May);
    LifetimeInfo->run();
  }

  void patchPHINodes() {
    IRBuilder<> EntryIRB(FnPrologueStart);

    for (auto &[PN, Prov, Idx] : ProvPHINodes) {
      for (auto [V, IncomingBlock] :
           llvm::zip(PN->incoming_values(), PN->blocks())) {
        Provenance IncomingProv = assertProvenance(
            EntryIRB, IncomingBlock, Prov.Kind, Prov.Elems, {V, Idx});
        Prov.addIncoming(IncomingBlock, IncomingProv);
      }
    }

    SmallVector<PHINode *> Worklist;
    for (const auto &[BB, AI, Prov] : AllocaProvPHINodes) {
      PHINode *IdNode = cast<PHINode>(Prov.Id);
      Worklist.push_back(IdNode);
      PHINode *TagNode = cast<PHINode>(Prov.Tag);
      Worklist.push_back(TagNode);
      PHINode *InfoNode = cast<PHINode>(Prov.Info);
      Worklist.push_back(InfoNode);
      for (BasicBlock *IncomingBlock : predecessors(BB)) {

        ProvenanceScalar IncomingProv =
            assertAllocaProvenance(IncomingBlock, AI);
        IdNode->setIncomingValueForBlock(IncomingBlock, IncomingProv.Id);
        TagNode->setIncomingValueForBlock(IncomingBlock, IncomingProv.Tag);
        InfoNode->setIncomingValueForBlock(IncomingBlock, IncomingProv.Info);
      }
    }
    SmallVector<PHINode *> PHIToDelete;
    do {
      PHIToDelete.clear();
      SmallVector<PHINode *> PendingWorklist;
      for (PHINode *PN : Worklist) {
        std::optional<Value *> Replacement = canEliminatePHI(PN);
        if (Replacement.has_value()) {
          PN->replaceAllUsesWith(Replacement.value());
          PHIToDelete.push_back(PN);
        } else {
          PendingWorklist.push_back(PN);
        }
      }
      for (PHINode *PN : PHIToDelete) {
        PN->removeFromParent();
      }
      Worklist = PendingWorklist;
    } while (PHIToDelete.size() > 0);
  }

  std::optional<Value *> canEliminatePHI(PHINode *PN) {
    std::optional<Value *> Sentinel = std::nullopt;
    bool FoundDifferent = false;
    for (Value *Incoming : PN->incoming_values()) {
      if (Incoming == PN)
        continue;
      if (Sentinel.has_value()) {
        FoundDifferent = FoundDifferent || Incoming != Sentinel.value();
      } else {
        Sentinel = Incoming;
      }
    }
    if (FoundDifferent) {
      return std::nullopt;
    }
    return Sentinel;
  }

  Value *newAllocId(IRBuilder<> &IRB) {
    return IRB.CreateAtomicRMW(AtomicRMWInst::Add, BS.AllocIdCounter, BS.One,
                               std::nullopt, AtomicOrdering::Monotonic);
  }

  Value *newBorrowTag(IRBuilder<> &IRB) {
    return IRB.CreateAtomicRMW(AtomicRMWInst::Add, BS.BorTagCounter, BS.One,
                               std::nullopt, AtomicOrdering::Monotonic);
  }

  // Allocates object metadata for a stack or heap allocation.
  ProvenanceScalar instrumentHeapAllocation(IRBuilder<> &IRB, Value *Address,
                                            Value *Size) {
    Value *Id = newAllocId(IRB);
    Value *Tag = newBorrowTag(IRB);
    Value *Info = IRB.CreateCall(BS.BsanFuncAlloc, {Address, Size, Id, Tag});
    ProvenanceScalar Prov = ProvenanceScalar(Id, Tag, Info);
    setProvenance(Address, Prov);
    return Prov;
  }

  // We only instrument allocations that have a non-zero size.
  bool shouldInstrumentAlloca(AllocaInst &AI) {
    // Although Rust emits retags for ZSTs, tracking
    // allocations leads to false positive errors—probably
    // due to interactions with lowering.
    return (AI.getAllocatedType()->isSized() &&
            !BS.getAllocaSizeInBytes(AI).isZero());
  }

  // Deallocates a pointer.
  void instrumentDeallocation(IRBuilder<> &IRB, Value *Ptr) {
    ProvenanceScalar Prov = assertProvenanceScalar(Ptr);
    IRB.CreateCall(BS.BsanFuncDealloc,
                   {Ptr, Prov.Id, Prov.Tag, Prov.Info, BS.True});
  }

  bool isRustShim(CallBase &CB) {
    if (isAllocationFn(&CB, TLI) || getFreedOperand(&CB, TLI)) {
      if (Function *Callee = CB.getCalledFunction()) {
        for (const char *Name : kRustAllocFns) {
          if (Callee->getName().ends_with(Name)) {
            return true;
          }
        }
      }
    }
    return false;
  }

  bool isFnEntryRetag(CallBase *CB) {
    if (Function *Callee = CB->getCalledFunction()) {
      if (Callee->getName().starts_with(kBsanRetagPrefix)) {
        std::optional<Value *> LastOperand = std::nullopt;
        LastOperand = CB->getOperand(3);
        if (LastOperand.has_value()) {
          if (ConstantInt *CI = dyn_cast<ConstantInt>(LastOperand.value())) {
            return !CI->isZero();
          }
          report_fatal_error("Invalid parameters to retag");
        }
      }
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
    } else {
      report_fatal_error("Unknown debug function: " + Twine(Name) + "\n");
    }

    IRB.CreateCall(Callee, {Prov.Id, Prov.Tag, Prov.Info});
    CB.eraseFromParent();
  }

  Value *resolveAllocSize(IRBuilder<> &IRB, CallBase &CB) {
    Value *AllocSize;
    // The function `getAllocSize` will only return a value if the allocation
    // function is being called with a constant integer. If not, then we need to
    // resolve the allocation size manually based on the semantics of
    // `allocsize`.
    std::optional<APInt> OptAllocSize = getAllocSize(&CB, TLI);
    if (OptAllocSize.has_value()) {
      AllocSize =
          ConstantInt::get(BS.IntptrTy, OptAllocSize.value().getZExtValue());
    } else {
      Attribute Attr = CB.getFnAttr(Attribute::AllocSize);
      if (Attr == Attribute()) {
        report_fatal_error(
            "Unable to resolve `allocsize` attribute for function with "
            "`allockind(\"alloc\")`");
      }
      std::pair<unsigned, std::optional<unsigned>> Args =
          Attr.getAllocSizeArgs();
      AllocSize = CB.getArgOperand(Args.first);

      if (Args.second.has_value())
        AllocSize =
            IRB.CreateMul(AllocSize, CB.getArgOperand(Args.second.value()));
    }
    return AllocSize;
  }

  void instrumentRetagPlace(CallBase &CB) {
    ToRemove.push_back(&CB);

    IRBuilder<> IRB(&CB);
    Value *ObjAddr = CB.getOperand(0);

    Value *ShadowPointer = IRB.CreateCall(BS.BsanFuncGetShadowSrc, {ObjAddr});

    ProvenancePointerScalar ProvPtr =
        ProvenancePointerScalar(IRB, BS.PL, ShadowPointer);
    ProvenanceScalar Prov = Provenance::loadScalar(IRB, BS.PL, ProvPtr);

    Value *NewTag = newBorrowTag(IRB);
    IRB.CreateCall(BS.BsanFuncRetag,
                   {CB.getOperand(0), CB.getOperand(1), CB.getOperand(2),
                    Prov.Id, Prov.Tag, Prov.Info, NewTag});
    StoreInst *SI = IRB.CreateStore(NewTag, ProvPtr.TagPtr);
    SI->setVolatile(1);
  }

  void instrumentRetagOperand(CallBase &CB) {
    ToReplace.push_back(&CB);
    IRBuilder<> IRB(&CB);
    ProvenanceScalar Prov = assertProvenanceScalar(CB.getOperand(0));
    Value *NewTag = newBorrowTag(IRB);

    IRB.CreateCall(BS.BsanFuncRetag,
                   {CB.getOperand(0), CB.getOperand(1), CB.getOperand(2),
                    Prov.Id, Prov.Tag, Prov.Info, NewTag});
    Prov.Tag = NewTag;
    setProvenance(&CB, Prov);
  }

  using InstVisitor<BorrowSanitizerVisitor>::visit;

  void visitCallBase(CallBase &CB) {
    assert(!CB.getMetadata(LLVMContext::MD_nosanitize));
    assert(!isa<IntrinsicInst>(CB) && "intrinsics are handled elsewhere");

    if (CB.isInlineAsm())
      return;

    Function *Callee = CB.getCalledFunction();

    if (Callee && Callee->getName().starts_with(kBsanDebugPrefix)) {
      return handleDebugFunction(CB, Callee);
    }

    if (Callee && Callee->getName().starts_with(kBsanPrefix)) {
      if (Callee->getName() == kBsanIntrinsicRetagOperandName) {
        instrumentRetagOperand(CB);
      } else if (Callee->getName() == kBsanIntrinsicRetagPlaceName) {
        instrumentRetagPlace(CB);
      }
      return;
    }

    // If we've made it here, then we don't have a hard-coded way to handle this
    // function. We need to pass its arguments into our thread-local array and
    // then read the provenance for the return value.
    IRBuilder<> Before(&CB);
    bool IsExternFunction = !Callee || (Callee && Callee->isDeclaration());

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
        Value *Slot = offsetPointer(Before, BS.DL, BS.ParamTLS, ParamByteWidth);

        Provenance ProvSrc = assertProvenance(Before, Comp, {Arg, Idx});
        ProvenancePointer Dest =
            ProvenancePointer(Before, BS.PL, Slot, Comp.Elems, ProvSrc.Kind);
        ProvSrc.store(Before, BS.PL, Dest);

        Value *ByteWidth =
            Before.CreateMul(Comp.NumProvenanceValues, BS.ProvenanceSize);
        ParamByteWidth = Before.CreateAdd(ParamByteWidth, ByteWidth);
      }
    }

    // We need to do some extra work here to compute where to insert our
    // instructions, since some function calls occur within terminators.
    IRBuilder<> After = switchToInsertionPointAfterCall(&CB);

    if (!isRustShim(CB)) {
      // If we're calling a heap allocation or deallocation function,
      // then we can skip handling argument provenance and defer to our
      // run-time calls.
      std::optional<APInt> AllocSize = getAllocSize(&CB, TLI);

      if (isAllocLikeFn(&CB, TLI)) {
        Value *Size = resolveAllocSize(After, CB);
        instrumentHeapAllocation(After, &CB, Size);
        return;
      }

      if (Value *Operand = getReallocatedOperand(&CB)) {
        Value *Size = resolveAllocSize(After, CB);
        instrumentHeapAllocation(After, &CB, Size);
        instrumentDeallocation(After, Operand);
        return;
      }

      if (Value *Operand = getFreedOperand(&CB, TLI)) {
        instrumentDeallocation(After, Operand);
        return;
      }
    }

    // Unsized return types do not have provenance, so we can skip handling the
    // return array.
    if (CB.getType()->isSized()) {
      SmallVector<ProvenanceComponent> *ReturnComponents =
          getProvenanceComponents(Before, CB.getType());

      // Load each provenance component for the return type from the
      // thread-local return value array. Also, compute the byte-width of the
      // provenance components that we expect to be here. If the function that
      // we are calling is uninstrumented, then we need ensure that the return
      // array is populated with default values.

      Value *RetvalByteWidth = BS.Zero;

      for (const auto &[Idx, Comp] : llvm::enumerate(*ReturnComponents)) {
        Value *Slot =
            offsetPointer(After, BS.DL, BS.RetvalTLS, RetvalByteWidth);

        ProvenancePointer Ptr = Comp.getPointerToProvenance(After, BS.PL, Slot);
        setProvenance({&CB, Idx}, Provenance::load(After, BS.PL, Ptr));

        Value *ByteWidth =
            Before.CreateMul(Comp.NumProvenanceValues, BS.ProvenanceSize);
        RetvalByteWidth = Before.CreateAdd(RetvalByteWidth, ByteWidth);
      }

      if (IsExternFunction)
        Before.CreateMemSet(BS.RetvalTLS, ConstantInt::get(BS.Int8Ty, 0),
                            RetvalByteWidth, BS.ProvenanceAlign);
    }
  }

  ProvenanceVector
  createVectorProvenancePHI(IRBuilder<> &IRB, ElementCount Elems,
                            iterator_range<pred_iterator> Blocks) {
    unsigned NumIncoming = std::distance(Blocks.begin(), Blocks.end());
    Type *IntptrVector = VectorType::get(BS.IntptrTy, Elems);
    Type *PtrVector = VectorType::get(BS.PtrTy, Elems);

    PHINode *IdNode = IRB.CreatePHI(IntptrVector, NumIncoming, "_bsphi_vec_id");
    IdNode->dropDbgRecords();
    PHINode *TagNode =
        IRB.CreatePHI(IntptrVector, NumIncoming, "_bsphi_vec_tag");
    TagNode->dropDbgRecords();
    PHINode *InfoNode =
        IRB.CreatePHI(PtrVector, NumIncoming, "_bsphi_vec_info");
    InfoNode->dropDbgRecords();

    ProvenanceVector WildcardVector =
        ProvenanceVector::wildcard(IRB, BS.PL, Elems);

    for (BasicBlock *BB : Blocks) {
      IdNode->addIncoming(WildcardVector.Id, BB);
      TagNode->addIncoming(WildcardVector.Tag, BB);
      InfoNode->addIncoming(WildcardVector.Info, BB);
    }

    return ProvenanceVector(IdNode, TagNode, InfoNode, Elems);
  }

  ProvenanceScalar
  createScalarProvenancePHI(IRBuilder<> &IRB,
                            iterator_range<pred_iterator> Blocks) {
    unsigned NumIncoming = std::distance(Blocks.begin(), Blocks.end());
    PHINode *IdNode = IRB.CreatePHI(BS.IntptrTy, NumIncoming, "_bsphi_id");
    IdNode->dropDbgRecords();
    PHINode *TagNode = IRB.CreatePHI(BS.IntptrTy, NumIncoming, "_bsphi_tag");
    TagNode->dropDbgRecords();
    PHINode *InfoNode = IRB.CreatePHI(BS.PtrTy, NumIncoming, "_bsphi_info");
    InfoNode->dropDbgRecords();

    for (BasicBlock *BB : Blocks) {
      IdNode->addIncoming(BS.WildcardProvenance.Id, BB);
      TagNode->addIncoming(BS.WildcardProvenance.Tag, BB);
      InfoNode->addIncoming(BS.WildcardProvenance.Info, BB);
    }
    return ProvenanceScalar(IdNode, TagNode, InfoNode);
  }

  Provenance createProvenancePHI(IRBuilder<> &IRB, ProvenanceComponent Comp,
                                 iterator_range<pred_iterator> Blocks) {
    if (Comp.isVector()) {
      return createVectorProvenancePHI(IRB, Comp.Elems, Blocks);
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
    Value *Id = newAllocId(IRB);
    Value *Tag = newBorrowTag(IRB);
    Value *Info = IRB.CreateCall(BS.BsanFuncReserveStackSlot, {});
    return std::make_pair(Size, ProvenanceScalar(Id, Tag, Info));
  }

  void initAllocaMetadata(IRBuilder<> &IRB, AllocaInst *AI, Value *Size,
                          ProvenanceScalar Prov) {
    IRB.CreateCall(BS.BsanFuncAllocStack,
                   {AI, Size, Prov.Id, Prov.Tag, Prov.Info});
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
    if (CurrentProv != BS.InvalidProvenance &&
        CurrentProv != BS.WildcardProvenance) {
      IRB.CreateCall(BS.BsanFuncDeallocWeak,
                     {AI, CurrentProv.Id, CurrentProv.Tag, CurrentProv.Info});
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
    if (Root != BS.InvalidProvenance && Root != BS.WildcardProvenance) {
      IRB.CreateCall(BS.BsanFuncDeallocWeak,
                     {AI, Root.Id, Root.Tag, Root.Info});
    }
  }

  // Whenever we memset, we need to clear the corresponding shadow memory
  // section This should be removed when interceptors are implemented.
  void visitMemSetInst(MemSetInst &I) {
    IRBuilder<> IRB(&I);
    IRB.CreateCall(
        BS.BsanFuncShadowClear,
        {I.getDest(), IRB.CreateIntCast(I.getLength(), BS.IntptrTy, false)});
  }

  // Whenever we memcpy, we need to copy the corresponding shadow memory section
  // This should be removed when interceptors are implemented.
  void visitMemTransferInst(MemTransferInst &I) {
    IRBuilder<> IRB(&I);
    IRB.CreateCall(BS.BsanFuncShadowCopy,
                   {I.getSource(), I.getDest(),
                    IRB.CreateIntCast(I.getLength(), BS.IntptrTy, false)});
  }

  // Inserts a check to validate a read access.
  void insertReadCheck(IRBuilder<> &IRB, Instruction *Inst, Value *Ptr,
                       Value *Size) {
    ProvenanceScalar Prov = assertProvenanceScalar(Ptr);
    IRB.CreateCall(BS.BsanFuncRead, {Ptr, Size, Prov.Id, Prov.Tag, Prov.Info});
  }

  // Inserts a check to validate a write access.
  void insertWriteCheck(IRBuilder<> &IRB, Instruction *Inst, Value *Ptr,
                        Value *Size) {
    ProvenanceScalar Prov = assertProvenanceScalar(Ptr);
    IRB.CreateCall(BS.BsanFuncWrite, {Ptr, Size, Prov.Id, Prov.Tag, Prov.Info});
  }

  void visitLoadInst(LoadInst &LI) {
    IRBuilder<> IRB(&LI);
    Value *Ptr = LI.getPointerOperand();

    Value *Size =
        IRB.CreateTypeSize(BS.IntptrTy, BS.DL->getTypeAllocSize(LI.getType()));
    insertReadCheck(IRB, &LI, Ptr, Size);

    // Load provenance for the value from shadow memory.
    SmallVector<ProvenanceComponent> *Components =
        getProvenanceComponents(IRB, LI.getType());
    Value *Base = LI.getPointerOperand();
    for (const auto &[Idx, Comp] : llvm::enumerate(*Components)) {
      ShadowFootprint Footprint = Comp.Footprint;
      Value *ObjAddr = offsetPointer(IRB, BS.DL, Base, Footprint.ByteOffset);
      Provenance Prov = loadProvenanceFromShadow(IRB, Comp, ObjAddr);
      setProvenance({&LI, Idx}, Prov);
    }
  }

  void visitStoreInst(StoreInst &SI) {
    IRBuilder<> IRB(&SI);
    Value *Ptr, *Val;
    Ptr = SI.getPointerOperand();
    Val = SI.getValueOperand();

    Value *Size = IRB.CreateTypeSize(BS.IntptrTy,
                                     BS.DL->getTypeAllocSize(Val->getType()));
    insertWriteCheck(IRB, &SI, Ptr, Size);

    // Store provenance for the value into shadow memory.
    Value *Base = SI.getPointerOperand();
    SmallVector<ProvenanceComponent> *Components =
        getProvenanceComponents(IRB, Val->getType());

    for (const auto &[Idx, Comp] : llvm::enumerate(*Components)) {
      ShadowFootprint Footprint = Comp.Footprint;
      Value *ObjAddr = offsetPointer(IRB, BS.DL, Base, Footprint.ByteOffset);

      Provenance Prov;
      ProvenanceKey Key = {SI.getValueOperand(), Idx};
      if (Comp.isVector()) {
        Prov = assertProvenanceVector(IRB, Key, Comp.Elems);
      } else {
        Prov = assertProvenanceScalar(Key);
      }
      storeProvenanceToShadow(IRB, ObjAddr, Prov);
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

  void visitExtractElementInst(ExtractElementInst &EE) {
    IRBuilder<> IRB(&EE);
    VectorType *SrcType = EE.getVectorOperandType();

    if (SrcType->getElementType()->isPointerTy()) {
      Value *V = EE.getVectorOperand();

      VectorType *VT = dyn_cast<VectorType>(V->getType());
      ProvenanceVector VP =
          assertProvenanceVector(IRB, V, VT->getElementCount());

      Value *Idx = EE.getIndexOperand();

      Value *Id, *Tag, *Info;
      Id = IRB.CreateExtractElement(VP.Id, Idx);
      Tag = IRB.CreateExtractElement(VP.Tag, Idx);
      Info = IRB.CreateExtractElement(VP.Info, Idx);

      setProvenance(&EE, ProvenanceScalar(Id, Tag, Info));
    }
  }

  void visitInsertElementInst(InsertElementInst &IE) {
    IRBuilder<> IRB(&IE);
    VectorType *DestType = IE.getType();

    if (DestType->getElementType()->isPointerTy()) {
      Value *V = IE.getOperand(0);

      VectorType *VT = dyn_cast<VectorType>(V->getType());
      ProvenanceVector VP =
          assertProvenanceVector(IRB, V, VT->getElementCount());

      Value *S = IE.getOperand(1);
      ProvenanceScalar SP = assertProvenanceScalar(S);

      Value *Idx = IE.getOperand(2);
      IRB.CreateInsertElement(VP.Id, SP.Id, Idx);
      IRB.CreateInsertElement(VP.Tag, SP.Tag, Idx);
      IRB.CreateInsertElement(VP.Info, SP.Info, Idx);
    }
  }

  void visitShuffleVectorInst(ShuffleVectorInst &SI) {
    IRBuilder<> IRB(&SI);
    VectorType *SpecificTy = SI.getType();
    if (SpecificTy->getElementType()->isPointerTy()) {
      Value *LHS = SI.getOperand(0);
      VectorType *LHT = dyn_cast<VectorType>(LHS->getType());
      ProvenanceVector VPL =
          assertProvenanceVector(IRB, LHS, LHT->getElementCount());

      Value *RHS = SI.getOperand(1);
      VectorType *RHT = dyn_cast<VectorType>(RHS->getType());
      ProvenanceVector VPR =
          assertProvenanceVector(IRB, RHS, RHT->getElementCount());

      ArrayRef<int> Mask = SI.getShuffleMask();

      Value *ShuffledIds = IRB.CreateShuffleVector(VPL.Id, VPR.Id, Mask);
      Value *ShuffledTags = IRB.CreateShuffleVector(VPL.Tag, VPR.Tag, Mask);
      Value *ShuffledInfo = IRB.CreateShuffleVector(VPL.Info, VPR.Info, Mask);

      ElementCount DestElems = ElementCount::get(Mask.size(), false);

      setProvenance(&SI, ProvenanceVector(ShuffledIds, ShuffledTags,
                                          ShuffledInfo, DestElems));
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
        // For scalable vectors, we need a select instruction for each component
        // vector, as well as for the length. Even though the length of a
        // scalable vector will be fixed at runtime (only the scaling factor is
        // dynamically determined, and remains fixed), we still need to account
        // for null provenance inputs, and the length of the null vector
        // provenance is zero.
        ProvenanceVector ProvL =
            assertProvenanceVector(IRB, {SI.getTrueValue(), Idx}, Comp.Elems);
        ProvenanceVector ProvR =
            assertProvenanceVector(IRB, {SI.getFalseValue(), Idx}, Comp.Elems);

        Value *Id = IRB.CreateSelect(SI.getCondition(), ProvL.Id, ProvR.Id);
        Value *Tag = IRB.CreateSelect(SI.getCondition(), ProvL.Tag, ProvR.Tag);
        Value *Info =
            IRB.CreateSelect(SI.getCondition(), ProvL.Info, ProvR.Info);

        setProvenance({&SI, Idx}, ProvenanceVector(Id, Tag, Info, Comp.Elems));
      } else {
        // For scalable provenance, we just select on each of the three
        // components.
        ProvenanceScalar ProvL =
            assertProvenanceScalar({SI.getTrueValue(), Idx});
        ProvenanceScalar ProvR =
            assertProvenanceScalar({SI.getFalseValue(), Idx});

        Value *Id = IRB.CreateSelect(SI.getCondition(), ProvL.Id, ProvR.Id);
        Value *Tag = IRB.CreateSelect(SI.getCondition(), ProvL.Tag, ProvR.Tag);
        Value *Info =
            IRB.CreateSelect(SI.getCondition(), ProvL.Info, ProvR.Info);
        setProvenance({&SI, Idx}, ProvenanceScalar(Id, Tag, Info));
      }
    }
  }

  void popFrame(IRBuilder<> &IRB, Instruction &I) {
    if (StaticAllocaVec.size() > 0) {
      for (AllocaInst *AI : StaticAllocaVec) {
        if (LifetimeInfo->isAliveAfter(AI, &I)) {
          ProvenanceScalar Root = assertProvenanceScalar(AI);
          IRB.CreateCall(BS.BsanFuncDeallocWeak,
                         {AI, Root.Id, Root.Tag, Root.Info});
        }
      }
      IRB.CreateCall(BS.BsanFuncPopAllocaFrame, {});
    }

    if (NumFnEntryRetags > 0) {
      IRB.CreateCall(BS.BsanFuncPopRetagFrame, {});
    }
  }

  void visitReturnInst(ReturnInst &I) {
    IRBuilder<> IRB(&I);
    if (Value *RetVal = I.getReturnValue()) {
      SmallVector<ProvenanceComponent> *Components =
          getProvenanceComponents(IRB, RetVal->getType());

      Value *RetvalByteWidth = BS.Zero;
      for (const auto &[Idx, Comp] : llvm::enumerate(*Components)) {
        Value *Slot = offsetPointer(IRB, BS.DL, BS.RetvalTLS, RetvalByteWidth);

        Provenance Prov = assertProvenance(IRB, Comp, {RetVal, Idx});
        ProvenancePointer Dest =
            ProvenancePointer(IRB, BS.PL, Slot, Comp.Elems, Prov.Kind);
        Prov.store(IRB, BS.PL, Dest);

        Value *ByteWidth =
            IRB.CreateMul(Comp.NumProvenanceValues, BS.ProvenanceSize);
        RetvalByteWidth = IRB.CreateAdd(RetvalByteWidth, ByteWidth);
      }
    }
    popFrame(IRB, I);
  }

  void visitResumeInst(ResumeInst &I) {
    IRBuilder<> IRB(&I);
    if (Value *RetVal = I.getValue()) {
      SmallVector<ProvenanceComponent> *Components =
          getProvenanceComponents(IRB, RetVal->getType());

      Value *RetvalByteWidth = BS.Zero;
      for (const auto &[Idx, Comp] : llvm::enumerate(*Components)) {
        Value *Slot = offsetPointer(IRB, BS.DL, BS.RetvalTLS, RetvalByteWidth);

        Provenance Prov = assertProvenance(IRB, Comp, {RetVal, Idx});
        ProvenancePointer Dest =
            ProvenancePointer(IRB, BS.PL, Slot, Comp.Elems, Prov.Kind);
        Prov.store(IRB, BS.PL, Dest);

        Value *ByteWidth =
            IRB.CreateMul(Comp.NumProvenanceValues, BS.ProvenanceSize);
        RetvalByteWidth = IRB.CreateAdd(RetvalByteWidth, ByteWidth);
      }
    }
    popFrame(IRB, I);
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

  bool CtorComdat = true;

  IRBuilder<> IRB(BsanCtorFunction->getEntryBlock().getTerminator());
  instrumentGlobals(IRB, M, &CtorComdat);

  assert(BsanCtorFunction && BsanDtorFunction);
  const int Priority = 1;

  // Put the constructor and destructor in comdat if both
  // (1) global instrumentation is not TU-specific
  // (2) target is ELF.
  if (CtorComdat && TargetTriple.isOSBinFormatELF() && CtorComdat) {
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

void BorrowSanitizer::instrumentGlobals(IRBuilder<> &IRB, Module &M,
                                        bool *CtorComdat) {
  createBsanModuleDtor(M);
}

void BorrowSanitizer::initializeCallbacks(Module &M,
                                          const TargetLibraryInfo &TLI) {
  if (CallbacksInitialized) {
    return;
  }

  IRBuilder<> IRB(*C);

  AttributeList AL;
  AL = AL.addFnAttribute(*C, Attribute::NoUnwind);

  BsanFuncRetag = M.getOrInsertFunction(kBsanFuncRetagName, AL, IRB.getVoidTy(),
                                        PtrTy, IntptrTy, Int64Ty, IntptrTy,
                                        IntptrTy, PtrTy, IntptrTy);

  BsanFuncPushAllocaFrame = M.getOrInsertFunction(
      kBsanFuncPushAllocaFrameName,
      FunctionType::get(IRB.getVoidTy(), /*isVarArg=*/false), AL);

  BsanFuncPopAllocaFrame = M.getOrInsertFunction(
      kBsanFuncPopAllocaFrameName,
      FunctionType::get(IRB.getVoidTy(), /*isVarArg=*/false), AL);

  BsanFuncPushRetagFrame = M.getOrInsertFunction(
      kBsanFuncPushRetagFrameName,
      FunctionType::get(IRB.getVoidTy(), /*isVarArg=*/false), AL);

  BsanFuncPopRetagFrame = M.getOrInsertFunction(
      kBsanFuncPopRetagFrameName,
      FunctionType::get(IRB.getVoidTy(), /*isVarArg=*/false), AL);

  BsanFuncShadowCopy = M.getOrInsertFunction(
      kBsanFuncShadowCopyName, AL, IRB.getVoidTy(), PtrTy, PtrTy, IntptrTy);

  BsanFuncShadowClear = M.getOrInsertFunction(kBsanFuncShadowClearName, AL,
                                              IRB.getVoidTy(), PtrTy, IntptrTy);

  BsanFuncGetShadowDest =
      M.getOrInsertFunction(kBsanFuncGetShadowDestName, AL, PtrTy, PtrTy);

  BsanFuncGetShadowSrc =
      M.getOrInsertFunction(kBsanFuncGetShadowSrcName, AL, PtrTy, PtrTy);

  BsanFuncAlloc = M.getOrInsertFunction(kBsanFuncAllocName, AL, PtrTy, PtrTy,
                                        IntptrTy, IntptrTy, IntptrTy);

  BsanFuncReserveStackSlot =
      M.getOrInsertFunction(kBsanFuncReserveStackSlotName,
                            FunctionType::get(PtrTy, /*isVarArg=*/false), AL);

  BsanFuncAllocStack =
      M.getOrInsertFunction(kBsanFuncAllocStack, AL, IRB.getVoidTy(), PtrTy,
                            IntptrTy, IntptrTy, IntptrTy, PtrTy);

  BsanFuncDealloc =
      M.getOrInsertFunction(kBsanFuncDeallocName, AL, IRB.getVoidTy(), PtrTy,
                            IntptrTy, IntptrTy, PtrTy, Int8Ty);

  BsanFuncDeallocWeak =
      M.getOrInsertFunction(kBsanFuncDeallocWeakName, AL, IRB.getVoidTy(),
                            PtrTy, IntptrTy, IntptrTy, PtrTy);

  BsanFuncExposeTag = M.getOrInsertFunction(
      kBsanFuncExposeTagName, AL, IRB.getVoidTy(), IntptrTy, IntptrTy, PtrTy);

  BsanFuncRead =
      M.getOrInsertFunction(kBsanFuncReadName, AL, IRB.getVoidTy(), PtrTy,
                            IntptrTy, IntptrTy, IntptrTy, PtrTy);

  BsanFuncWrite =
      M.getOrInsertFunction(kBsanFuncWriteName, AL, IRB.getVoidTy(), PtrTy,
                            IntptrTy, IntptrTy, IntptrTy, PtrTy);

  BsanFuncShadowLoadVector =
      M.getOrInsertFunction(kBsanFuncShadowLoadVectorName, AL, IRB.getVoidTy(),
                            PtrTy, IntptrTy, PtrTy, PtrTy, PtrTy);

  BsanFuncShadowStoreVector =
      M.getOrInsertFunction(kBsanFuncShadowStoreVectorName, AL, IRB.getVoidTy(),
                            PtrTy, IntptrTy, PtrTy, PtrTy, PtrTy);

  BsanFuncAssertProvenanceNull =
      M.getOrInsertFunction(kBsanFuncAssertProvenanceNull, AL, IRB.getVoidTy(),
                            IntptrTy, IntptrTy, PtrTy);

  BsanFuncAssertProvenanceWildcard =
      M.getOrInsertFunction(kBsanFuncAssertProvenanceWildcard, AL,
                            IRB.getVoidTy(), IntptrTy, IntptrTy, PtrTy);

  BsanFuncAssertProvenanceValid =
      M.getOrInsertFunction(kBsanFuncAssertProvenanceValid, AL, IRB.getVoidTy(),
                            IntptrTy, IntptrTy, PtrTy);

  BsanFuncAssertProvenanceInvalid =
      M.getOrInsertFunction(kBsanFuncAssertProvenanceInvalid, AL,
                            IRB.getVoidTy(), IntptrTy, IntptrTy, PtrTy);

  BsanFuncDebugPrint = M.getOrInsertFunction(
      kBsanFuncDebugPrint, AL, IRB.getVoidTy(), IntptrTy, IntptrTy, PtrTy);

  BsanFuncDebugParamTLS = M.getOrInsertFunction(kBsanFuncDebugParamTLS, AL,
                                                IRB.getVoidTy(), IntptrTy);

  BsanFuncDebugRetvalTLS = M.getOrInsertFunction(kBsanFuncDebugRetvalTLS, AL,
                                                 IRB.getVoidTy(), IntptrTy);

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
                                   ArrayType::get(ProvenanceTy, kTLSSize));
  ParamTLS = getOrInsertTLSGlobal(M, kBsanParamTLSName,
                                  ArrayType::get(ProvenanceTy, kTLSSize));
  AllocIdCounter = getOrInsertGlobal(M, kBsanAllocIdCounterName, IntptrTy);
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
  return Visitor.run();
}
