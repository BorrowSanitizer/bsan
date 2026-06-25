#include "BorrowSanitizerPass.h"
#include "Retag.h"
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

#define BSAN(name) BSAN_PREFIX name
#define BSAN_STATIC(name) BSAN_STATIC_PREFIX name

using namespace llvm;
using namespace llvm::PatternMatch;

// Provenance is two words: a borrow tag and
// a pointer to an allocation metadata object.
static const unsigned kProvenanceSize = 16;
static const Align kMinProvAlignment = Align(8);

static cl::opt<bool> ClHandleAsmConservative(
    "bsan-asm-conservative",
    cl::desc("Conservatively handle inline assembly by setting all pointer "
             "outputs to wildcard Provenance"),
    cl::Hidden, cl::init(true));

static AtomicOrdering addAcquireOrdering(AtomicOrdering A) {
  switch (A) {
  case AtomicOrdering::NotAtomic:
    return AtomicOrdering::NotAtomic;
  case AtomicOrdering::Unordered:
  case AtomicOrdering::Monotonic:
  case AtomicOrdering::Acquire:
    return AtomicOrdering::Acquire;
  case AtomicOrdering::Release:
  case AtomicOrdering::AcquireRelease:
    return AtomicOrdering::AcquireRelease;
  case AtomicOrdering::SequentiallyConsistent:
    return AtomicOrdering::SequentiallyConsistent;
  }
  llvm_unreachable("Unknown ordering");
}

static AtomicOrdering addReleaseOrdering(AtomicOrdering A) {
  switch (A) {
  case AtomicOrdering::NotAtomic:
    return AtomicOrdering::NotAtomic;
  case AtomicOrdering::Unordered:
  case AtomicOrdering::Monotonic:
  case AtomicOrdering::Release:
    return AtomicOrdering::Release;
  case AtomicOrdering::Acquire:
  case AtomicOrdering::AcquireRelease:
    return AtomicOrdering::AcquireRelease;
  case AtomicOrdering::SequentiallyConsistent:
    return AtomicOrdering::SequentiallyConsistent;
  }
  llvm_unreachable("Unknown ordering");
}

static Value *ptradd(IRBuilder<> &IRB, Value *Pointer, Value *Offset) {
  if (match(Offset, m_Zero()))
    return Pointer;
  return IRB.CreateGEP(IRB.getInt8Ty(), Pointer, Offset);
}

static Value *ptrsub(IRBuilder<> &IRB, Value *Pointer, Value *Offset) {
  return ptradd(IRB, Pointer, IRB.CreateNeg(Offset));
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
// Memory map parameters used in application-to-shadow address calculation.
// Offset = (Addr & ~AndMask) ^ XorMask
// Shadow = ShadowBase + Offset
// Origin = OriginBase + Offset
struct MemoryMapParams {
  uint64_t AndMask;
  uint64_t XorMask;
  uint64_t ShadowBase;
  uint64_t OriginBase;
};

} // end anonymous namespace

// x86_64 Linux
static const MemoryMapParams kLinuxX8664MemoryMapParams = {
    0,              // AndMask (not used)
    0x500000000000, // XorMask
    0,              // ShadowBase (not used)
    0x100000000000, // OriginBase
};

// aarch64 Linux
static const MemoryMapParams kLinuxAArch64MemoryMapParams = {
    0,               // AndMask (not used)
    0x0B00000000000, // XorMask
    0,               // ShadowBase (not used)
    0x0200000000000, // OriginBase
};

namespace {
// A component of a type that carries provenance information.
// This is either a pointer or a vector of pointers.
struct ProvenanceDesc {
  // The offset where this field is located.
  Value *ByteOffset;
  // The byte width of this field.
  Value *ByteWidth;
  // The alignment of this field relative to its parent type.
  MaybeAlign FieldAlign;
  // The number of provenance values in this field.
  ElementCount Elems;

public:
  ProvenanceDesc(Value *ByteOffset, Value *ByteWidth, ElementCount Elems,
                 MaybeAlign FieldAlign)
      : ByteOffset(ByteOffset), ByteWidth(ByteWidth), Elems(Elems),
        FieldAlign(FieldAlign) {}

  MaybeAlign alignRelativeTo(Align BaseAlign) {
    if (!FieldAlign)
      return std::nullopt;
    return MaybeAlign(std::min(*FieldAlign, BaseAlign));
  }
};

// Instrument functions of a module to detect violations of Rust's aliasing
// model.
//
// Instantiating BorrowSanitizer inserts the bsan runtime library API function
// declarations into the module if they don't exist already. Instantiating
// ensures the __bsan_init function is in the list of global constructors for
// the module.
struct BorrowSanitizer {
public:
  BorrowSanitizer(Module &M, ModuleAnalysisManager &MAM) {
    C = &(M.getContext());
    DL = &M.getDataLayout();
    TargetTriple = Triple(M.getTargetTriple());

    switch (TargetTriple.getOS()) {
    case Triple::Linux:
      switch (TargetTriple.getArch()) {
      case Triple::x86_64:
        MapParams = &kLinuxX8664MemoryMapParams;
        break;
      case Triple::aarch64:
        MapParams = &kLinuxAArch64MemoryMapParams;
        break;
      default:
        report_fatal_error("unsupported architecture");
      }
      break;
    default:
      report_fatal_error("unsupported operating system");
    }

    PtrTy = PointerType::getUnqual(*C);
    unsigned PtrSize = M.getDataLayout().getPointerSize();
    IntptrTy = Type::getIntNTy(*C, PtrSize * 8);

    ProvenanceTy = StructType::get(IntptrTy, PtrTy);
    ProvenanceSize = ConstantInt::get(IntptrTy, 16);
  }
  bool instrumentModule(Module &M);
  bool instrumentFunction(Function &F, FunctionAnalysisManager &FAM);

private:
  friend struct Provenance;
  friend struct BorrowSanitizerVisitor;

  void initializeCallbacks(Module &M, const TargetLibraryInfo &TLI);
  struct GlobalDescription {
    bool ShouldInstrument;
    std::optional<Function *> AssocFn;
  };
  GlobalDescription getGlobalDescription(GlobalVariable *G) const;
  void instrumentGlobals(IRBuilder<> &IRB, Module &M, bool CtorComdat);
  Function *createBsanModuleDtor(Module &M);
  void createUserspaceApi(Module &M, const TargetLibraryInfo &TLI);

  LLVMContext *C;
  const DataLayout *DL;
  Triple TargetTriple;

  PointerType *PtrTy;
  Type *IntptrTy;
  Align IntptrAlign;

  /// Memory map parameters used in application-to-shadow calculation.
  const MemoryMapParams *MapParams;

  Type *ProvenanceTy = nullptr;
  Value *ProvenanceSize = nullptr;

  /// Thread-local variable containing the number of provenance values
  /// for variable arguments.
  Value *VarArgCounterTLS = nullptr;

  /// Thread-local variable containing the shadow stack pointer.
  Value *ProvStackTLS = nullptr;

  /// Thread local variable containing the boundary marker.
  Value *MarkerTLS = nullptr;

  /// Thread local atomic counter used to generate borrow tags.
  Value *BorTagCounter = nullptr;

  /// Are the instrumentation callbacks set up?
  bool CallbacksInitialized = false;

  /// Runtime function for performing a retag
  FunctionCallee BsanFuncRetag;

  /// Runtime function for exposing a pointer's provenance.
  FunctionCallee BsanFuncExposeProv;

  /// Runtime function for validating a read access
  FunctionCallee BsanFuncRead;

  /// Runtime function for validating a write access
  FunctionCallee BsanFuncWrite;

  /// Runtime function for creating stack-allocation metadata
  FunctionCallee BsanFuncAllocStack;

  /// Runtime function for destroying stack-allocation metadata
  FunctionCallee BsanFuncDeallocStack;

  /// Runtime function for deinitializing local metadata before function exit.
  FunctionCallee BsanFuncPopFrame;

  /// Runtime function for setting the boundary marker.
  FunctionCallee BsanFuncMark;

  /// Runtime function for validating the section of the shadow stack containing
  /// the return value from a function call.
  FunctionCallee BsanFuncValidateRetval;

  /// Runtime function for validating the section of the shadow stack containing
  /// a function's arguments.
  FunctionCallee BsanFuncValidateParams;

  /// Runtime replacement for `memset` that performs read and write checks
  /// and also clears shadow memory.
  FunctionCallee BsanFuncMemSet;

  /// Runtime replacement for `memmove` that performs read and write checks
  /// and also clears shadow memory.
  FunctionCallee BsanFuncMemMove;

  /// Runtime replacement for `memcpy` that performs read and write checks
  /// and also clears shadow memory.
  FunctionCallee BsanFuncMemCpy;

  /// Runtime function for clearing a range within shadow memory.
  FunctionCallee BsanFuncShadowClear;

  /// Runtime function for incrementing the reference count associated
  /// with a provenance value.
  FunctionCallee BsanFuncRcInc;

  /// Runtime function for decrementing the reference count associated
  /// with a provenance value.
  FunctionCallee BsanFuncRcDec;

  /// Runtime function for reserving alloca metadata.
  FunctionCallee BsanFuncReserveStackSlot;

  /// Runtime function for deallocating alloca metadata.
  FunctionCallee BsanFuncDestroyStackSlot;

  /// A default personality function used for exception-handling.
  FunctionCallee DefaultPersonalityFn;

  /// Indicates that the given function is instrumented, or otherwise
  /// handled such that we can trust its return value without boundary
  /// validation.
  bool shouldTrustFunction(const TargetLibraryInfo *TLI, const Value *V);

  /// Indicates if this `alloca` needs to be instrumented.
  bool shouldInstrumentAlloca(const AllocaInst &AI);

  /// Indicates if the given function requires boundary validation.
  bool needsBoundaryValidation(const Function *Callee);

  /// Returns a list of ProvenanceDesc, indicating where provenance values
  /// are located within the given type.
  SmallVector<ProvenanceDesc> getProvenanceDesc(IRBuilder<> &IRB, Type *Ty);

private:
  Value *getProvenanceDesc(IRBuilder<> &IRB,
                           SmallVector<ProvenanceDesc> &ProvDesc,
                           Type *CurrentTy, Value *ByteOffset);
};
} // end anonymous namespace

// Provides a list of the locations of provenance values inside a type.
SmallVector<ProvenanceDesc> BorrowSanitizer::getProvenanceDesc(IRBuilder<> &IRB,
                                                               Type *Ty) {
  SmallVector<ProvenanceDesc> Desc;
  if (Ty->isSized()) {
    Value *Zero = ConstantInt::get(IRB.getIntPtrTy(*DL), 0);
    getProvenanceDesc(IRB, Desc, Ty, Zero);
  }
  return Desc;
}

// Populates a vector with the list of locations of provenance
// values within a type.
Value *BorrowSanitizer::getProvenanceDesc(IRBuilder<> &IRB,
                                          SmallVector<ProvenanceDesc> &ProvDesc,
                                          Type *CurrentTy, Value *ByteOffset) {
  assert(CurrentTy->isSized() && "expected a sized type");
  Type *IntptrTy = IRB.getIntPtrTy(*DL);

  switch (CurrentTy->getTypeID()) {
  case Type::PointerTyID: {
    TypeSize AllocTySize = DL->getTypeAllocSize(CurrentTy);
    Value *AllocSize = IRB.CreateTypeSize(IntptrTy, AllocTySize);
    // The alignment of this field relative to its offset within the parent
    // This is intentionally left as a nullopt for scalable types.
    MaybeAlign FieldAlign = std::nullopt;
    if (auto *CI = dyn_cast<ConstantInt>(ByteOffset))
      FieldAlign =
          commonAlignment(DL->getABITypeAlign(CurrentTy), CI->getZExtValue());
    ProvenanceDesc Desc(ByteOffset, AllocSize, ElementCount::get(1, false),
                        FieldAlign);
    ProvDesc.push_back(Desc);
    return ConstantInt::get(IntptrTy, 1);
  } break;
  case Type::StructTyID: {
    StructType *ST = cast<StructType>(CurrentTy);
    const StructLayout *SL = DL->getStructLayout(ST);
    Value *CurrProvOffset = ConstantInt::get(IntptrTy, 0);
    for (auto [Idx, ElemTy] : llvm::enumerate(ST->elements())) {
      Value *ElemOffset =
          IRB.CreateTypeSize(IntptrTy, SL->getElementOffset(Idx));
      Value *CurrByteOffset = IRB.CreateAdd(ByteOffset, ElemOffset);
      auto *ProvOffset =
          getProvenanceDesc(IRB, ProvDesc, ElemTy, CurrByteOffset);
      CurrProvOffset = IRB.CreateAdd(CurrProvOffset, ProvOffset);
    }
    return CurrProvOffset;
  } break;
  case Type::ArrayTyID: {
    ArrayType *AT = cast<ArrayType>(CurrentTy);
    Value *CurrProvOffset = ConstantInt::get(IntptrTy, 0);
    TypeSize ElemTySize = DL->getTypeAllocSize(AT->getElementType());
    Value *ElemSize = IRB.CreateTypeSize(IntptrTy, ElemTySize);
    for (unsigned Idx = 0; Idx < AT->getNumElements(); ++Idx) {
      Value *CurrByteOffset =
          IRB.CreateMul(ConstantInt::get(IntptrTy, Idx), ElemSize);
      CurrByteOffset = IRB.CreateAdd(ByteOffset, CurrByteOffset);
      auto *ProvOffset = getProvenanceDesc(IRB, ProvDesc, AT->getElementType(),
                                           CurrByteOffset);
      CurrProvOffset = IRB.CreateAdd(CurrProvOffset, ProvOffset);
    }
    return CurrProvOffset;
  } break;
  default: {
    return ConstantInt::get(IntptrTy, 0);
  } break;
  }
}

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

// We only instrument allocations that have a non-zero size.
bool BorrowSanitizer::shouldInstrumentAlloca(const AllocaInst &AI) {
  // Although Rust emits retags for ZSTs, tracking
  // allocations leads to false positive errors—probably
  // due to interactions with lowering.
  Type *AllocType = AI.getAllocatedType();
  std::optional<TypeSize> AllocSize = AI.getAllocationSize(*DL);
  return (AllocType->isSized() && AllocSize.has_value() &&
          !AllocSize.value().isZero());
}

Function *BorrowSanitizer::createBsanModuleDtor(Module &M) {
  Function *Dtor;
  IRBuilder<> IRB(M.getContext());

  Dtor = Function::createWithDefaultAttr(
      FunctionType::get(IRB.getVoidTy(), false), GlobalValue::InternalLinkage,
      0, "bsan.module_dtor", &M);
  Dtor->addFnAttr(Attribute::NoUnwind);

  BasicBlock *BsanDtorBB = BasicBlock::Create(*C, "", Dtor);
  ReturnInst *BsanDtorRet = ReturnInst::Create(*C, BsanDtorBB);

  auto *FnTy = FunctionType::get(IRB.getVoidTy(), false);
  FunctionCallee DeinitFn = M.getOrInsertFunction(BSAN("deinit"), FnTy);

  IRB.SetInsertPoint(BsanDtorRet);
  CallInst *DeinitCall = IRB.CreateCall(DeinitFn, {});

  appendToUsed(M, {Dtor});
  return Dtor;
}

bool BorrowSanitizer::instrumentModule(Module &M) {
  Function *BsanCtorFunction, *BsanDtorFunction;
  // TODO: add version check.
  std::tie(BsanCtorFunction, std::ignore) = createSanitizerCtorAndInitFunctions(
      M, "bsan.module_ctor", BSAN("init"), /*InitArgTypes=*/{},
      /*InitArgs=*/{}, "");

  bool CtorComdat = false;
  BsanDtorFunction = createBsanModuleDtor(M);

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

  BsanFuncRetag = M.getOrInsertFunction(
      BSAN("retag"), AL, IRB.getVoidTy(), PtrTy, IntptrTy, Int8Ty, PtrTy,
      IntptrTy, PtrTy, IntptrTy, IntptrTy, PtrTy, PtrTy);

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

  BsanFuncRcInc = M.getOrInsertFunction(BSAN("rc_inc"), AL, IRB.getVoidTy(),
                                        IntptrTy, PtrTy);

  BsanFuncRcDec = M.getOrInsertFunction(BSAN("rc_dec"), AL, IRB.getVoidTy(),
                                        IntptrTy, PtrTy);

  BsanFuncMemCpy = M.getOrInsertFunction(BSAN("memcpy"), AL, IRB.getVoidTy(),
                                         PtrTy, PtrTy, IntptrTy);

  BsanFuncMemMove = M.getOrInsertFunction(BSAN("memmove"), AL, IRB.getVoidTy(),
                                          PtrTy, PtrTy, IntptrTy);

  BsanFuncMemSet = M.getOrInsertFunction(BSAN("memset"), AL, IRB.getVoidTy(),
                                         PtrTy, Int32Ty, IntptrTy);

  BsanFuncShadowClear = M.getOrInsertFunction(BSAN("shadow_clear"), AL,
                                              IRB.getVoidTy(), PtrTy, IntptrTy);

  BsanFuncReserveStackSlot =
      M.getOrInsertFunction(BSAN("reserve_stack_slot"),
                            FunctionType::get(PtrTy, /*isVarArg=*/false), AL);

  BsanFuncDestroyStackSlot = M.getOrInsertFunction(BSAN("destroy_stack_slot"),
                                                   AL, IRB.getVoidTy(), PtrTy);

  BsanFuncExposeProv = M.getOrInsertFunction(BSAN("expose_prov"), AL,
                                             IRB.getVoidTy(), IntptrTy, PtrTy);

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
  MarkerTLS = getOrInsertTLSGlobal(M, BSAN("marker"), PtrTy);
  VarArgCounterTLS = getOrInsertTLSGlobal(M, BSAN("var_arg_ctr"), IntptrTy);
  ProvStackTLS = getOrInsertTLSGlobal(M, BSAN("shadow_stack"), PtrTy);
  BorTagCounter = getOrInsertGlobal(M, BSAN("bor_tag_ctr"), IntptrTy);
}

namespace {

// A pointer's provenance value.
//
// Each pointer has provenance, indicating its permission to access
// a memory location.
class Provenance {
public:
  Value *Tag = nullptr;
  Value *Info = nullptr;
  ElementCount Elems = ElementCount::getFixed(1);
  Provenance() {}
  Provenance(Value *Tag, Value *Info) : Tag(Tag), Info(Info) {}
  Provenance(Value *Tag, Value *Info, ElementCount Elems)
      : Tag(Tag), Info(Info), Elems(Elems) {}
  bool operator==(const Provenance &Other) const {
    return this->Tag == Other.Tag && this->Info == Other.Info &&
           this->Elems == Other.Elems;
  }
  bool operator!=(const Provenance &Other) const { return !(*this == Other); }

  void addIncoming(BasicBlock *IncomingBlock, Provenance &IncomingProv);
  static Provenance omnivalid(BorrowSanitizer &BS,
                              ElementCount Elems = ElementCount::getFixed(1));
  static Provenance wildcard(BorrowSanitizer &BS,
                             ElementCount Elems = ElementCount::getFixed(1));
};

struct ProvenanceKey {
  Value *V;
  unsigned long Offset;
  ProvenanceKey(Value *V) : V(V), Offset(0) {}
  ProvenanceKey(Value *V, unsigned long Offset) : V(V), Offset(Offset) {}
};

struct ProvenanceMap {
  DenseMap<Value *, SmallDenseMap<unsigned, Provenance>> Inner;

public:
  Provenance *find(ProvenanceKey Key) {
    auto InnerIt = Inner.find(Key.V);
    if (InnerIt == Inner.end())
      return nullptr;

    auto &SubMap = InnerIt->second;
    auto SubIt = SubMap.find(Key.Offset);
    if (SubIt == SubMap.end())
      return nullptr;

    return &SubIt->second;
  }

  void transfer(Value *Src, Value *Dest) {
    auto It = Inner.find(Src);
    if (It != Inner.end()) {
      SmallDenseMap<unsigned, Provenance> *DestMap = &Inner[Dest];
      for (const auto &[Idx, Prov] : It->second) {
        (*DestMap)[Idx] = Prov;
      }
    }
  }

  void set(ProvenanceKey Key, Provenance Prov) {
    Inner[Key.V][Key.Offset] = Prov;
  }

  std::optional<Provenance> get(ProvenanceKey Key) {
    if (Provenance *Prov = this->find(Key)) {
      return *Prov;
    }
    return std::nullopt;
  }
};

} // end anonymous namespace

void Provenance::addIncoming(BasicBlock *IncomingBlock,
                             Provenance &IncomingProv) {
  assert(isa<PHINode>(this->Tag));
  PHINode *TagNode = cast<PHINode>(this->Tag);

  assert(isa<PHINode>(this->Info));
  PHINode *InfoNode = cast<PHINode>(this->Info);

  TagNode->setIncomingValueForBlock(IncomingBlock, IncomingProv.Tag);
  InfoNode->setIncomingValueForBlock(IncomingBlock, IncomingProv.Info);
}

Provenance Provenance::omnivalid(BorrowSanitizer &BS, ElementCount Elems) {
  if (Elems.isScalar()) {
    Value *Zero = ConstantInt::get(BS.IntptrTy, 0);
    Value *InvalidPtr = ConstantPointerNull::get(BS.PtrTy);
    return Provenance(Zero, InvalidPtr, Elems);
  }
  report_fatal_error("Vector provenance is not supported yet");
}

Provenance Provenance::wildcard(BorrowSanitizer &BS, ElementCount Elems) {
  if (Elems.isScalar()) {
    Value *Two = ConstantInt::get(BS.IntptrTy, 2);
    Value *InvalidPtr = ConstantPointerNull::get(BS.PtrTy);
    return Provenance(Two, InvalidPtr, Elems);
  }
  report_fatal_error("Vector provenance is not supported yet");
}

PreservedAnalyses BorrowSanitizerPass::run(Module &M,
                                           ModuleAnalysisManager &MAM) {
  if (checkIfAlreadyInstrumented(M, "nosanitize_borrow"))
    return PreservedAnalyses::all();

  BorrowSanitizer ModuleSanitizer(M, MAM);

  bool Modified = false;

  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();

  for (Function &F : M) {
    Modified |= ModuleSanitizer.instrumentFunction(F, FAM);
  }
  if (!Modified)
    return PreservedAnalyses::all();

  Modified |= ModuleSanitizer.instrumentModule(M);

  PreservedAnalyses PA = PreservedAnalyses::none();
  // We incrementally update the dominator tree throughout
  // these analysis passes.
  PA.preserve<DominatorTreeAnalysis>();
  // GlobalsAA is considered stateless and does not get invalidated unless
  // explicitly invalidated; PreservedAnalyses::none() is not enough. Sanitizers
  // make changes that require GlobalsAA to be invalidated.
  PA.abandon<GlobalsAA>();
  return PA;
}

namespace {
// BorrowSanitizer uses a shadow stack to track the provenance values
// that are accessible in memory and to pass provenance between functions.
// We need the stack to be a contiguous array of provenance values to make it
// easy to scan and avoid consuming excess memory. Note: we use a combination of
// allocas and mem2reg to efficiently track stack offsets. This greatly
// simplifies the implementation but the same can be accomplished using only phi
// nodes. The result is equivalent either way.
class ShadowStackAllocator {
  // The size of a slot within the shadow stack.
  Value *SlotSize;
  // A pointer to where the frame pointer is stored.
  Value *FramePtrSrc;
  // The top of the frame header.
  Value *FrameHeaderTop = nullptr;
  // The bottom of the frame header (after params, byval args,
  // and static allocas, but before function-entry retags.)
  Value *FrameHeaderBottom = nullptr;

public:
  ShadowStackAllocator(Value *SlotSize, Value *FramePtrSrc)
      : SlotSize(SlotSize), FramePtrSrc(FramePtrSrc) {}

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

  // Allocates the requested number of slots and returns the slot count offset.
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

public:
  void initFrameHeader(IRBuilder<> &IRB, Value *NumParamProv) {
    BasicBlock *EntryBlock =
        &IRB.GetInsertBlock()->getParent()->getEntryBlock();
    IRBuilder<> EntryIRB(EntryBlock, EntryBlock->getFirstNonPHIIt());
    FrameHeaderTop = EntryIRB.CreateLoad(EntryIRB.getPtrTy(), FramePtrSrc);
    Value *ByteOffset = EntryIRB.CreateMul(NumParamProv, SlotSize);
    FrameHeaderBottom = ptrsub(EntryIRB, FrameHeaderTop, ByteOffset);
  }

  std::optional<Value *> getFrameHeaderTop() {
    if (FrameHeaderTop) {
      return FrameHeaderTop;
    }
    return std::nullopt;
  }

  Value *getOrInitFrameHeaderTop(IRBuilder<> &IRB) {
    if (!FrameHeaderTop) {
      initFrameHeader(IRB, ConstantInt::get(SlotSize->getType(), 0));
    }
    return FrameHeaderTop;
  }

  std::optional<Value *> getFrameHeaderBottom() {
    if (FrameHeaderBottom) {
      return FrameHeaderBottom;
    }
    return std::nullopt;
  }

  Value *getOrInitFrameHeaderBottom(IRBuilder<> &IRB) {
    if (!FrameHeaderBottom) {
      initFrameHeader(IRB, ConstantInt::get(SlotSize->getType(), 0));
    }
    return FrameHeaderBottom;
  }

  // Extends the frame header down by one provenance slot. This will be called
  // to allocate space in the header for the metadata of every byval arg and
  // static alloca. However, once the header has been initialized, it should
  // never be expanded again.
  Value *pushFrameHeaderSlot(IRBuilder<> &IRB) {
    FrameHeaderBottom = ptrsub(IRB, getOrInitFrameHeaderBottom(IRB), SlotSize);
    return FrameHeaderBottom;
  }

  // Allocates one or more shadow stack slots.
  Value *allocStackSlot(DominatorTree &DT, LoopInfo &LI, IRBuilder<> &IRB,
                        bool IsFnEntry,
                        ElementCount Elems = ElementCount::getFixed(1)) {
    Value *SlotOffset =
        alloc(DT, LI, IRB, Elems, SlotSize->getType(), IsFnEntry);
    Value *ProvOffset = IRB.CreateMul(SlotOffset, SlotSize);
    Value *FramePtr = ptrsub(IRB, getOrInitFrameHeaderBottom(IRB), ProvOffset);
    // We need to update the bottom of the frame every time we allocate a slot,
    // because arbitrary instructions can be lowered into calls to instrumented
    // compiler-rt runtimes (e.g. __multi3, __udivti3, __floatuntidf) that will
    // use the shadow stack.
    IRB.CreateStore(FramePtr, FramePtrSrc);
    return FramePtr;
  }

  // Returns a pointer to the bottom of the specified section of the
  // shadow frame.
  Value *getStackPtr(DominatorTree &DT, LoopInfo &LI, IRBuilder<> &IRB,
                     bool IsFnEntry) {
    Value *CurrOffset =
        getOutgoingOffset(DT, LI, IRB, SlotSize->getType(), IsFnEntry);
    Value *ProvOffset = IRB.CreateMul(CurrOffset, SlotSize);
    return ptrsub(IRB, getOrInitFrameHeaderBottom(IRB), ProvOffset);
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
} // end anonymous namespace

namespace {
/// Helper class to attach debug information of the given instruction onto new
/// instructions inserted after.
class NextNodeIRBuilder : public IRBuilder<> {
public:
  explicit NextNodeIRBuilder(Instruction *IP) : IRBuilder<>(IP->getNextNode()) {
    SetCurrentDebugLocation(IP->getDebugLoc());
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

  // The static allocations that we will instrument.
  SmallVector<AllocaInst *, 8> StaticAllocaVec;

  // The static allocations that have a `lifetime.start` intrinsic.
  SmallDenseSet<AllocaInst *> HasLifetimeStart;

  // A map from Arguments to (byte offset, provenance count) pairs, indicating
  // the offset from the top of the header where the argument's provenane is
  // stored, and how many provenance values are stored there.
  SmallDenseMap<Argument *, SmallVector<std::pair<Value *, ElementCount>>>
      ArgumentProvenance;

  // A map from values to their provenance.
  ProvenanceMap BaseProvMap;

  // A vector containing every byval argument. When we exit the function,
  // we need to deallocate the metadata associated with every byval argument.
  SmallVector<Value *, 2> ByValArgs;

  // A vector containing yet-to-be resolved provenance values for PHI nodes.
  // The first element in the pair, the provenance "key", consists of a
  // pointer to the PHINode and the index into its provenance.
  SmallVector<std::pair<ProvenanceKey, Provenance>> ProvPHINodes;

  // A vector containing every retag intrinsic invocation. Since these are
  // "dummy" function calls, they need to be erased before the pass has
  // finished.
  SmallVector<CallBase *> Retags;

  // The number of function-entry retags that occurred.
  unsigned NumFnEntryRetags = 0;

  ShadowStackAllocator ShadowStack;
  Value *FrameVariadicTop = nullptr;

  // An allocation used to store the boundary marker for
  // invoke instructions involving uninstrumented functions.
  AllocaInst *MarkerAlloca = nullptr;

public:
  BorrowSanitizerVisitor(Function &F, BorrowSanitizer &BS,
                         const TargetLibraryInfo &TLI, DominatorTree &DT)
      : F(F), BS(BS), C(BS.C), TLI(&TLI), DT(DT),
        ShadowStack(BS.ProvenanceSize, BS.ProvStackTLS) {}
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
          auto &AI = static_cast<AllocaInst &>(I);
          if (BS.shouldInstrumentAlloca(AI) && AI.isStaticAlloca())
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
            if (AI && BS.shouldInstrumentAlloca(*AI)) {
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
  Type *ptrToIntPtrType(Type *PtrTy) const {
    if (VectorType *VectTy = dyn_cast<VectorType>(PtrTy)) {
      return VectorType::get(ptrToIntPtrType(VectTy->getElementType()),
                             VectTy->getElementCount());
    }
    assert(PtrTy->isIntOrPtrTy());
    return BS.IntptrTy;
  }

  Type *getPtrToShadowPtrType(Type *IntPtrTy, Type *ShadowTy) const {
    if (VectorType *VectTy = dyn_cast<VectorType>(IntPtrTy)) {
      return VectorType::get(
          getPtrToShadowPtrType(VectTy->getElementType(), ShadowTy),
          VectTy->getElementCount());
    }
    assert(IntPtrTy == BS.IntptrTy);
    return BS.PtrTy;
  }

  Constant *constToIntPtr(Type *IntPtrTy, uint64_t C) const {
    if (VectorType *VectTy = dyn_cast<VectorType>(IntPtrTy)) {
      return ConstantVector::getSplat(
          VectTy->getElementCount(),
          constToIntPtr(VectTy->getElementType(), C));
    }
    assert(IntPtrTy == BS.IntptrTy);
    // TODO: Avoid implicit trunc?
    // See https://github.com/llvm/llvm-project/issues/112510.
    return ConstantInt::get(BS.IntptrTy, C, /*IsSigned=*/false,
                            /*ImplicitTrunc=*/true);
  }

  /// Returns the integer shadow offset that corresponds to a given application
  /// address `Addr`:
  ///
  ///     Offset = (Addr & ~AndMask) ^ XorMask
  ///
  /// getShadowOriginPtr turns this into the shadow and origin pointers by
  /// adding ShadowBase and OriginBase respectively. When `Alignment` cannot be
  /// shown to be at least kMinProvAlignment, the offset is additionally rounded
  /// down to a provenance-slot (kMinProvAlignment) boundary, so sub-slot
  /// addresses map to the slot that holds their provenance.
  Value *getShadowPtrOffset(Value *Addr, IRBuilder<> &IRB,
                            MaybeAlign Alignment) {
    Type *IntptrTy = ptrToIntPtrType(Addr->getType());
    Value *OffsetLong = IRB.CreatePointerCast(Addr, IntptrTy);

    if (uint64_t AndMask = BS.MapParams->AndMask)
      OffsetLong = IRB.CreateAnd(OffsetLong, constToIntPtr(IntptrTy, ~AndMask));

    if (uint64_t XorMask = BS.MapParams->XorMask)
      OffsetLong = IRB.CreateXor(OffsetLong, constToIntPtr(IntptrTy, XorMask));

    if (!Alignment || *Alignment < kMinProvAlignment) {
      uint64_t Mask = kMinProvAlignment.value() - 1;
      OffsetLong = IRB.CreateAnd(OffsetLong, constToIntPtr(IntptrTy, ~Mask));
    }

    return OffsetLong;
  }

  std::pair<Value *, Value *>
  getShadowOriginPtr(IRBuilder<> &IRB, Value *Addr,
                     MaybeAlign Alignment = kMinProvAlignment) {
    VectorType *VectTy = dyn_cast<VectorType>(Addr->getType());
    if (!VectTy) {
      assert(Addr->getType()->isPointerTy());
    } else {
      assert(VectTy->getElementType()->isPointerTy());
    }
    Type *IntptrTy = ptrToIntPtrType(Addr->getType());
    Value *ShadowOffset = getShadowPtrOffset(Addr, IRB, Alignment);
    Value *ShadowLong = ShadowOffset;
    if (uint64_t ShadowBase = BS.MapParams->ShadowBase) {
      ShadowLong =
          IRB.CreateAdd(ShadowLong, constToIntPtr(IntptrTy, ShadowBase));
    }
    Value *ShadowPtr = IRB.CreateIntToPtr(
        ShadowLong, getPtrToShadowPtrType(IntptrTy, BS.IntptrTy));

    Value *OriginLong = ShadowOffset;
    uint64_t OriginBase = BS.MapParams->OriginBase;
    if (OriginBase != 0)
      OriginLong =
          IRB.CreateAdd(OriginLong, constToIntPtr(IntptrTy, OriginBase));
    Value *OriginPtr = IRB.CreateIntToPtr(
        OriginLong, getPtrToShadowPtrType(IntptrTy, BS.PtrTy));

    return std::make_pair(ShadowPtr, OriginPtr);
  }

  Provenance loadProvenanceFromShadow(
      IRBuilder<> &IRB, Value *Base, MaybeAlign Alignment = kMinProvAlignment,
      ElementCount Elems = ElementCount::getFixed(1),
      AtomicOrdering Ordering = AtomicOrdering::NotAtomic) {
    if (Elems.isScalar()) {
      Value *TagPtr, *InfoPtr;
      std::tie(TagPtr, InfoPtr) = getShadowOriginPtr(IRB, Base, Alignment);
      Provenance Prov =
          loadProvenanceAlignedPairwise(IRB, TagPtr, InfoPtr, Ordering);
      Value *Slot = allocStackSlot(IRB, false);
      storeProvenance(IRB, Prov, Slot);
      return Prov;
    }
    report_fatal_error("Vectors are not supported.");
  }

  Provenance loadProvenance(IRBuilder<> &IRB, Value *Src,
                            ElementCount Elems = ElementCount::getFixed(1)) {
    if (Elems.isScalar()) {
      Value *ZeroIdx = ConstantInt::get(IRB.getInt64Ty(), 0);
      Value *TagPtr = Src;
      Value *InfoPtr =
          IRB.CreateGEP(BS.ProvenanceTy, Src,
                        {ZeroIdx, ConstantInt::get(IRB.getInt32Ty(), 1)});
      return loadProvenanceAlignedPairwise(IRB, TagPtr, InfoPtr,
                                           AtomicOrdering::NotAtomic);
    }
    report_fatal_error("Vector provenance is not supported yet");
  }

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
    return Provenance::omnivalid(BS, ElementCount::getFixed(1));
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
    return Provenance::omnivalid(BS, Elems);
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
        Value *ArgProvOffset = ProvVec[Key.Offset].first;
        ElementCount Elems = ProvVec[Key.Offset].second;
        Value *HeaderTop = ShadowStack.getOrInitFrameHeaderTop(EntryIRB);
        Value *ByteOffset =
            EntryIRB.CreateMul(BS.ProvenanceSize, ArgProvOffset);
        Value *ArgProvenancePtr = ptrsub(EntryIRB, HeaderTop, ByteOffset);
        Provenance ArgProvenance =
            loadProvenance(EntryIRB, ArgProvenancePtr, Elems);
        setProvenance(Key, ArgProvenance);
        return ArgProvenance;
      }
    }
    return std::nullopt;
  }

  void setProvenance(ProvenanceKey Key, Provenance Prov) {
    BaseProvMap.set(Key, Prov);
  }

  void storeProvenance(IRBuilder<> &IRB, Provenance Prov, Value *Base,
                       AtomicOrdering Ordering = AtomicOrdering::NotAtomic) {
    if (Prov.Elems.isVector()) {
      report_fatal_error("Vector provenance is not supported yet");
    }
    Value *ZeroIdx = ConstantInt::get(IRB.getInt64Ty(), 0);
    Value *TagPtr = Base;
    Value *InfoPtr =
        IRB.CreateGEP(BS.ProvenanceTy, Base,
                      {ZeroIdx, ConstantInt::get(IRB.getInt32Ty(), 1)});
    storeProvenanceAlignedPairwise(IRB, TagPtr, InfoPtr, Prov, Ordering);
  }

  // Stores a provenance value into shadow memory, starting at the given object
  // address. The alignment provided is used to determine whether the shadow
  // address needs to be manually aligned, or if it is already at the correct
  // alignment.
  void
  storeProvenanceToShadow(IRBuilder<> &IRB, Value *ObjAddr, Provenance Prov,
                          MaybeAlign Alignment = kMinProvAlignment,
                          AtomicOrdering Ordering = AtomicOrdering::NotAtomic) {
    if (Prov.Elems.isVector()) {
      report_fatal_error("Vectors are not supported.");
    } else {
      Value *TagPtr, *InfoPtr;
      std::tie(TagPtr, InfoPtr) = getShadowOriginPtr(IRB, ObjAddr, Alignment);
      storeProvenanceAlignedPairwise(IRB, TagPtr, InfoPtr, Prov, Ordering);
    }
  }

  void updateReferenceCount(IRBuilder<> &IRB, Provenance Dec, Provenance Inc) {
    IRB.CreateCall(BS.BsanFuncRcDec, {Dec.Tag, Dec.Info});
    IRB.CreateCall(BS.BsanFuncRcInc, {Inc.Tag, Inc.Info});
  }

  // Loads a provenance value into shadow memory pairwise at the specified
  // addresses. Each address must be aligned to the wordsize.
  Provenance loadProvenanceAlignedPairwise(IRBuilder<> &IRB, Value *TagPtr,
                                           Value *InfoPtr,
                                           AtomicOrdering Ordering) {
    LoadInst *Tag =
        IRB.CreateAlignedLoad(BS.IntptrTy, TagPtr, kMinProvAlignment);
    Tag->setAtomic(Ordering);
    LoadInst *Info =
        IRB.CreateAlignedLoad(BS.PtrTy, InfoPtr, kMinProvAlignment);
    Info->setAtomic(Ordering);
    return Provenance(Tag, Info);
  }

  void storeProvenanceWithReferenceCount(IRBuilder<> &IRB, Value *TagPtr,
                                         Value *InfoPtr, Provenance Prov,
                                         AtomicOrdering Ordering) {
    Provenance Old =
        loadProvenanceAlignedPairwise(IRB, TagPtr, InfoPtr, Ordering);
    updateReferenceCount(IRB, Old, Prov);
    storeProvenanceAlignedPairwise(IRB, TagPtr, InfoPtr, Prov, Ordering);
  }

  // Stores a provenance value into shadow memory pairwise at the specified
  // addresses. Each address must be aligned to the word size.
  void storeProvenanceAlignedPairwise(IRBuilder<> &IRB, Value *TagPtr,
                                      Value *InfoPtr, Provenance Prov,
                                      AtomicOrdering Ordering) {
    IRB.CreateAlignedStore(Prov.Tag, TagPtr, kMinProvAlignment)
        ->setAtomic(Ordering);
    IRB.CreateAlignedStore(Prov.Info, InfoPtr, kMinProvAlignment)
        ->setAtomic(Ordering);
  }

  // Populates the array of argument provenance pointers and initializes the
  // start and end of the function prologue.
  void initStack(IRBuilder<> &TopIRB) {
    FnPrologueEnd = TopIRB.CreateIntrinsic(Intrinsic::donothing, {});
    IRBuilder<> EntryIRB(FnPrologueEnd);

    Value *NumParamProv = ConstantInt::get(BS.IntptrTy, 0);
    Value *VarArgProvCount = nullptr;
    if (F.isVarArg()) {
      VarArgProvCount = EntryIRB.CreateLoad(BS.IntptrTy, BS.VarArgCounterTLS);
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
        NumParamProv =
            EntryIRB.CreateAdd(NumParamProv, ConstantInt::get(BS.IntptrTy, 1));
      } else {
        SmallVector<ProvenanceDesc> ProvDesc =
            BS.getProvenanceDesc(EntryIRB, Arg.getType());
        for (auto &Desc : ProvDesc) {
          Value *NumProv = EntryIRB.CreateElementCount(BS.IntptrTy, Desc.Elems);
          NumParamProv = EntryIRB.CreateAdd(NumParamProv, NumProv);
          ArgumentProvenance[&Arg].push_back(
              std::make_pair(NumParamProv, Desc.Elems));
        }
      }
    }

    if (!match(NumParamProv, m_Zero()))
      ShadowStack.initFrameHeader(EntryIRB, NumParamProv);

    // We can safely pass a null pointer if there are no arguments to
    // validate; the runtime resets the boundary marker either way.
    Value *ValidateHeaderBottom = ConstantPointerNull::get(BS.PtrTy);

    if (F.isVarArg()) {
      Value *VarArgByteOffset =
          EntryIRB.CreateMul(VarArgProvCount, BS.ProvenanceSize);
      FrameVariadicTop = ShadowStack.getOrInitFrameHeaderBottom(EntryIRB);
      ValidateHeaderBottom = ptradd(EntryIRB, FrameVariadicTop,
                                    EntryIRB.CreateNeg(VarArgByteOffset));
      EntryIRB.CreateStore(ConstantInt::get(BS.IntptrTy, 0),
                           BS.VarArgCounterTLS);
    } else if (!match(NumParamProv, m_Zero())) {
      ValidateHeaderBottom = ShadowStack.getOrInitFrameHeaderBottom(EntryIRB);
    }

    if (BS.needsBoundaryValidation(&F)) {
      if (!BS.shouldTrustFunction(TLI, &F)) {
        EntryIRB.CreateCall(BS.BsanFuncValidateParams,
                            {&F, ValidateHeaderBottom, NumParamProv});
      }
    }

    for (auto &Arg : ByValArgs) {
      BasicBlock *BB = EntryIRB.GetInsertBlock();
      Provenance Prov = assertProvenanceScalar(BB, Arg);
      Value *Slot = ShadowStack.pushFrameHeaderSlot(EntryIRB);
      storeProvenance(EntryIRB, Prov, Slot);
    }

    for (auto [Idx, AI] : llvm::enumerate(StaticAllocaVec)) {
      Provenance Prov = createAllocaMetadata(EntryIRB, AI);
      if (!HasLifetimeStart.contains(AI)) {
        NextNodeIRBuilder IRB(AI);
        initAllocaMetadata(IRB, AI, Prov);
      }
      setProvenance(AI, Prov);
      Value *Slot = ShadowStack.pushFrameHeaderSlot(EntryIRB);
      storeProvenance(EntryIRB, Prov, Slot);
    }

    // We have initialized the frame header, but we have not updated the frame
    // pointer to reflect it. We need to do this eagerly, because we cannot
    // reliably determine when an instruction will compile into a call to an
    // instrumented libcall.
    if (std::optional<Value *> FHB = ShadowStack.getFrameHeaderBottom()) {
      EntryIRB.CreateStore(*FHB, BS.ProvStackTLS);
    }
  }

  void patchShadowPHINodes() {
    IRBuilder<> EntryIRB(FnPrologueEnd);
    for (auto &[Key, Prov] : ProvPHINodes) {
      auto *PN = static_cast<PHINode *>(Key.V);
      for (auto [V, IncomingBlock] :
           llvm::zip(PN->incoming_values(), PN->blocks())) {
        Provenance IncomingProv = assertProvenance(EntryIRB, IncomingBlock,
                                                   Prov.Elems, {V, Key.Offset});
        Prov.addIncoming(IncomingBlock, IncomingProv);
      }
    }
  }

  Value *newBorrowTag(IRBuilder<> &IRB) {
    return IRB.CreateAtomicRMW(AtomicRMWInst::Add, BS.BorTagCounter,
                               ConstantInt::get(BS.IntptrTy, 1), std::nullopt,
                               AtomicOrdering::Monotonic);
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
    return ConstantInt::get(BS.IntptrTy, 0);
  }

  void instrumentRetagMem(CallBase &CB) {
    IRBuilder<> IRB(&CB);
    Value *Operand = CB.getOperand(0);
    Value *SrcAddr = IRB.CreateLoad(BS.PtrTy, Operand);
    Provenance SrcProv = loadProvenanceFromShadow(IRB, Operand);

    RetagInfo RI(&CB);
    Value *ImArrayLen = getLayoutArrayLength(RI.ImArray);
    Value *PinArrayLen = getLayoutArrayLength(RI.PinArray);
    Value *Slot = allocStackSlot(IRB, RI.isProtected());
    IRB.CreateCall(BS.BsanFuncRetag,
                   {SrcAddr, RI.Size, RI.Perms, RI.ImArray, ImArrayLen,
                    RI.PinArray, PinArrayLen, SrcProv.Tag, SrcProv.Info, Slot});
    Provenance RetaggedProv = loadProvenance(IRB, Slot);
    storeProvenanceToShadow(IRB, Operand, RetaggedProv);
  }

  void instrumentRetagReg(CallBase &CB) {
    IRBuilder<> IRB(&CB);
    Value *Ptr = CB.getOperand(0);
    if (auto Prov = getProvenance(CB.getParent(), Ptr)) {
      RetagInfo RI(&CB);
      Value *ImArrayLen = getLayoutArrayLength(RI.ImArray);
      Value *PinArrayLen = getLayoutArrayLength(RI.PinArray);
      Value *Dest = allocStackSlot(IRB, RI.isProtected());
      IRB.CreateCall(BS.BsanFuncRetag,
                     {Ptr, RI.Size, RI.Perms, RI.ImArray, ImArrayLen,
                      RI.PinArray, PinArrayLen, Prov->Tag, Prov->Info, Dest});
      setProvenance(&CB, loadProvenance(IRB, Dest));
    }
  }

  Value *allocStackSlot(IRBuilder<> &IRB, bool IsFnEntry,
                        ElementCount Elems = ElementCount::getFixed(1)) {
    return ShadowStack.allocStackSlot(DT, LI, IRB, IsFnEntry, Elems);
  }

  Value *getStackOffset(IRBuilder<> &IRB, bool IsFnEntry) {
    return ShadowStack.getStackPtr(DT, LI, IRB, IsFnEntry);
  }

  using InstVisitor<BorrowSanitizerVisitor>::visit;

  void visitCallBase(CallBase &CB) {
    assert(!CB.getMetadata(LLVMContext::MD_nosanitize));
    assert(!isa<IntrinsicInst>(CB) && "intrinsics are handled elsewhere");

    Function *Callee = CB.getCalledFunction();
    if (Callee) {
      if (IsRetag(&CB)) {
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

    // We need to store the provenance for each argument onto the shadow stack.
    // First, we calculate the offset for each parameter's provenance.
    Value *NumParamProv = ConstantInt::get(BS.IntptrTy, 0);
    Value *VarArgProvCount = ConstantInt::get(BS.IntptrTy, 0);
    bool IsVarArg = CB.getFunctionType()->isVarArg();
    unsigned NumFixedParams = CB.getFunctionType()->getNumParams();

    SmallVector<std::pair<Value *, Provenance>> ParamOffsets;
    for (const auto &[i, Arg] : llvm::enumerate(CB.args())) {
      SmallVector<ProvenanceDesc> ProvDesc =
          BS.getProvenanceDesc(Before, Arg->getType());
      for (const auto &[Idx, Desc] : llvm::enumerate(ProvDesc)) {
        Value *NumProv = Before.CreateElementCount(BS.IntptrTy, Desc.Elems);
        NumParamProv = Before.CreateAdd(NumParamProv, NumProv);

        if (IsVarArg && i >= NumFixedParams) {
          VarArgProvCount = Before.CreateAdd(VarArgProvCount, NumProv);
        }

        Value *ByteOffset = Before.CreateMul(NumParamProv, BS.ProvenanceSize);
        Provenance ProvSrc = assertProvenance(Before, Desc.Elems, {Arg, Idx});
        ParamOffsets.push_back(std::make_pair(ByteOffset, ProvSrc));
      }
    }

    if (CB.isMustTailCall()) {
      // We need to pop the current frame, since
      // the semantics of a tail call are equivalent
      // to a return and then another call.
      popFrame(Before, CB, nullptr);
    }

    if (!ParamOffsets.empty() || ShadowStack.getFrameHeaderTop().has_value()) {
      Value *StackOffset;
      if (CB.isMustTailCall()) {
        // Now that we've popped the frame, we
        // can clobber the current frame header.
        StackOffset = ShadowStack.getOrInitFrameHeaderTop(Before);
      } else {
        // Always update ProvStack before any non-musttail call so the callee
        // loads a valid frame top, even when there are no pointer args.
        StackOffset = getStackOffset(Before, false);
      }

      for (auto [ByteOffset, Prov] : ParamOffsets) {
        Value *Slot = ptrsub(Before, StackOffset, ByteOffset);
        storeProvenance(Before, Prov, Slot);
      }

      Before.CreateStore(StackOffset, BS.ProvStackTLS);
    }

    if (IsVarArg) {
      Before.CreateStore(VarArgProvCount, BS.VarArgCounterTLS);
    }

    // Skip the epilogue for musttail calls, since
    // they need to be adjacent to a ret.
    if (CB.isMustTailCall()) {
      return;
    }

    // We need to do some extra work here to compute where
    // to insert the epilogue, since some function calls are
    // terminators, and have multiple outgoing edges.
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

    Value *NumReturnProv = ConstantInt::get(BS.IntptrTy, 0);
    SmallVector<Value *> ReturnProvPtrs;

    SmallVector<ProvenanceDesc> ReturnDesc =
        BS.getProvenanceDesc(Before, CB.getType());

    if (CB.getType()->isSized()) {
      // Unsized return types do not have provenance, so we can
      // skip handling the return array.

      // Load each provenance component for the return type from the
      // thread-local return value array. Also, compute the byte-width of the
      // provenance components that we expect to be here. If the function that
      // we are calling is uninstrumented, then we need ensure that the return
      // array is populated with default values.
      for (const auto &[Idx, Desc] : llvm::enumerate(ReturnDesc)) {
        Value *Slot = allocStackSlot(After, false, Desc.Elems);
        ReturnProvPtrs.push_back(Slot);
        Value *NumProv = After.CreateElementCount(BS.IntptrTy, Desc.Elems);
        NumReturnProv = After.CreateAdd(NumReturnProv, NumProv);
      }
    }

    // If we are returning from a possibly-uninstrumented function, then we may
    // need to validate the space on the shadow stack where the return value's
    // provenance is stored.
    if (BS.needsBoundaryValidation(Callee)) {
      Value *Marker;
      Value *NullPtr = ConstantPointerNull::get(BS.PtrTy);
      // If this is a function that we can trust (e.g. an allocator)
      // then we write null into the boundary marker and trust the content
      // of the shadow stack.
      if (BS.shouldTrustFunction(TLI, &CB)) {
        Marker = Before.CreateCall(BS.BsanFuncMark, {NullPtr});
        After.CreateStore(Marker, BS.MarkerTLS);
      } else {
        // Otherwise, we need to initialize the marker with the function
        // pointer that we're calling with, so that the callee can check
        // against it.
        Marker = Before.CreateCall(BS.BsanFuncMark, {CB.getCalledOperand()});
        // If we do not have any return provenance, then
        // we do not need to validate any part of the shadow stack
        // on return.
        if (!match(NumReturnProv, m_Zero())) {
          Value *Slot = getStackOffset(After, false);
          After.CreateCall(BS.BsanFuncValidateRetval,
                           {Marker, Slot, NumReturnProv});
        }
      }
      // We always need to restore our boundary
      // marker to the value that it had before.
      After.CreateStore(Marker, BS.MarkerTLS);

      if (auto *II = dyn_cast<InvokeInst>(&CB)) {
        // An invoke may unwind to an additional block, which might
        // not be dominated by the invoke. In that case, we need to
        // store our return value marker at a location that we can
        // guarantee will be accessible in any block.
        if (!MarkerAlloca) {
          // We initialize an alloca for this purpose.
          // It's shared between every invoke that needs
          // boundary validation.
          IRBuilder<> EntryIRB(FnPrologueEnd);
          MarkerAlloca = EntryIRB.CreateAlloca(BS.PtrTy);
          EntryIRB.CreateStore(NullPtr, MarkerAlloca);
        }
        Before.CreateStore(Marker, MarkerAlloca);
        BasicBlock *UnwindDest = II->getUnwindDest();
        IRBuilder<> UnwindIRB(UnwindDest, UnwindDest->getFirstInsertionPt());
        Value *ToRestore = UnwindIRB.CreateLoad(BS.PtrTy, MarkerAlloca);
        UnwindIRB.CreateStore(ToRestore, BS.MarkerTLS);
      }
    }

    // Finally, store the return value's provenance to the shadow stack.
    for (const auto &[Idx, Ptr] : llvm::enumerate(ReturnProvPtrs)) {
      ElementCount Elems = ReturnDesc[Idx].Elems;
      Provenance Prov = loadProvenance(After, Ptr, Elems);
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
          BS.getProvenanceDesc(IRB, Operand->getType());
      for (const auto &[Idx, Comp] : llvm::enumerate(Components)) {
        setProvenance({Operand, Idx}, Provenance::omnivalid(BS));
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

    Provenance Omni = Provenance::omnivalid(BS);
    for (BasicBlock *BB : Blocks) {
      TagNode->addIncoming(Omni.Tag, BB);
      InfoNode->addIncoming(Omni.Info, BB);
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
        BS.getProvenanceDesc(IRB, PN.getType());
    for (auto [Idx, Comp] : llvm::enumerate(Components)) {
      Provenance Prov =
          createProvenancePHI(IRB, Comp, predecessors(PN.getParent()));
      setProvenance({&PN, Idx}, Prov);
      ProvPHINodes.push_back({{&PN, Idx}, Prov});
    }
  }

  void visitIntrinsicInst(IntrinsicInst &I) {
    switch (I.getIntrinsicID()) {
    case Intrinsic::lifetime_start:
      return instrumentLifetimeStart(I);
    case Intrinsic::lifetime_end:
      return instrumentLifetimeEnd(I);
    default:
      break;
    }
  }

  Provenance createAllocaMetadata(IRBuilder<> &IRB, AllocaInst *AI) {
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
    if (auto *AI = findAllocaForValue(II.getArgOperand(0), true)) {
      if (auto Prov = getProvenance(II.getParent(), AI)) {
        IRBuilder<> IRB(&II);
        IRB.CreateCall(BS.BsanFuncDeallocStack,
                       {AI, (*Prov).Tag, (*Prov).Info});
        initAllocaMetadata(IRB, AI, *Prov);
      }
    }
  }

  void instrumentLifetimeEnd(IntrinsicInst &II) {
    if (auto *AI = findAllocaForValue(II.getArgOperand(0), true)) {
      if (auto Prov = getProvenance(II.getParent(), AI)) {
        IRBuilder<> IRB(&II);
        IRB.CreateCall(BS.BsanFuncDeallocStack,
                       {AI, (*Prov).Tag, (*Prov).Info});
      }
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
        BS.getProvenanceDesc(IRB, LI.getType());

    Value *Base = LI.getPointerOperand();
    for (const auto &[Idx, Comp] : llvm::enumerate(Components)) {
      Value *ByteOffset = Comp.ByteOffset;
      Value *ObjAddr = ptradd(IRB, Base, ByteOffset);
      MaybeAlign Alignment = Comp.alignRelativeTo(LI.getAlign());
      Provenance Prov = loadProvenanceFromShadow(IRB, ObjAddr, Alignment,
                                                 Comp.Elems, LI.getOrdering());
      setProvenance({&LI, Idx}, Prov);
    }
    insertReadCheck(IRB, Ptr, Size);
  }

  bool shouldClearProvenance(IRBuilder<> &IRB, StoreInst &SI) { return true; }

  void visitStoreInst(StoreInst &SI) {
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
        BS.getProvenanceDesc(IRB, Val->getType());

    Value *Offset = ConstantInt::get(BS.IntptrTy, 0);

    SmallVector<std::tuple<Value *, Value *>> SlotsToClear;

    for (const auto &[Idx, Desc] : llvm::enumerate(ProvDesc)) {
      Value *ByteOffset = Desc.ByteOffset;
      if (Clear) {
        if (Offset != Desc.ByteOffset) {
          Value *GapSize = IRB.CreateSub(ByteOffset, Offset);
          SlotsToClear.push_back(std::make_tuple(Offset, GapSize));
        }
        Offset = IRB.CreateAdd(Desc.ByteOffset, Desc.ByteWidth);
      }
      Value *ObjAddr = ptradd(IRB, Base, ByteOffset);
      MaybeAlign Alignment = Desc.alignRelativeTo(SI.getAlign());
      Provenance Prov =
          assertProvenance(IRB, Desc.Elems, {SI.getValueOperand(), Idx});
      storeProvenanceToShadow(IRB, ObjAddr, Prov, Alignment, SI.getOrdering());
    }

    if (Clear) {
      Value *GapSize = IRB.CreateSub(EntireSize, Offset);
      SlotsToClear.push_back(std::make_tuple(Offset, GapSize));
    }

    for (auto &[Offset, GapSize] : SlotsToClear) {
      Value *BaseAddr = ptradd(IRB, Base, Offset);
      MaybeAlign GapAlign = std::nullopt;
      if (auto *CI = dyn_cast<ConstantInt>(Offset))
        GapAlign = commonAlignment(SI.getAlign(), CI->getZExtValue());
      clearProvenance(IRB, BaseAddr, GapSize, GapAlign, SI.getOrdering());
    }
  }

  // Clears the provenance of the application range.
  void clearProvenance(IRBuilder<> &IRB, Value *Base, Value *Size,
                       MaybeAlign Alignment, AtomicOrdering Ordering) {
    ConstantInt *CI = dyn_cast<ConstantInt>(Size);
    if (!CI)
      report_fatal_error("Scalable vectors are not supported!");

    uint64_t Bytes = CI->getZExtValue();
    if (Bytes == 0)
      return;

    const uint64_t SlotSize = kMinProvAlignment.value();
    uint64_t AlignedBytes = alignTo(Bytes, SlotSize);

    Value *TagPtr, *InfoPtr;
    std::tie(TagPtr, InfoPtr) = getShadowOriginPtr(IRB, Base, Alignment);

    const uint64_t MaxInlineSlots = 8;
    uint64_t NumSlots = AlignedBytes / SlotSize;

    if (NumSlots <= MaxInlineSlots) {
      for (uint64_t I = 0; I < NumSlots; ++I) {
        Value *Idx = ConstantInt::get(BS.IntptrTy, I * SlotSize);
        TagPtr = ptradd(IRB, TagPtr, Idx);
        InfoPtr = ptradd(IRB, InfoPtr, Idx);
        storeProvenanceAlignedPairwise(IRB, TagPtr, InfoPtr,
                                       Provenance::omnivalid(BS), Ordering);
      }
    } else {
      IRB.CreateCall(BS.BsanFuncShadowClear, {Base, Size});
    }
  }

  void visitGetElementPtrInst(GetElementPtrInst &I) {
    // Pointer arithmetic does not affect provenance.
    // We can propagage the provenance of the input to the output value.
    if (auto Prov = getProvenance(I.getParent(), I.getPointerOperand())) {
      setProvenance(&I, *Prov);
    }
  }

  void visitPtrToIntInst(PtrToIntInst &I) {
    if (auto Prov = getProvenance(I.getParent(), I.getPointerOperand())) {
      IRBuilder<> IRB(&I);
      IRB.CreateCall(BS.BsanFuncExposeProv, {(*Prov).Tag, (*Prov).Info});
    }
  }

  void visitIntToPtrInst(IntToPtrInst &I) {
    setProvenance(&I, Provenance::wildcard(BS));
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
            BS.getProvenanceDesc(IRB, ElemType);
        Offset += ProvDesc.size();
      }
      return {ST->getElementType(Idx), Offset};
    }

    if (auto *AT = dyn_cast<ArrayType>(Ty)) {
      SmallVector<ProvenanceDesc> ProvDesc =
          BS.getProvenanceDesc(IRB, AT->getElementType());
      return {AT->getElementType(), ProvDesc.size() * Idx};
    }

    report_fatal_error("Cannot index into a non-struct or non-array type.");
  }

  void visitExtractValueInst(ExtractValueInst &EI) {
    IRBuilder<> IRB(&EI);
    Value *AggregateSrc = EI.getAggregateOperand();

    SmallVector<ProvenanceDesc> DestProvDesc =
        BS.getProvenanceDesc(IRB, EI.getType());

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
        BS.getProvenanceDesc(IRB, ToInsert->getType());

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
        BS.getProvenanceDesc(IRB, SI.getType());

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
      Value *NumStackAllocs = ConstantInt::get(
          BS.IntptrTy, StaticAllocaVec.size() + ByValArgs.size());
      Value *NumProtectors =
          ShadowStack.getOutgoingOffset(DT, LI, IRB, BS.IntptrTy, true);
      Value *FrameHeaderBottom = ShadowStack.getOrInitFrameHeaderBottom(IRB);
      Value *Offset = IRB.CreateMul(NumProtectors, BS.ProvenanceSize);
      Value *FrameBottom = ptrsub(IRB, FrameHeaderBottom, Offset);
      IRB.CreateCall(BS.BsanFuncPopFrame,
                     {FrameBottom, NumProtectors, NumStackAllocs});
    }

    if (auto FrameTop = ShadowStack.getFrameHeaderTop()) {
      IRB.CreateStore(FrameTop.value(), BS.ProvStackTLS);
    }

    if (RetVal) {
      SmallVector<ProvenanceDesc> ProvDesc =
          BS.getProvenanceDesc(IRB, RetVal->getType());

      if (!ProvDesc.empty()) {
        Value *NumReturnProv = ConstantInt::get(BS.IntptrTy, 0);
        Value *FrameTop = ShadowStack.getOrInitFrameHeaderTop(IRB);
        for (const auto &[Idx, Desc] : llvm::enumerate(ProvDesc)) {
          Value *NumProv = IRB.CreateElementCount(BS.IntptrTy, Desc.Elems);
          NumReturnProv = IRB.CreateAdd(NumReturnProv, NumProv);

          Value *ByteWidth = IRB.CreateMul(NumReturnProv, BS.ProvenanceSize);
          Value *Slot = ptrsub(IRB, FrameTop, ByteWidth);

          Provenance Prov = assertProvenance(IRB, Desc.Elems, {RetVal, Idx});
          storeProvenance(IRB, Prov, Slot);
        }
      }
    }
  }

  void visitReturnInst(ReturnInst &I) {
    // musttail calls pop the frame prior to the ret
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

} // end anonymous namespace

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
