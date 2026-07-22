#include "BorrowSanitizerPass.h"
#include "Retag.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/Analysis/DomTreeUpdater.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/StackLifetime.h"
#include "llvm/Analysis/StackSafetyAnalysis.h"
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
struct ProvenanceField {
  // The offset where this field is located.
  Value *ByteOffset;
  // The byte width of this field.
  Value *ByteWidth;
  // The alignment of this field relative to its parent type.
  Align FieldAlign;
  // The number of provenance values in this field.
  ElementCount Elems;

public:
  ProvenanceField(Value *ByteOffset, Value *ByteWidth, ElementCount Elems,
                  Align FieldAlign)
      : ByteOffset(ByteOffset), ByteWidth(ByteWidth), Elems(Elems),
        FieldAlign(FieldAlign) {}
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
  bool instrumentFunction(Function &F, FunctionAnalysisManager &FAM,
                          const StackSafetyGlobalInfo &SSGI);

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

  /// Indicates whether the given function is a declaration for another function
  /// outside of this module, which might be using a different ABI-lowering
  /// for the same type.
  bool mayHaveDifferentABI(const Function *Callee);

  /// Computes the size of an `alloca` in bytes.
  Value *getAllocaSizeBytes(IRBuilder<> &IRB, AllocaInst *AI);

  /// Returns a list of the fields within a type that carry provenance. If
  /// `ClearGaps` is set, then we treat all integer values larger than a pointer
  /// as if they carry provenance. This Is necessary to reconcile ABI
  /// differences between Rust and C++. If we have a singleton struct containing
  /// a pointer, then in Rust its field will use i64 (if repr(C)). However,
  /// clang will use `ptr` regardless. This will be resolved once the byte type
  /// is more broadly supported.
  SmallVector<ProvenanceField> getProvenanceDesc(IRBuilder<> &IRB, Type *Ty,
                                                 bool ClearGaps = false);

private:
  Value *getProvenanceDesc(IRBuilder<> &IRB,
                           SmallVector<ProvenanceField> &ProvDesc,
                           Type *CurrentTy, Value *ByteOffset,
                           bool ClearGaps = false);
};
} // end anonymous namespace

// Provides a list of the locations of provenance values inside a type.
SmallVector<ProvenanceField>
BorrowSanitizer::getProvenanceDesc(IRBuilder<> &IRB, Type *Ty, bool ClearGaps) {
  SmallVector<ProvenanceField> Desc;
  if (Ty->isSized()) {
    Value *Zero = ConstantInt::get(IRB.getIntPtrTy(*DL), 0);
    getProvenanceDesc(IRB, Desc, Ty, Zero, ClearGaps);
  }
  return Desc;
}

Value *BorrowSanitizer::getAllocaSizeBytes(IRBuilder<> &IRB, AllocaInst *AI) {
  TypeSize TS = AI->getAllocationSize(*DL).value();
  return IRB.CreateTypeSize(IntptrTy, TS);
}

// Populates a vector with the list of locations of provenance
// values within a type.
Value *BorrowSanitizer::getProvenanceDesc(
    IRBuilder<> &IRB, SmallVector<ProvenanceField> &ProvDesc, Type *CurrentTy,
    Value *ByteOffset, bool ClearGaps) {
  assert(CurrentTy->isSized() && "expected a sized type");
  Type *IntptrTy = IRB.getIntPtrTy(*DL);

  switch (CurrentTy->getTypeID()) {
  case Type::PointerTyID: {
    TypeSize AllocTySize = DL->getTypeAllocSize(CurrentTy);
    Value *AllocSize = IRB.CreateTypeSize(IntptrTy, AllocTySize);
    Align AllocAlign = DL->getABITypeAlign(CurrentTy);
    ProvenanceField Desc(ByteOffset, AllocSize, ElementCount::get(1, false),
                         AllocAlign);
    ProvDesc.push_back(Desc);
    return ConstantInt::get(IntptrTy, 1);
  } break;
  case Type::IntegerTyID: {
    if (!ClearGaps)
      break;
    IntegerType *IT = cast<IntegerType>(CurrentTy);
    unsigned IntBitWidth = IT->getBitWidth();
    unsigned PtrBitWidth = DL->getPointerSizeInBits();
    // If the integer type is as large (or larger) than the
    // word size, then we assume that it could be used in type-punning.
    // We can assume that it's being used in place of the byte type,
    // so we need to do *something* with provenance.
    if (IntBitWidth < PtrBitWidth)
      break;
    // Normally, we could be able to take care of this by clearing
    // provenance on stores, where type-punned pointers end up receiving
    // omnivalid provenance. However, things work a bit differently when we
    // pass provenance between functions. We store the provenance of each field
    // in adjacent slots of the shadow stack. This avoids needing to allocate
    // space for values that we know will never be treated as pointers.
    TypeSize AllocTySize = DL->getTypeAllocSize(CurrentTy);
    Value *AllocSize = IRB.CreateTypeSize(IntptrTy, AllocTySize);
    Align AllocAlign = DL->getABITypeAlign(CurrentTy);
    ProvenanceField Desc(ByteOffset, AllocSize, ElementCount::get(1, false),
                         AllocAlign);
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
          getProvenanceDesc(IRB, ProvDesc, ElemTy, CurrByteOffset, ClearGaps);
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
                                           CurrByteOffset, ClearGaps);
      CurrProvOffset = IRB.CreateAdd(CurrProvOffset, ProvOffset);
    }
    return CurrProvOffset;
  } break;
  default: {
  } break;
  }
  return ConstantInt::get(IntptrTy, 0);
}

bool BorrowSanitizer::needsBoundaryValidation(const Function *Callee) {
  return !Callee ||
         (Callee->isDeclaration() || Callee->hasExternalLinkage() ||
          Callee->hasExternalWeakLinkage() || Callee->hasAddressTaken());
}

bool BorrowSanitizer::mayHaveDifferentABI(const Function *Callee) {
  return !Callee || Callee->isDeclaration();
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

bool BorrowSanitizer::instrumentModule(Module &M) {
  Function *BsanCtorFunction;
  // TODO: add version check.
  std::tie(BsanCtorFunction, std::ignore) = createSanitizerCtorAndInitFunctions(
      M, "bsan.module_ctor", BSAN("init"), /*InitArgTypes=*/{},
      /*InitArgs=*/{}, "");

  bool CtorComdat = false;

  IRBuilder<> IRB(BsanCtorFunction->getEntryBlock().getTerminator());
  instrumentGlobals(IRB, M, CtorComdat);

  assert(BsanCtorFunction);
  const int Priority = 1;

  // Put the constructor and destructor in comdat if both
  // (1) global instrumentation is not TU-specific
  // (2) target is ELF.
  if (CtorComdat && TargetTriple.isOSBinFormatELF()) {
    BsanCtorFunction->setComdat(M.getOrInsertComdat("bsan.module_ctor"));
    appendToGlobalCtors(M, BsanCtorFunction, Priority, BsanCtorFunction);
  } else {
    appendToGlobalCtors(M, BsanCtorFunction, Priority);
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
  Type *BoolTy = Type::getInt1Ty(*C);

  AL = AL.addFnAttribute(*C, Attribute::NoUnwind);

  BsanFuncRetag = M.getOrInsertFunction(
      BSAN("retag"), AL, IRB.getVoidTy(), PtrTy, IntptrTy, Int8Ty, PtrTy,
      IntptrTy, PtrTy, IntptrTy, IntptrTy, PtrTy, PtrTy, BoolTy);

  BsanFuncPopFrame = M.getOrInsertFunction(
      BSAN("pop_frame"), AL, IRB.getVoidTy(), PtrTy, IntptrTy, IntptrTy);

  BsanFuncRead = M.getOrInsertFunction(BSAN("read"), AL, IRB.getVoidTy(), PtrTy,
                                       IntptrTy, IntptrTy, PtrTy, BoolTy);

  BsanFuncWrite =
      M.getOrInsertFunction(BSAN("write"), AL, IRB.getVoidTy(), PtrTy, IntptrTy,
                            IntptrTy, PtrTy, BoolTy);

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
  const StackSafetyGlobalInfo &SSGI =
      MAM.getResult<StackSafetyGlobalAnalysis>(M);

  for (Function &F : M) {
    Modified |= ModuleSanitizer.instrumentFunction(F, FAM, SSGI);
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

class SlotAllocator {
  SlotAllocator(Type *Ty) : Ty(Ty) {}

private:
  friend struct ShadowStackAllocator;

  // The integer type used to track the number of slots.
  Type *Ty = nullptr;
  // We track the total number of stack slots used by this
  // function with a single alloca that gets promoted to a register.
  AllocaInst *GlobalOffsetAlloc = nullptr;
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

  // Allocates the requested number of slots,
  // returning the slot count offset.
  Value *alloc(DominatorTree &DT, LoopInfo &LI, IRBuilder<> &IRB,
               ElementCount EC, Type *Ty, bool IsFnEntry) {
    Value *&Offset = getCurrentOffset(DT, LI, IRB, Ty);
    Value *Elems = IRB.CreateElementCount(Ty, EC);
    Offset = IRB.CreateAdd(Offset, Elems);
    return Offset;
  }

  void patch(DominatorTree &DT) {
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

// BorrowSanitizer uses a shadow stack to track the provenance values
// that are accessible in memory, and to pass provenance between functions.
// The shadow stack has multiple regions, and each has a different purpose.
//
// |-----------------------|  <-- FrameHeaderTop
// | parameter provenance  |
// |_______________________|
// |                       |
// | static/byval allocas  |
// |_______________________|
// |                       |  <-- FnEntryTop
// | function entry retags |
// |_______________________|  <-- FrameHeaderBottom
// |                       |
// | all other slots       |
// |_______________________|
//
// When we enter a function, we load the value of the shadow frame
// pointer from a TLS variable (`__bsan_shadow_stack`). It points immediately
// above the first provenance value associated with a parameter. We bump this
// pointer down for each provenance value that we expect to receive, based on
// the type signature of the function. Then, we bump it further to create slots
// for each static allocation that we need to instrument. Function entry retags
// receive a dedicated, fixed region on the stack, because the number of
// protected tags is variable depending on the function (retagging can branch).
// The end of this region is the end of the "frame header". All other kind of
// shadow stack slots lie below this region.
class ShadowStackAllocator {
  // The size of a slot within the shadow stack.
  Value *SlotSize;

  // The number of stack slots allocated to store the provenance
  // of allocations that live for the duration of the stack frame,
  // and will be deallocated before the function returns.
  unsigned NumStackAllocSlots = 0;

  // A pointer to where the frame pointer is stored.
  Value *FramePtrSrc;

  // The top of the frame header.
  Value *FrameHeaderTop = nullptr;

  // Within the frame header, the start of the section containing
  // the permissions associated with function-entry retags.
  Value *FnEntryTop = nullptr;

  // The bottom of the frame header (after params,
  // static allocas, and function-entry retags).
  Value *FrameHeaderBottom = nullptr;

  // A helper struct, tracking the number of "regular" shadow
  // stack slots that have been allocated.
  SlotAllocator RegularSlots;

  // A helper struct, tracking the number of "protected" shadow
  // stack slots that have been allocated.
  SlotAllocator FnEntrySlots;

  // Returns the specified slot allocator.
  SlotAllocator &slotsFor(bool IsFnEntry) {
    return IsFnEntry ? FnEntrySlots : RegularSlots;
  }

public:
  ShadowStackAllocator(Value *SlotSize, Value *FramePtrSrc)
      : SlotSize(SlotSize), FramePtrSrc(FramePtrSrc),
        RegularSlots(SlotSize->getType()), FnEntrySlots(SlotSize->getType()) {}

  bool wasUsed() {
    return FrameHeaderBottom && (FrameHeaderBottom != FrameHeaderTop);
  }

  void allocateFnEntryRegion(IRBuilder<> &IRB, unsigned NumFnEntryRetags) {
    FnEntryTop = getOrInitFrameHeaderBottom(IRB);
    Value *Slots = ConstantInt::get(SlotSize->getType(), NumFnEntryRetags);
    Value *Bytes = IRB.CreateMul(Slots, SlotSize);
    FrameHeaderBottom = ptrsub(IRB, FnEntryTop, Bytes);
  }

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

  std::optional<Value *> getFnEntryTop(IRBuilder<> &IRB) {
    if (FnEntryTop) {
      return FnEntryTop;
    }
    return std::nullopt;
  }

  Value *getOrInitFrameHeaderBottom(IRBuilder<> &IRB) {
    if (!FrameHeaderBottom) {
      initFrameHeader(IRB, ConstantInt::get(SlotSize->getType(), 0));
    }
    return FrameHeaderBottom;
  }

  // Extends the frame header down by one provenance slot to store the
  // provenance associated with a stack allocation. This includes allocas and
  // byval arguments.
  Value *getStackAllocSlot(IRBuilder<> &IRB) {
    FrameHeaderBottom = ptrsub(IRB, getOrInitFrameHeaderBottom(IRB), SlotSize);
    NumStackAllocSlots += 1;
    return FrameHeaderBottom;
  }

  Value *getNumStackAllocSlots(IRBuilder<> &IRB, Type *Ty) {
    return ConstantInt::get(Ty, NumStackAllocSlots);
  }

  // Allocates one or more shadow stack slots from the requested section.
  Value *bumpStackSlot(DominatorTree &DT, LoopInfo &LI, IRBuilder<> &IRB,
                       bool IsFnEntry,
                       ElementCount Elems = ElementCount::getFixed(1)) {
    Value *SlotOffset = slotsFor(IsFnEntry).alloc(
        DT, LI, IRB, Elems, SlotSize->getType(), IsFnEntry);
    Value *ProvOffset = IRB.CreateMul(SlotOffset, SlotSize);
    if (IsFnEntry) {
      assert(FnEntryTop && "No function-entry slots available");
      return ptrsub(IRB, FnEntryTop, ProvOffset);
    }
    Value *Header = getOrInitFrameHeaderBottom(IRB);
    return ptrsub(IRB, Header, ProvOffset);
  }

  // Allocates one or more shadow stack slots from the requested section.
  Value *allocStackSlot(DominatorTree &DT, LoopInfo &LI, IRBuilder<> &IRB,
                        bool IsFnEntry,
                        ElementCount Elems = ElementCount::getFixed(1)) {

    Value *Slot = bumpStackSlot(DT, LI, IRB, IsFnEntry, Elems);
    if (!IsFnEntry) {
      // We need to update the bottom of the frame every time we allocate a
      // slot, because arbitrary instructions can be lowered into calls to
      // instrumented compiler-rt runtimes (e.g. __multi3, __udivti3,
      // __floatuntidf) that will use the shadow stack. We do not do this for
      // function-entry retags because they are a part of the frame header,
      // which is eagerly initialized on function entry.
      IRB.CreateStore(Slot, FramePtrSrc);
    }
    return Slot;
  }

  // Returns a pointer to the bottom of the specified section of the
  // shadow frame.
  Value *getStackPtr(DominatorTree &DT, LoopInfo &LI, IRBuilder<> &IRB,
                     bool IsFnEntry) {
    Value *CurrOffset =
        getOutgoingOffset(DT, LI, IRB, SlotSize->getType(), IsFnEntry);
    Value *ProvOffset = IRB.CreateMul(CurrOffset, SlotSize);
    Value *Base = IsFnEntry ? FnEntryTop : getOrInitFrameHeaderBottom(IRB);
    return ptrsub(IRB, Base, ProvOffset);
  }

  // Returns the current offset from the top of the relevant section. This is
  // used to update the stack pointer before calling functions and to get the
  // total number of function-entry retags before popping a stack frame.
  Value *getOutgoingOffset(DominatorTree &DT, LoopInfo &LI, IRBuilder<> &IRB,
                           Type *Ty, bool IsFnEntry) {
    return slotsFor(IsFnEntry).getCurrentOffset(DT, LI, IRB, Ty);
  }

  // Patches both section counters and promotes their tracking allocas.
  void patchStackSlots(DominatorTree &DT) {
    RegularSlots.patch(DT);
    FnEntrySlots.patch(DT);
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
  const StackSafetyGlobalInfo &SSGI;

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

  // Information needed to reconstruct the shadow memory of a byval argument
  // once the frame header has been initialized and validated.
  struct ByValArgInfo {
    // The byval argument (a pointer to the callee's private copy).
    Argument *Arg;
    // The provenance of the implicit allocation backing the byval copy.
    Provenance AllocProv;
    // The size, in bytes, of the byval allocation.
    Value *Size;
    // The alignment of the byval allocation.
    Align Alignment;
    // For each provenance field in the pointee type, the shadow-stack slot
    // offset (measured in provenance slots from the top of the frame header)
    // where the caller stored its provenance, paired with the field's location
    // within the allocation.
    SmallVector<std::pair<Value *, ProvenanceField>> Fields;
  };

  SmallVector<Provenance, 2> ByValAllocs;

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
                         const TargetLibraryInfo &TLI, DominatorTree &DT,
                         const StackSafetyGlobalInfo &SSGI)
      : F(F), BS(BS), C(BS.C), TLI(&TLI), DT(DT), SSGI(SSGI),
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
          // SafeStack marks an alloca as safe when it is never exposed to an
          // unknown source of memory effects. Such allocas cannot be subject
          // to the aliasing violations our retags would detect, so we ignore
          // them entirely instead of tracking and checking their accesses.
          if (BS.shouldInstrumentAlloca(AI) && AI.isStaticAlloca() &&
              !SSGI.isSafe(AI))
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
            if (AI && BS.shouldInstrumentAlloca(*AI) && !SSGI.isSafe(*AI)) {
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
      storeProvenanceWithReferenceCount(IRB, TagPtr, InfoPtr, Prov, Ordering);
    }
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
    // We always need to increment first, in case both the source and
    // destination are the same provenance value. If we decrement the
    // provenance in the destination first, then the garbage collector
    // may see a zero reference count and deinitialize the provenance
    // that we are about to store.
    if (Prov != Provenance::omnivalid(BS)) {
      IRB.CreateCall(BS.BsanFuncRcInc, {Prov.Tag, Prov.Info});
    }
    // We only decrement on nonatomic loads. This leaks provenance exposed to
    // atomic operations, which is necessary to support them without locking.
    if (Ordering == AtomicOrdering::NotAtomic) {
      Provenance Old =
          loadProvenanceAlignedPairwise(IRB, TagPtr, InfoPtr, Ordering);
      IRB.CreateCall(BS.BsanFuncRcDec, {Old.Tag, Old.Info});
    }

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
    // We use a `donothing` marker to separate the "prologue" of the function
    // from the rest of its body. This creates a dedicated insertion point for
    // instructions that require the shadow stack to be initialized and
    // need to create values that dominate the body of the function.
    FnPrologueEnd = TopIRB.CreateIntrinsic(Intrinsic::donothing, {});
    IRBuilder<> EntryIRB(FnPrologueEnd);

    // We need to compute the total number of provenance values that
    // we receive from the caller before we can load them, which is
    // necessary for boundary validation. We can only load a provenance
    // value once we have ensured that its stack slot is omnivalid
    // if we had an uninstrumented caller.
    Value *NumParamProv = ConstantInt::get(BS.IntptrTy, 0);

    Value *VarArgProvCount = nullptr;
    if (F.isVarArg()) {
      VarArgProvCount = EntryIRB.CreateLoad(BS.IntptrTy, BS.VarArgCounterTLS);
    }

    bool DiffABI = BS.needsBoundaryValidation(&F);
    // Iterate over each argument to compute how many provenance slots
    // we need.
    SmallVector<ByValArgInfo> ByValArgs;
    for (auto &Arg : F.args()) {
      if (Arg.hasAttribute(Attribute::ByVal)) {
        // byval arguments create a new allocation to store
        // the value received from the caller. We treat this
        // implicit allocation the same as an explicit alloca.
        Type *Ty = Arg.getParamByValType();
        TypeSize TS = BS.DL->getTypeAllocSize(Ty);
        Value *Size = EntryIRB.CreateTypeSize(BS.IntptrTy, TS);

        Provenance Prov = createAllocaMetadata(EntryIRB);
        initAllocaMetadata(EntryIRB, &Arg, Size, Prov);
        setProvenance(&Arg, Prov);

        ByValArgInfo Info;
        Info.Arg = &Arg;
        Info.AllocProv = Prov;
        Info.Size = Size;

        // If a `byval` parameter does not have an explicit alignment, then
        // we use the alignment of the type. As specified in the LLVM guide:
        // "the byval type argument is only used for its allocation size
        // and alignment (if there is no explicit align attribute)"
        MaybeAlign ParamAlign = Arg.getParamAlign();
        Info.Alignment = ParamAlign.value_or(BS.DL->getABITypeAlign(Ty));

        for (auto &Desc :
             BS.getProvenanceDesc(EntryIRB, Ty, /*ClearGaps=*/DiffABI)) {
          Value *NumProv = EntryIRB.CreateElementCount(BS.IntptrTy, Desc.Elems);
          NumParamProv = EntryIRB.CreateAdd(NumParamProv, NumProv);
          Info.Fields.push_back({NumParamProv, Desc});
        }
        ByValArgs.push_back(Info);
        ByValAllocs.push_back(Prov);
      } else {

        SmallVector<ProvenanceField> ProvDesc = BS.getProvenanceDesc(
            EntryIRB, Arg.getType(), /*ClearGaps=*/DiffABI);
        for (auto &Desc : ProvDesc) {
          Value *NumProv = EntryIRB.CreateElementCount(BS.IntptrTy, Desc.Elems);
          NumParamProv = EntryIRB.CreateAdd(NumParamProv, NumProv);
          // We store the shadow stack offset and width of the provenance for
          // each argument, without eagerly loading it.
          ArgumentProvenance[&Arg].push_back({NumParamProv, Desc.Elems});
        }
      }
    }

    // If our parameters have provenance, then we need to allocate
    // that many slots within our shadow stack frame's header.
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

    // We have computed the total number of shadow stack slots that
    // are associated with parameters. Now, if this function could be
    // called from an uninstrumented context, we need to check to see if
    // our boundary marker matches the current function's address. If not,
    // we zero-out all of the parameter shadow stack slots, giving them
    // omnivalid provenance.
    if (BS.needsBoundaryValidation(&F)) {
      if (!BS.shouldTrustFunction(TLI, &F)) {
        EntryIRB.CreateCall(BS.BsanFuncValidateParams,
                            {&F, ValidateHeaderBottom, NumParamProv});
      }
    }

    // Afterward, we can load the provenance of the byval type,
    // and store it to the shadow memory of the byval pointer.
    for (auto &Info : ByValArgs) {
      SmallVector<std::pair<ProvenanceField, Provenance>> Fields;
      for (auto &[SlotOffset, Desc] : Info.Fields) {
        Value *HeaderTop = ShadowStack.getOrInitFrameHeaderTop(EntryIRB);
        Value *ByteOffset = EntryIRB.CreateMul(BS.ProvenanceSize, SlotOffset);
        Value *ProvPtr = ptrsub(EntryIRB, HeaderTop, ByteOffset);
        Provenance Prov = loadProvenance(EntryIRB, ProvPtr, Desc.Elems);
        Fields.push_back({Desc, Prov});
      }
      copyProvenance(EntryIRB, Info.Arg, Fields, Info.Size, Info.Alignment,
                     AtomicOrdering::NotAtomic);
      Value *Slot = ShadowStack.getStackAllocSlot(EntryIRB);
      storeProvenance(EntryIRB, Info.AllocProv, Slot);
    }

    // We push additional slots into the frame header for
    // static allocas.
    for (auto [Idx, AI] : llvm::enumerate(StaticAllocaVec)) {
      Provenance Prov = createAllocaMetadata(EntryIRB);
      NextNodeIRBuilder IRB(AI);
      if (!HasLifetimeStart.contains(AI)) {
        Value *AllocaSize = BS.getAllocaSizeBytes(IRB, AI);
        initAllocaMetadata(IRB, AI, AllocaSize, Prov);
      }
      setProvenance(AI, Prov);
      Value *Slot = ShadowStack.getStackAllocSlot(EntryIRB);
      storeProvenance(EntryIRB, Prov, Slot);
    }

    // We also need a dedicated region of the shadow stack
    // for function-entry retags. The total number of function
    // entry retags is variable, because function entry retags can
    // happen across different branches.
    ShadowStack.allocateFnEntryRegion(EntryIRB, NumFnEntryRetags);

    // We have initialized the frame header, but we have not updated the frame
    // pointer to reflect it.
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
                    RI.PinArray, PinArrayLen, SrcProv.Tag, SrcProv.Info, Slot,
                    IRB.getInt1(false)});
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
                      RI.PinArray, PinArrayLen, Prov->Tag, Prov->Info, Dest,
                      IRB.getInt1(false)});
      setProvenance(&CB, loadProvenance(IRB, Dest));
    }
  }

  Value *bumpStackSlot(IRBuilder<> &IRB, bool IsFnEntry,
                       ElementCount Elems = ElementCount::getFixed(1)) {
    return ShadowStack.bumpStackSlot(DT, LI, IRB, IsFnEntry, Elems);
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

    bool DiffABI = BS.needsBoundaryValidation(Callee);
    SmallVector<std::pair<Value *, Provenance>> ParamOffsets;
    for (const auto &[i, Arg] : llvm::enumerate(CB.args())) {
      bool IsByVal = CB.paramHasAttr(i, Attribute::ByVal);
      Type *ArgTy = IsByVal ? CB.getParamByValType(i) : Arg->getType();

      SmallVector<ProvenanceField> ProvDesc =
          BS.getProvenanceDesc(Before, ArgTy, /*ClearGaps=*/DiffABI);

      for (const auto &[Idx, Desc] : llvm::enumerate(ProvDesc)) {
        Value *NumProv = Before.CreateElementCount(BS.IntptrTy, Desc.Elems);
        NumParamProv = Before.CreateAdd(NumParamProv, NumProv);

        if (IsVarArg && i >= NumFixedParams) {
          VarArgProvCount = Before.CreateAdd(VarArgProvCount, NumProv);
        }

        Value *ByteOffset = Before.CreateMul(NumParamProv, BS.ProvenanceSize);
        Provenance ProvSrc;
        if (IsByVal) {
          Align ByValAlign =
              CB.getParamAlign(i).value_or(BS.DL->getABITypeAlign(ArgTy));
          // Read the field's provenance from the caller's copy of the byval
          // memory so that we can forward it to the callee.
          Value *ObjAddr = ptradd(Before, Arg, Desc.ByteOffset);
          Align FieldAlign =
              commonAlignment(ByValAlign, Desc.FieldAlign.value());
          ProvSrc =
              loadProvenanceFromShadow(Before, ObjAddr, FieldAlign, Desc.Elems);
        } else {
          ProvSrc = assertProvenance(Before, Desc.Elems, {Arg, Idx});
        }
        ParamOffsets.push_back(std::make_pair(ByteOffset, ProvSrc));
      }
    }

    if (CB.isMustTailCall()) {
      // We need to pop the current frame, since
      // the semantics of a tail call are equivalent
      // to a return and then another call.
      popFrame(Before, CB, nullptr);
    }

    // If we have parameter provenance, then store it to the shadow stack
    // below the value of the current frame pointer.
    if (!ParamOffsets.empty() || ShadowStack.getFrameHeaderTop().has_value()) {
      Value *StackOffset;
      if (CB.isMustTailCall()) {
        // Now that we've popped the frame, we
        // can clobber the current frame header.
        StackOffset = ShadowStack.getOrInitFrameHeaderTop(Before);
      } else {
        // Always update the provenance stack before any non-musttail call,
        // so the callee loads a valid frame top, even when there are
        // no pointer args.
        StackOffset = getStackOffset(Before, false);
      }
      Before.CreateStore(StackOffset, BS.ProvStackTLS);

      for (auto [ByteOffset, Prov] : ParamOffsets) {
        Value *Slot = ptrsub(Before, StackOffset, ByteOffset);
        storeProvenance(Before, Prov, Slot);
      }
    }

    if (IsVarArg) {
      Before.CreateStore(VarArgProvCount, BS.VarArgCounterTLS);
    }

    // Skip the epilogue for musttail calls, since
    // they need to be adjacent to a ret.
    if (CB.isMustTailCall()) {
      return;
    }

    // If a function call is a terminator, then we need to insert
    // the epilogue at the beginning of the next block. If it has
    // multiple successors, then we create a new intermediate block
    // for the epilogue, which will jump to the original destination.
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

    SmallVector<ProvenanceField> ReturnDesc =
        BS.getProvenanceDesc(Before, CB.getType());

    // Only sized return types have provenance
    if (CB.getType()->isSized()) {
      // The callee stores return provenance above the frame pointer.
      // so that it remains in view of the garbage collector. We need to
      // bump our "view" of the stack pointer forward so that it matches
      // what was set by the callee.
      for (const auto &[Idx, Desc] : llvm::enumerate(ReturnDesc)) {
        Value *Slot = bumpStackSlot(After, false, Desc.Elems);
        ReturnProvPtrs.push_back(Slot);
        Value *NumProv = After.CreateElementCount(BS.IntptrTy, Desc.Elems);
        NumReturnProv = After.CreateAdd(NumReturnProv, NumProv);
      }
    }
    // If we are returning from a possibly-uninstrumented function, then we need
    // need to validate the space on the shadow stack where the return value's
    // provenance is stored.
    if (BS.needsBoundaryValidation(Callee)) {
      Value *Marker;
      Value *NullPtr = ConstantPointerNull::get(BS.PtrTy);
      // If this is a function that we can trust (e.g. an allocator)
      // then we write 1 into the boundary marker. This "magic value"
      // indicates to subsequent callees that they can trust that their
      // caller was instrumented. This is necessary for Rust's allocator
      // shims (e.g. `__rust_alloc`) which are thin wrappers around the
      // `__rdl_alloc` family of functions. The wrapper shims are left
      // uninstrumented when we run this pass through Rust's LLVM plugin
      // hooks, so they will clear provenance unless we override the default
      // behavior here.
      if (BS.shouldTrustFunction(TLI, &CB)) {
        Value *TrustedMarker = ConstantExpr::getIntToPtr(
            ConstantInt::get(BS.IntptrTy, 1), BS.PtrTy);
        Marker = Before.CreateCall(BS.BsanFuncMark, {TrustedMarker});
        After.CreateStore(Marker, BS.MarkerTLS);
      } else {
        // Otherwise, we need to initialize the marker with the function
        // pointer that we are calling, so that the callee can check
        // against it.
        Marker = Before.CreateCall(BS.BsanFuncMark, {CB.getCalledOperand()});
        // If we do not have any return provenance, then
        // we do not need to validate any part of the shadow stack
        // on return.
        Value *Slot = getStackOffset(After, false);
        if (!ReturnProvPtrs.empty()) {
          After.CreateCall(BS.BsanFuncValidateRetval,
                           {Marker, Slot, NumReturnProv});
        }
        // We always need to store the expected value of our stack pointer,
        // which should sit below the return provenance. If our caller is
        // instrumented, then we can guarantee that the stack pointer is in the
        // correct spot, but if it is uninstrumented, then the stack pointer
        // might be far below where we expect it to be, if we crossed back into
        // instrumented code at some point.
        After.CreateStore(Slot, BS.ProvStackTLS);
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

    // Finally, load the return value's provenance from the shadow stack.
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
      SmallVector<ProvenanceField> Components =
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

  Provenance createProvenancePHI(IRBuilder<> &IRB, ProvenanceField Comp,
                                 iterator_range<pred_iterator> Blocks) {
    if (Comp.Elems.isVector()) {
      report_fatal_error("Vectors are not supported.");
    }
    return createScalarProvenancePHI(IRB, Blocks);
  }

  void visitPHINode(PHINode &PN) {
    IRBuilder<> IRB(&PN);
    unsigned NumIncoming = PN.getNumIncomingValues();
    SmallVector<ProvenanceField> Components =
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

  Provenance createAllocaMetadata(IRBuilder<> &IRB) {
    Value *Tag = newBorrowTag(IRB);
    Value *Info = IRB.CreateCall(BS.BsanFuncReserveStackSlot, {});
    return Provenance(Tag, Info);
  }

  void initAllocaMetadata(IRBuilder<> &IRB, AllocaInst *AI, Provenance Prov) {
    Value *AllocaSize = BS.getAllocaSizeBytes(IRB, AI);
    initAllocaMetadata(IRB, AI, AllocaSize, Prov);
  }

  void initAllocaMetadata(IRBuilder<> &IRB, Value *Addr, Value *Size,
                          Provenance Prov) {
    IRB.CreateCall(BS.BsanFuncAllocStack, {Addr, Size, Prov.Tag, Prov.Info});
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
      // SafeStack-safe allocas are never instrumented, so any access that
      // reaches here needs the full borrow-tracking check (`checked = false`).
      // The runtime retains the unchecked fast path for future use.
      IRB.CreateCall(BS.BsanFuncRead, {Ptr, Size, (*Prov).Tag, (*Prov).Info,
                                       IRB.getInt1(false)});
    }
  }

  void insertWriteCheck(IRBuilder<> &IRB, Value *Ptr, Value *Size) {
    if (auto Prov = getProvenance(IRB.GetInsertBlock(), Ptr)) {
      IRB.CreateCall(BS.BsanFuncWrite, {Ptr, Size, (*Prov).Tag, (*Prov).Info,
                                        IRB.getInt1(false)});
    }
  }

  void visitLoadInst(LoadInst &LI) {
    if (LI.isAtomic())
      return;

    IRBuilder<> IRB(&LI);
    Value *Ptr = LI.getPointerOperand();

    Value *Size =
        IRB.CreateTypeSize(BS.IntptrTy, BS.DL->getTypeStoreSize(LI.getType()));

    SmallVector<ProvenanceField> Components =
        BS.getProvenanceDesc(IRB, LI.getType());

    Value *Base = LI.getPointerOperand();
    for (const auto &[Idx, Comp] : llvm::enumerate(Components)) {
      Value *ByteOffset = Comp.ByteOffset;
      Value *ObjAddr = ptradd(IRB, Base, ByteOffset);
      Align FieldAlign =
          commonAlignment(LI.getAlign(), Comp.FieldAlign.value());
      Provenance Prov = loadProvenanceFromShadow(IRB, ObjAddr, FieldAlign,
                                                 Comp.Elems, LI.getOrdering());
      setProvenance({&LI, Idx}, Prov);
    }
    insertReadCheck(IRB, Ptr, Size);
  }

  void visitStoreInst(StoreInst &SI) {
    IRBuilder<> BeforeIRB(&SI);
    Value *Ptr, *Val;
    Ptr = SI.getPointerOperand();
    Val = SI.getValueOperand();

    // Insert a write check for the store size of the type.
    // This may be different than the size of the type itself.
    // An `i48` is a legal integer type in LLVM, but would typically
    // be stored as an `i64`.
    TypeSize TypeStoreSize = BS.DL->getTypeStoreSize(Val->getType());
    Value *ValStoreSize = BeforeIRB.CreateTypeSize(BS.IntptrTy, TypeStoreSize);
    insertWriteCheck(BeforeIRB, Ptr, ValStoreSize);

    // If the write check succeeds, then we need to propagate provenance
    // through the store instruction. This includes clearing provenance
    // from memory locations that are clobbered by non-pointer stores.
    // This is necessary for accurate reference counting and to
    // make sure that pointers that are cast from integers via load / store
    // type punning receive omnivalid provenance.
    NextNodeIRBuilder AfterIRB(&SI);

    Type *Ty = Val->getType();
    SmallVector<std::pair<ProvenanceField, Provenance>> FieldValues;
    SmallVector<ProvenanceField> Fields = BS.getProvenanceDesc(AfterIRB, Ty);
    for (const auto &[Idx, Desc] : llvm::enumerate(Fields)) {
      Provenance Prov = assertProvenance(AfterIRB, Desc.Elems, {Val, Idx});
      FieldValues.push_back({Desc, Prov});
    }
    TypeSize StoreSize = BS.DL->getTypeStoreSize(Ty);
    Value *TotalSize = AfterIRB.CreateTypeSize(BS.IntptrTy, StoreSize);
    copyProvenance(AfterIRB, Ptr, FieldValues, TotalSize, SI.getAlign(),
                   SI.getOrdering());
  }

  void copyProvenance(IRBuilder<> &IRB, Value *Pointer,
                      ArrayRef<std::pair<ProvenanceField, Provenance>> ProvDesc,
                      Value *TotalSize, Align CopyAlign,
                      AtomicOrdering Ordering) {
    Value *Cursor = ConstantInt::get(BS.IntptrTy, 0);
    SmallVector<std::tuple<Value *, Value *>> SlotsToClear;

    for (const auto &[Desc, Prov] : ProvDesc) {
      Align FieldAlign = commonAlignment(Desc.FieldAlign, CopyAlign.value());
      Value *GapSize = ConstantInt::get(BS.IntptrTy, 0);

      // If our cursor is less than this field's offset, then there's a gap to
      // clear.
      if (Cursor != Desc.ByteOffset) {
        GapSize = IRB.CreateSub(Desc.ByteOffset, Cursor);
        if (FieldAlign < kMinProvAlignment) {
          // Round down so we don't clear a slot that we are about to overwrite
          // anyway.
          if (auto *CI = dyn_cast<ConstantInt>(GapSize)) {
            uint64_t GapSizeDown =
                (CI->getZExtValue() & ~(kMinProvAlignment.value() - 1));
            GapSize = ConstantInt::get(BS.IntptrTy, GapSizeDown);
          }
        }
        if (!match(GapSize, m_Zero()))
          SlotsToClear.push_back(std::make_tuple(Cursor, GapSize));
      }

      Value *ObjAddr = ptradd(IRB, Pointer, Desc.ByteOffset);
      storeProvenanceToShadow(IRB, ObjAddr, Prov, FieldAlign, Ordering);

      Cursor = IRB.CreateNUWAdd(Desc.ByteOffset, Desc.ByteWidth);
    }

    // Clear any trailing gap between the last field and the end of the range.
    Value *FinalGapSize = IRB.CreateSub(TotalSize, Cursor);
    if (!match(FinalGapSize, m_Zero()))
      SlotsToClear.push_back(std::make_tuple(Cursor, FinalGapSize));

    for (auto &[Offset, GapSize] : SlotsToClear) {
      Value *BaseAddr = ptradd(IRB, Pointer, Offset);
      MaybeAlign GapAlign = std::nullopt;
      if (auto *CI = dyn_cast<ConstantInt>(Offset))
        GapAlign = commonAlignment(CopyAlign, CI->getZExtValue());
      clearProvenance(IRB, BaseAddr, GapSize, GapAlign, Ordering);
    }
  }

  // Clears the provenance for the given range.
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
        Value *SlotTagPtr = ptradd(IRB, TagPtr, Idx);
        Value *SlotInfoPtr = ptradd(IRB, InfoPtr, Idx);
        storeProvenanceWithReferenceCount(IRB, SlotTagPtr, SlotInfoPtr,
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
        SmallVector<ProvenanceField> ProvDesc =
            BS.getProvenanceDesc(IRB, ElemType);
        Offset += ProvDesc.size();
      }
      return {ST->getElementType(Idx), Offset};
    }

    if (auto *AT = dyn_cast<ArrayType>(Ty)) {
      SmallVector<ProvenanceField> ProvDesc =
          BS.getProvenanceDesc(IRB, AT->getElementType());
      return {AT->getElementType(), ProvDesc.size() * Idx};
    }

    report_fatal_error("Cannot index into a non-struct or non-array type.");
  }

  void visitExtractValueInst(ExtractValueInst &EI) {
    IRBuilder<> IRB(&EI);
    Value *AggregateSrc = EI.getAggregateOperand();

    SmallVector<ProvenanceField> DestProvDesc =
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
    SmallVector<ProvenanceField> SrcProvDesc =
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
    SmallVector<ProvenanceField> ProvDesc =
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
    if (ShadowStack.wasUsed()) {
      Value *NumStackAllocs =
          ShadowStack.getNumStackAllocSlots(IRB, BS.IntptrTy);
      Value *NumProtectors =
          ShadowStack.getOutgoingOffset(DT, LI, IRB, BS.IntptrTy, true);
      Value *MaxNumProtectors = ConstantInt::get(BS.IntptrTy, NumFnEntryRetags);

      Value *FrameHeaderBottom = ShadowStack.getOrInitFrameHeaderBottom(IRB);
      Value *OffsetSlots = IRB.CreateSub(MaxNumProtectors, NumProtectors);
      Value *OffsetBytes = IRB.CreateMul(OffsetSlots, BS.ProvenanceSize);
      Value *Start = ptradd(IRB, FrameHeaderBottom, OffsetBytes);

      IRB.CreateCall(BS.BsanFuncPopFrame,
                     {Start, NumProtectors, NumStackAllocs});
    }

    if (RetVal) {
      SmallVector<Value *> ReturnProvPtrs;
      SmallVector<ProvenanceField> ProvDesc =
          BS.getProvenanceDesc(IRB, RetVal->getType());
      if (!ProvDesc.empty()) {
        Value *FrameTop = ShadowStack.getOrInitFrameHeaderTop(IRB);
        Value *NumReturnProv = ConstantInt::get(BS.IntptrTy, 0);
        for (const auto &[Idx, Desc] : llvm::enumerate(ProvDesc)) {
          NumReturnProv = IRB.CreateAdd(
              NumReturnProv, IRB.CreateElementCount(BS.IntptrTy, Desc.Elems));
          Value *ByteWidth = IRB.CreateMul(NumReturnProv, BS.ProvenanceSize);
          ReturnProvPtrs.push_back(ptrsub(IRB, FrameTop, ByteWidth));
        }
        IRB.CreateStore(ReturnProvPtrs.back(), BS.ProvStackTLS);
        for (const auto &[Idx, Ptr] : llvm::enumerate(ReturnProvPtrs)) {
          Provenance Prov =
              assertProvenance(IRB, ProvDesc[Idx].Elems, {RetVal, Idx});
          storeProvenance(IRB, Prov, Ptr);
        }
        return;
      }
    }

    if (auto FrameTop = ShadowStack.getFrameHeaderTop()) {
      IRB.CreateStore(FrameTop.value(), BS.ProvStackTLS);
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
                                         FunctionAnalysisManager &FAM,
                                         const StackSafetyGlobalInfo &SSGI) {
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
  BorrowSanitizerVisitor Visitor(F, *this, TLI, DT, SSGI);

  AttributeMask B;
  B.addAttribute(Attribute::Memory).addAttribute(Attribute::Speculatable);
  F.removeFnAttrs(B);

  Visitor.run();

  F.addFnAttr(Attribute::DisableSanitizerInstrumentation);
  return true;
}