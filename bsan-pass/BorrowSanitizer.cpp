#include "BorrowSanitizerPass.h"
#include "InstrumentationPlan.h"
#include "Retag.h"
#include "llvm/Analysis/DomTreeUpdater.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/StackLifetime.h"
#include "llvm/Analysis/StackSafetyAnalysis.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/AttributeMask.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/CycleInfo.h"
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

// The number of bytes that can be
// stored within a TLS array for
// variadic arguments.
static const unsigned kVarArgTLSSizeBytes = 800;

// The number of provenance values that can
// be stored within a TLS array for fixed parameters.
static const unsigned kParamTLSSizeProv = 100;

static cl::opt<bool> ClHandleAsmConservative(
    "bsan-asm-conservative",
    cl::desc("Conservatively handle inline assembly by setting all pointer "
             "outputs to wildcard Provenance"),
    cl::Hidden, cl::init(true));

static cl::opt<bool> ClInstrumentVariadics(
    "bsan-variadics", cl::desc("Instrument functions with variadic arguments."),
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

/// Indicates if the given function requires boundary validation (e.g.),
/// it may be called from an uninstrumented context, or from an instrumented
/// context that uses a different ABI lowering for parameter types.
static bool needsBoundaryValidation(const Function *Callee) {
  return !Callee ||
         (Callee->isDeclaration() || Callee->hasExternalLinkage() ||
          Callee->hasExternalWeakLinkage() || Callee->hasAddressTaken());
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

// A static or dynamic offset as a number
// of provenance slots.
struct ProvenanceOffset {
  Value *Val;
  ProvenanceOffset() {}
  ProvenanceOffset(Value *Val) : Val(Val) {
    if (auto *CI = dyn_cast<ConstantInt>(Val)) {
      assert(CI->getZExtValue() % kMinProvAlignment.value() == 0);
    }
  }
  ProvenanceOffset(Type *Ty, unsigned Bytes) {
    assert(alignTo(Bytes, kMinProvAlignment) == Bytes);
    Val = ConstantInt::get(Ty, Bytes);
  }

  static ProvenanceOffset alignDown(IRBuilder<> &IRB, Value *V) {
    const uint64_t ProvAlign = kMinProvAlignment.value();
    Value *Rounded =
        IRB.CreateAnd(V, ConstantInt::get(V->getType(), ~(ProvAlign - 1)));
    return ProvenanceOffset(Rounded);
  }

  static ProvenanceOffset alignUp(IRBuilder<> &IRB, Value *V) {
    const uint64_t ProvAlign = kMinProvAlignment.value();
    return alignDown(
        IRB, IRB.CreateAdd(V, ConstantInt::get(V->getType(), ProvAlign - 1)));
  }
};

// A pointer to a location where a provenance value can be stored.
// This location must be aligned to the size of a provenance value.
struct ProvenanceDest {
  // Pointers to where each component of a provenance value is stored.
  Value *ShadowPtr = nullptr;
  Value *OriginPtr = nullptr;
  // If we store a provenance value into shadow memory, then we need
  // to update the reference counts of the provenance being stored, and
  // the provenance being clobbered by the store. However, we also use
  // main memory to store provenance values, when we pass them as
  // parameters to functions and as variadic arguments. In these cases
  // we can guarantee that the provenance values are "rooted" elsewhere
  // on the shadow stack, so we do not need to update reference counts.
  // We can use this struct for each situation, setting the following
  // flag to control the desired behavior.
  bool UpdateRefCt = false;
  ProvenanceDest() {}
  ProvenanceDest(Value *Shadow, Value *Origin, bool UpdateRefCt)
      : ShadowPtr(Shadow), OriginPtr(Origin), UpdateRefCt(UpdateRefCt) {}
  ProvenanceDest ptradd(IRBuilder<> &IRB, ProvenanceOffset Offset) {
    return ProvenanceDest(::ptradd(IRB, ShadowPtr, Offset.Val),
                          ::ptradd(IRB, OriginPtr, Offset.Val), UpdateRefCt);
  }
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
  friend struct VarArgHelperBase;
  friend struct VarArgAMD64Helper;
  friend struct VarArgAArch64Helper;
  friend struct Provenance;
  friend struct ProvenanceMap;
  friend class BorrowSanitizerVisitor;

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

  /// Thread-local array used to pass the provenance of parameters.
  Value *ParamTLS = nullptr;

  /// Thread-local variable containing the number of provenance values
  /// for variable arguments.
  Value *VAArgOverflowSizeTLS = nullptr;

  /// Thread-local array containing the tag of variadic arguments.
  Value *VAArgTagTLS = nullptr;

  /// Thread-local array containing the info of variadic arguments.
  Value *VAArgInfoTLS = nullptr;

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

  /// Runtime replacement for `memset` that also clears shadow memory.
  FunctionCallee BsanFuncMemSet;

  /// Runtime replacement for `memmove` that also clears shadow memory.
  FunctionCallee BsanFuncMemMove;

  /// Runtime replacement for `memcpy` that also clears shadow memory.
  FunctionCallee BsanFuncMemCpy;

  /// Runtime function for clearing a range within shadow memory.
  FunctionCallee BsanFuncShadowClearAligned;

  /// Runtime function for copying provenance, split across
  /// two disjoint regions of memory, into the shadow for a given address.
  /// Used to support variadic functions.
  FunctionCallee BsanFuncShadowJoin;

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

  /// Indicates that the given function is instrumented, intercepted,
  /// or otherwise has semantics that we can trust without boundary validation.
  bool shouldTrustFunction(const TargetLibraryInfo *TLI, const Value *V);

  /// Indicates if this `alloca` needs to be instrumented.
  bool shouldInstrumentAlloca(const AllocaInst &AI);

  /// Computes the size of an `alloca` in bytes.
  Value *getAllocaSizeBytes(IRBuilder<> &IRB, AllocaInst *AI);

  /// Returns a list of the fields within a type that carry provenance
  SmallVector<ProvenanceField> getProvenanceLayout(IRBuilder<> &IRB, Type *Ty,
                                                   bool ClearGaps = false);

private:
  Value *getProvenanceLayout(IRBuilder<> &IRB,
                             SmallVector<ProvenanceField> &ProvDesc,
                             Type *CurrentTy, Value *ByteOffset,
                             bool ClearGaps = false);
};
} // end anonymous namespace

// Provides a list of the locations of provenance values inside a type.
SmallVector<ProvenanceField>
BorrowSanitizer::getProvenanceLayout(IRBuilder<> &IRB, Type *Ty,
                                     bool ClearGaps) {
  SmallVector<ProvenanceField> Desc;
  if (Ty->isSized()) {
    Value *Zero = ConstantInt::get(IRB.getIntPtrTy(*DL), 0);
    getProvenanceLayout(IRB, Desc, Ty, Zero, ClearGaps);
  }
  return Desc;
}

Value *BorrowSanitizer::getAllocaSizeBytes(IRBuilder<> &IRB, AllocaInst *AI) {
  TypeSize TS = AI->getAllocationSize(*DL).value();
  return IRB.CreateTypeSize(IntptrTy, TS);
}

// Populates a vector with the list of locations of provenance
// values within a type.
Value *BorrowSanitizer::getProvenanceLayout(
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
          getProvenanceLayout(IRB, ProvDesc, ElemTy, CurrByteOffset, ClearGaps);
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
      auto *ProvOffset = getProvenanceLayout(
          IRB, ProvDesc, AT->getElementType(), CurrByteOffset, ClearGaps);
      CurrProvOffset = IRB.CreateAdd(CurrProvOffset, ProvOffset);
    }
    return CurrProvOffset;
  } break;
  default: {
  } break;
  }
  return ConstantInt::get(IntptrTy, 0);
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
      BSAN("validate_params"), AL, IRB.getVoidTy(), PtrTy, IntptrTy, IntptrTy);

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

  BsanFuncShadowClearAligned =
      M.getOrInsertFunction(BSAN("shadow_clear_aligned"), AL, IRB.getVoidTy(),
                            PtrTy, PtrTy, IntptrTy);

  BsanFuncShadowJoin = M.getOrInsertFunction(
      BSAN("shadow_join"), AL, IRB.getVoidTy(), PtrTy, PtrTy, PtrTy, IntptrTy);

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

  VAArgOverflowSizeTLS =
      getOrInsertTLSGlobal(M, BSAN("var_arg_overflow"), IntptrTy);

  VAArgTagTLS = getOrInsertTLSGlobal(M, BSAN("var_arg_tag_tls"), PtrTy);
  VAArgInfoTLS = getOrInsertTLSGlobal(M, BSAN("var_arg_info_tls"), PtrTy);
  ParamTLS = getOrInsertTLSGlobal(M, BSAN("param_tls"), PtrTy);

  ProvStackTLS = getOrInsertTLSGlobal(M, BSAN("shadow_stack"), PtrTy);
  BorTagCounter = getOrInsertGlobal(M, BSAN("bor_tag_ctr"), IntptrTy);
}

namespace {

/// A helper class that handles instrumentation of VarArg
/// functions on a particular platform (borrowed from MSAN).
///
/// Implementations are expected to insert the instrumentation
/// necessary to propagate argument shadow through VarArg function
/// calls. Visit* methods are called during an InstVisitor pass over
/// the function, and should avoid creating new basic blocks. A new
/// instance of this class is created for each instrumented function.
struct VarArgHelper {
  virtual ~VarArgHelper() = default;

  /// Visit a CallBase.
  virtual void visitCallBase(CallBase &CB, IRBuilder<> &IRB) = 0;

  /// Visit a va_start call.
  virtual void visitVAStartInst(VAStartInst &I) = 0;

  /// Visit a va_copy call.
  virtual void visitVACopyInst(VACopyInst &I) = 0;

  /// Finalize function instrumentation.
  ///
  /// This method is called after visiting all interesting (see above)
  /// instructions in a function.
  virtual void finalizeInstrumentation() = 0;

  virtual uint64_t getFixedRegionSize() = 0;
};

struct BorrowSanitizerVisitor;

} // namespace

static VarArgHelper *createVarArgHelper(Function &Func, BorrowSanitizer &BS,
                                        BorrowSanitizerVisitor &BSV);

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
  static Provenance invalid(BorrowSanitizer &BS,
                            ElementCount Elems = ElementCount::getFixed(1));
  static Provenance wildcard(BorrowSanitizer &BS,
                             ElementCount Elems = ElementCount::getFixed(1));
};

// Tracks the provenance associated with each value.
struct ProvenanceMap {
  BorrowSanitizer &BS;
  // A map associating values with one or more provenance values,
  // corresponding to each field that carries provenance.  The index
  // in the inner map identifies the field. This map is used for SSA
  // values that have the same provenance everywhere that they are used.
  DenseMap<Value *, SmallDenseMap<unsigned, Provenance>> Mapping;

  // If an alloca has more than one `lifetime.start`, then its provenance
  // will vary, because each lifetime has a new root borrow tag. We create
  // an additional alloca to contain the tag for each of these allocas.
  DenseMap<AllocaInst *, AllocaInst *> TagAllocas;

  // When we need to resolve the tag for an alloca's provenance, we load it from
  // the dedicated tag alloca. We can cache loaded values during a given
  // lifetime to avoid unnecessary loads.
  DenseMap<BasicBlock *, DenseMap<AllocaInst *, Value *>> CachedTags;

  // After instrumenting the function, we promote all of the tag allocas into
  // registers.
  SmallVector<AllocaInst *> AllocasToPromote;

  // Only the tag of an alloca's provenance will change. The info stays the
  // same.
  DenseMap<AllocaInst *, Value *> AllocaInfo;

  // Certain operations (GEPs) might be emitted prior to any `lifetime.start`.
  // Instead of assigning them provenance, we track that they correspond to a
  // particular alloca, and lazily initialize provenance when we need it to
  // validate an access. As specified in langref: "operations that don’t
  // dereference [an alloca ...return a valid result."
  DenseMap<Value *, Value *> Forwards;

public:
  ProvenanceMap(BorrowSanitizer &BS) : BS(BS) {}

  // A key for the primary provenance mapping. Identifies the provenance
  // of a field.
  struct Key {
    Value *V;
    unsigned long Offset;
    Key(Value *V) : V(V), Offset(0) {}
    Key(Value *V, unsigned long Offset) : V(V), Offset(Offset) {}
  };

  void setProvenance(ProvenanceMap::Key K, Provenance Prov) {
    Mapping[K.V][K.Offset] = Prov;
  }

  void forwardProvenance(Value *Dest, Value *Src) { Forwards[Dest] = Src; }

  Value *getAllocaTagRecurse(BasicBlock *BB, AllocaInst *AI) {
    auto TagsIt = CachedTags.find(BB);
    if (TagsIt == CachedTags.end()) {
      if (auto *PredBB = BB->getSinglePredecessor()) {
        return getAllocaTagRecurse(PredBB, AI);
      }
    } else {
      auto &AllocaMap = TagsIt->second;
      auto AllocProvIt = AllocaMap.find(AI);
      if (AllocProvIt != AllocaMap.end())
        return AllocProvIt->second;
    }
    if (!TagAllocas.contains(AI)) {
      report_fatal_error("Unable to resolve cached tag alloca.");
    }

    IRBuilder<> FrontIRB(BB, BB->getFirstInsertionPt());
    AllocaInst *TagAlloca = TagAllocas[AI];
    Value *Tag = FrontIRB.CreateLoad(BS.IntptrTy, TagAlloca);
    CachedTags[BB][AI] = Tag;
    return Tag;
  }

  std::optional<Provenance> getProvenance(BasicBlock *BB, Key K) {
    // We return invalid provenance for null pointers.
    if (auto *CI = dyn_cast<ConstantPointerNull>(K.V)) {
      return Provenance::invalid(BS);
    }

    if (auto *Prov = find(K)) {
      return *Prov;
    }

    auto FwdIt = Forwards.find(K.V);
    if (FwdIt != Forwards.end()) {
      return getProvenance(BB, Key(FwdIt->second, K.Offset));
    }

    if (auto *AI = dyn_cast<AllocaInst>(K.V)) {
      auto InfoIT = AllocaInfo.find(AI);
      if (InfoIT != AllocaInfo.end()) {
        Value *Info = InfoIT->second;
        Value *Tag = getAllocaTagRecurse(BB, AI);
        return Provenance(Tag, Info);
      }
    }
    return std::nullopt;
  }

  void cacheAllocaProvenance(IRBuilder<> &IRB, AllocaInst *AI,
                             Provenance Prov) {
    AllocaInst *TagAlloca = IRB.CreateAlloca(BS.IntptrTy);
    IRB.CreateStore(Prov.Tag, TagAlloca);
    AllocasToPromote.push_back(TagAlloca);
    TagAllocas[AI] = TagAlloca;
    AllocaInfo[AI] = Prov.Info;
    CachedTags[IRB.GetInsertBlock()][AI] = Prov.Tag;
  }

  Provenance updateTag(IRBuilder<> &IRB, AllocaInst *AI, Value *Tag) {
    if (TagAllocas.contains(AI)) {
      AllocaInst *TagAlloca = TagAllocas[AI];
      IRB.CreateStore(Tag, TagAlloca);
      CachedTags[IRB.GetInsertBlock()][AI] = Tag;

      auto InfoIT = AllocaInfo.find(AI);
      if (InfoIT != AllocaInfo.end()) {
        Value *Info = InfoIT->second;
        return Provenance(Tag, Info);
      }
    }
    report_fatal_error("Unable to resolve cached tag alloca.");
  }

  Provenance *find(Key K) {
    auto InnerIt = Mapping.find(K.V);
    if (InnerIt == Mapping.end())
      return nullptr;

    auto &SubMap = InnerIt->second;
    auto SubIt = SubMap.find(K.Offset);
    if (SubIt == SubMap.end())
      return nullptr;

    return &SubIt->second;
  }

  void transfer(Value *Src, Value *Dest) {
    auto It = Mapping.find(Src);
    if (It == Mapping.end())
      return;

    SmallDenseMap<unsigned, Provenance> SrcMap = It->second;
    auto &DestMap = Mapping[Dest];
    for (const auto &[Idx, Prov] : SrcMap) {
      DestMap[Idx] = Prov;
    }
  }

  std::optional<Provenance> get(Key K) {
    if (Provenance *Prov = this->find(K)) {
      return *Prov;
    }
    return std::nullopt;
  }

  void patch(DominatorTree &DT) { PromoteMemToReg(AllocasToPromote, DT); }
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

Provenance Provenance::invalid(BorrowSanitizer &BS, ElementCount Elems) {
  if (Elems.isScalar()) {
    Value *One = ConstantInt::get(BS.IntptrTy, 1);
    Value *InvalidPtr = ConstantPointerNull::get(BS.PtrTy);
    return Provenance(One, InvalidPtr, Elems);
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
  Value *&getCurrentOffset(CycleInfo &CI, IRBuilder<> &IRB, Type *Ty) {
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
    // We can enter this block more than once, so we need to cache the offset
    // that we assigned on the first visit.
    if (CI.getCycle(InsertBB)) {
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
  Value *alloc(CycleInfo &CI, IRBuilder<> &IRB, ElementCount EC, Type *Ty,
               bool IsFnEntry) {
    Value *&Offset = getCurrentOffset(CI, IRB, Ty);
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
// that are accessible in memory and to pass provenance between functions.
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

  void initFrameHeader(IRBuilder<> &IRB) {
    BasicBlock *EntryBlock =
        &IRB.GetInsertBlock()->getParent()->getEntryBlock();
    IRBuilder<> EntryIRB(EntryBlock, EntryBlock->getFirstNonPHIIt());
    FrameHeaderTop = EntryIRB.CreateLoad(EntryIRB.getPtrTy(), FramePtrSrc);
    FrameHeaderBottom = FrameHeaderTop;
  }

  std::optional<Value *> getFrameHeaderTop() {
    if (FrameHeaderTop) {
      return FrameHeaderTop;
    }
    return std::nullopt;
  }

  Value *getOrInitFrameHeaderTop(IRBuilder<> &IRB) {
    if (!FrameHeaderTop) {
      initFrameHeader(IRB);
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
      initFrameHeader(IRB);
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
  Value *bumpStackSlot(CycleInfo &CI, IRBuilder<> &IRB, bool IsFnEntry,
                       ElementCount Elems = ElementCount::getFixed(1)) {
    Value *SlotOffset = slotsFor(IsFnEntry).alloc(
        CI, IRB, Elems, SlotSize->getType(), IsFnEntry);
    Value *ProvOffset = IRB.CreateMul(SlotOffset, SlotSize);
    if (IsFnEntry) {
      assert(FnEntryTop && "No function-entry slots available");
      return ptrsub(IRB, FnEntryTop, ProvOffset);
    }
    Value *Header = getOrInitFrameHeaderBottom(IRB);
    return ptrsub(IRB, Header, ProvOffset);
  }

  // Allocates one or more shadow stack slots from the requested section.
  Value *allocStackSlot(CycleInfo &CI, IRBuilder<> &IRB, bool IsFnEntry,
                        ElementCount Elems = ElementCount::getFixed(1)) {

    Value *Slot = bumpStackSlot(CI, IRB, IsFnEntry, Elems);
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
  Value *getStackPtr(CycleInfo &CI, IRBuilder<> &IRB, bool IsFnEntry) {
    Value *CurrOffset =
        getOutgoingOffset(CI, IRB, SlotSize->getType(), IsFnEntry);
    Value *ProvOffset = IRB.CreateMul(CurrOffset, SlotSize);
    Value *Base = IsFnEntry ? FnEntryTop : getOrInitFrameHeaderBottom(IRB);
    return ptrsub(IRB, Base, ProvOffset);
  }

  // Returns the current offset from the top of the relevant section. This is
  // used to update the stack pointer before calling functions and to get the
  // total number of function-entry retags before popping a stack frame.
  Value *getOutgoingOffset(CycleInfo &CI, IRBuilder<> &IRB, Type *Ty,
                           bool IsFnEntry) {
    return slotsFor(IsFnEntry).getCurrentOffset(CI, IRB, Ty);
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
  friend struct VarArgHelperBase;
  friend struct VarArgAMD64Helper;
  friend struct VarArgAArch64Helper;

  BorrowSanitizer &BS;
  Function &F;
  LLVMContext *C;

  // Cached analysis results
  const TargetLibraryInfo *TLI;
  DominatorTree &DT;
  CycleInfo Cycles;
  InstrumentationPlan Plan;

  // The end of the prologue of the function, where we initialize our
  // instrumentation. This is a call to llvm.donothing.
  Instruction *FnPrologueEnd;

  // The instance of `VarArgHelper` for the target architecture.
  std::unique_ptr<VarArgHelper> VAHelper;

  // A map from Arguments to (byte offset, provenance count) pairs, indicating
  // the offset from the top of the header where the argument's provenane is
  // stored, and how many provenance values are stored there.
  SmallDenseMap<Argument *, SmallVector<std::pair<Value *, ElementCount>>>
      ArgumentProvenance;

  // A map from values to their provenance.
  ProvenanceMap ProvMap;

  // For each alloca that has an explicit `lifetime.start` (and so gets a
  // fresh borrow tag minted on every entry into its scope), this records
  // where its provenance lives in this frame's shadow-stack header. At
  // function exit, `popFrame` reads directly out of that header to pop/
  // deallocate every slot in it -- so every time a fresh tag is minted, we
  // must also refresh the copy stored here, or `popFrame` will act on
  // whatever stale (tag, info) pair was written at function entry instead
  // of the alloca's current one.
  DenseMap<AllocaInst *, ProvenanceDest> AllocaFrameSlots;

  // Information needed to reconstruct the shadow memory of a `byval` argument
  // once the frame header has been initialized and validated.
  struct ByValArgInfo {
    Argument *Arg;
    // The provenance of the implicit allocation backing the byval copy.
    Provenance AllocProv;
    Value *Size;
    Align Alignment;
    // The shadow-stack slot offset where the caller stored the provenance
    // of each field within the `byval` pointee type.
    SmallVector<std::pair<Value *, ProvenanceField>> Fields;
  };

  SmallVector<Provenance, 2> ByValAllocs;

  // A vector containing yet-to-be resolved provenance values for PHI nodes.
  // The first element in the pair, the provenance "key", consists of a
  // pointer to the PHINode and the index into its provenance.
  SmallVector<std::pair<ProvenanceMap::Key, Provenance>> ProvPHINodes;

  ShadowStackAllocator ShadowStack;

  // An allocation used to store the boundary marker for
  // invoke instructions involving uninstrumented functions.
  AllocaInst *MarkerAlloca = nullptr;

  // Memory intrinsics that have been replaced by a call to the runtime. Their
  // removal is deferred until after checks have been inserted, because each one
  // is the insertion point for the checks guarding its own access.
  SmallVector<MemIntrinsic *, 4> ReplacedMemIntrinsics;

public:
  BorrowSanitizerVisitor(Function &F, BorrowSanitizer &BS,
                         const TargetLibraryInfo &TLI, DominatorTree &DT,
                         const StackSafetyGlobalInfo &SSGI)
      : F(F), BS(BS), C(BS.C), TLI(&TLI), DT(DT), Plan(F, BS.DL, DT, SSGI),
        ProvMap(BS), VAHelper(createVarArgHelper(F, BS, *this)),
        ShadowStack(BS.ProvenanceSize, BS.ProvStackTLS) {}
  bool run() {
    DomTreeUpdater DTU(DT, DomTreeUpdater::UpdateStrategy::Lazy);
    EscapeEnumerator EE(F, "bsan_cleanup", true, &DTU);
    while (IRBuilder<> *AtExit = EE.Next()) {
    }
    DTU.flush();
    Cycles.compute(F);

    Plan.build();

    BasicBlock *EntryBlock = &F.getEntryBlock();
    IRBuilder<> EntryIRB(EntryBlock, EntryBlock->getFirstNonPHIIt());
    initStack(EntryIRB);

    for (Instruction *I : Plan.instructions()) {
      InstVisitor<BorrowSanitizerVisitor>::visit(*I);
    }

    for (const CheckInfo &CI : Plan.checks()) {
      Value *AccessSize = CI.getAccessSize(BS.IntptrTy);
      IRBuilder<> IRB(CI.InsertPt);
      if (CI.AccessKind == CheckInfo::Read) {
        insertReadCheck(IRB, CI.Target, AccessSize);
      } else {
        insertWriteCheck(IRB, CI.Target, AccessSize);
      }
    }

    VAHelper->finalizeInstrumentation();

    for (MemIntrinsic *MI : ReplacedMemIntrinsics)
      MI->eraseFromParent();
    ReplacedMemIntrinsics.clear();

    patchShadowPHINodes();
    ProvMap.patch(DT);
    ShadowStack.patchStackSlots(DT);
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
  /// address
  Value *getShadowPtrOffset(Value *Addr, IRBuilder<> &IRB,
                            MaybeAlign Alignment) {
    Type *IntptrTy = ptrToIntPtrType(Addr->getType());
    Value *OffsetLong = IRB.CreatePointerCast(Addr, IntptrTy);

    Align AddrAlign = Alignment.valueOrOne();
    Align CommonAlign = commonAlignment(AddrAlign, kMinProvAlignment.value());

    if (CommonAlign != kMinProvAlignment) {
      uint64_t Mask = kMinProvAlignment.value() - 1;
      OffsetLong = IRB.CreateAnd(OffsetLong, constToIntPtr(IntptrTy, ~Mask));
    }

    if (uint64_t AndMask = BS.MapParams->AndMask)
      OffsetLong = IRB.CreateAnd(OffsetLong, constToIntPtr(IntptrTy, ~AndMask));

    if (uint64_t XorMask = BS.MapParams->XorMask)
      OffsetLong = IRB.CreateXor(OffsetLong, constToIntPtr(IntptrTy, XorMask));

    return OffsetLong;
  }

  // Returns a destination for a provenance value to be stored within
  // "main" memory, indicating that reference counts will not be
  // updated by the store.
  ProvenanceDest getMainProvenancePtr(IRBuilder<> &IRB, Value *Base) {
    Value *ZeroIdx = ConstantInt::get(IRB.getInt64Ty(), 0);
    Value *TagPtr = Base;
    Value *InfoPtr =
        IRB.CreateGEP(BS.ProvenanceTy, Base,
                      {ZeroIdx, ConstantInt::get(IRB.getInt32Ty(), 1)});
    return ProvenanceDest(TagPtr, InfoPtr, false);
  }

  // Returns a destination for a provenance value to be stored within
  // "shadow" memory. Storing provenance to shadow memory requires
  // updating the reference counts of the value being stored and the
  // value being overwritten.
  ProvenanceDest
  getShadowProvenancePtr(IRBuilder<> &IRB, Value *Addr,
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

    return ProvenanceDest(ShadowPtr, OriginPtr, true);
  }

  Value *newBorrowTag(IRBuilder<> &IRB) {
    return IRB.CreateAtomicRMW(AtomicRMWInst::Add, BS.BorTagCounter,
                               ConstantInt::get(BS.IntptrTy, 1), std::nullopt,
                               AtomicOrdering::Monotonic);
  }

  // Loads a provenance value from shadow memory, storing it into a
  // new slot on the shadow stack.
  Provenance loadProvenanceFromShadow(
      IRBuilder<> &IRB, Value *Base, Align Alignment,
      ElementCount Elems = ElementCount::getFixed(1),
      AtomicOrdering Ordering = AtomicOrdering::NotAtomic) {
    if (Elems.isScalar()) {
      auto ShadowPtr = getShadowProvenancePtr(IRB, Base, Alignment);
      Provenance Prov = loadProvenanceAlignedPairwise(IRB, ShadowPtr, Ordering);
      Value *Slot = allocStackSlot(IRB, false);
      ProvenanceDest SlotPtr = getMainProvenancePtr(IRB, Slot);
      storeProvenance(IRB, SlotPtr, Prov);
      return Prov;
    }
    report_fatal_error("Vectors are not supported.");
  }

  // Loads a provenance value from an already-aligned address in main memory.
  Provenance
  loadProvenanceAligned(IRBuilder<> &IRB, Value *Src,
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
  Provenance assertProvenanceScalar(BasicBlock *BB, ProvenanceMap::Key Key) {
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
                              ProvenanceMap::Key Key) {
    BasicBlock *BB = IRB.GetInsertBlock();
    return assertProvenance(IRB, BB, Elems, Key);
  }

  // Asserts that there is either a provenance value at the given index, or that
  // no provenance values have been loaded for the given value, in which case we
  // return the null provenance value. Used whenever we need a provenance value
  // but do not care whether it's a vector or scalar. Checks for consistency
  // against a given provenance component.
  Provenance assertProvenance(IRBuilder<> &IRB, BasicBlock *BB,
                              ElementCount Elems, ProvenanceMap::Key Key) {
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
  std::optional<Provenance> getProvenance(BasicBlock *BB,
                                          ProvenanceMap::Key Key) {
    if (auto Prov = ProvMap.getProvenance(BB, Key)) {
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
        Value *ByteOffset =
            EntryIRB.CreateMul(BS.ProvenanceSize, ArgProvOffset);
        Value *ArgProvenancePtr = ptradd(EntryIRB, BS.ParamTLS, ByteOffset);
        Provenance ArgProvenance =
            loadProvenanceAligned(EntryIRB, ArgProvenancePtr, Elems);
        ProvMap.setProvenance(Key, ArgProvenance);
        return ArgProvenance;
      }
    }
    return std::nullopt;
  }

  Provenance loadProvenanceAlignedPairwise(IRBuilder<> &IRB, ProvenanceDest Ptr,
                                           AtomicOrdering Ordering) {
    return loadProvenanceAlignedPairwise(IRB, Ptr.ShadowPtr, Ptr.OriginPtr,
                                         Ordering);
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

  void storeProvenance(IRBuilder<> &IRB, ProvenanceDest Dest, Provenance Prov,
                       AtomicOrdering Ordering = AtomicOrdering::NotAtomic) {
    if (Prov.Elems.isVector()) {
      report_fatal_error("Vector provenance is not supported yet");
    }
    if (Dest.UpdateRefCt) {
      // We always need to increment first, in case both the source and
      // destination are the same provenance value. If we decrement the
      // provenance in the destination first, then the garbage collector
      // may see a zero reference count and deinitialize the provenance
      // that we are about to store.
      if (Prov != Provenance::omnivalid(BS)) {
        IRB.CreateCall(BS.BsanFuncRcInc, {Prov.Tag, Prov.Info});
      }
      // We only decrement on nonatomic store. This leaks provenance values that
      // are exposed to atomic operations, which is necessary to support atomics
      // without locking.
      if (Ordering == AtomicOrdering::NotAtomic) {
        Provenance Old = loadProvenanceAlignedPairwise(IRB, Dest, Ordering);
        IRB.CreateCall(BS.BsanFuncRcDec, {Old.Tag, Old.Info});
      }
    }

    IRB.CreateAlignedStore(Prov.Tag, Dest.ShadowPtr, kMinProvAlignment)
        ->setAtomic(Ordering);

    IRB.CreateAlignedStore(Prov.Info, Dest.OriginPtr, kMinProvAlignment)
        ->setAtomic(Ordering);
  }

  // Populates the array of argument provenance pointers and initializes the
  // start and end of the function prologue.
  void initStack(IRBuilder<> &TopIRB) {
    // We use a `donothing` marker to separate the "prologue" of the function
    // from the rest of its body. This creates a dedicated insertion point for
    // instructions that require the shadow stack to be initialized and
    // need to create values that dominate the body of the function.
    FnPrologueEnd = static_cast<Instruction *>(
        TopIRB.CreateIntrinsic(Intrinsic::donothing, {}));
    IRBuilder<> EntryIRB(FnPrologueEnd);

    // We need to compute the total number of provenance values that
    // we receive from the caller before we can load them, which is
    // necessary for boundary validation. We can only load a provenance
    // value once we have ensured that its stack slot is omnivalid
    // if we had an uninstrumented caller.
    Value *NumParamProv = ConstantInt::get(BS.IntptrTy, 0);

    bool Validation = needsBoundaryValidation(&F);
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
        ProvMap.setProvenance(&Arg, Prov);

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
             BS.getProvenanceLayout(EntryIRB, Ty, /*ClearGaps=*/Validation)) {
          Info.Fields.push_back({NumParamProv, Desc});
          Value *NumProv = EntryIRB.CreateElementCount(BS.IntptrTy, Desc.Elems);
          NumParamProv = EntryIRB.CreateAdd(NumParamProv, NumProv);
        }
        ByValArgs.push_back(Info);
      } else {
        SmallVector<ProvenanceField> ProvDesc = BS.getProvenanceLayout(
            EntryIRB, Arg.getType(), /*ClearGaps=*/Validation);
        for (auto &Desc : ProvDesc) {
          ArgumentProvenance[&Arg].push_back({NumParamProv, Desc.Elems});
          Value *NumProv = EntryIRB.CreateElementCount(BS.IntptrTy, Desc.Elems);
          NumParamProv = EntryIRB.CreateAdd(NumParamProv, NumProv);
          // We store the shadow stack offset and width of the provenance for
          // each argument, without eagerly loading it.
        }
      }
    }

    Value *HeaderBottom = ShadowStack.getOrInitFrameHeaderBottom(EntryIRB);

    // We have computed the total number of shadow stack slots that
    // are associated with parameters. Now, if this function could be
    // called from an uninstrumented context, we need to check to see if
    // our boundary marker matches the current function's address. If not,
    // we zero-out all of the parameter shadow stack slots, giving them
    // omnivalid provenance.
    if (needsBoundaryValidation(&F)) {
      if (!BS.shouldTrustFunction(TLI, &F)) {
        uint64_t VarArgSize = F.isVarArg() ? VAHelper->getFixedRegionSize() : 0;
        uint64_t VarArgLen = alignTo(VarArgSize, kMinProvAlignment) / 8;
        Value *VarArgLenVal = ConstantInt::get(BS.IntptrTy, VarArgLen);
        EntryIRB.CreateCall(BS.BsanFuncValidateParams,
                            {&F, NumParamProv, VarArgLenVal});
      }
    }

    // Afterward, we can load the provenance of the byval type,
    // and store it to the shadow memory of the byval pointer.
    for (auto &Info : ByValArgs) {
      SmallVector<std::pair<ProvenanceField, Provenance>> Fields;
      for (auto &[SlotOffset, Desc] : Info.Fields) {
        Value *ByteOffset = EntryIRB.CreateMul(BS.ProvenanceSize, SlotOffset);
        Value *ProvPtr = ptradd(EntryIRB, BS.ParamTLS, ByteOffset);
        Provenance Prov = loadProvenanceAligned(EntryIRB, ProvPtr, Desc.Elems);
        Fields.push_back({Desc, Prov});
      }

      ProvenanceDest ShadowPtr =
          getShadowProvenancePtr(EntryIRB, Info.Arg, Info.Alignment);
      copyProvenance(EntryIRB, ShadowPtr, Fields, Info.Size,
                     AtomicOrdering::NotAtomic);

      Value *Slot = ShadowStack.getStackAllocSlot(EntryIRB);
      auto SlotPtr = getMainProvenancePtr(EntryIRB, Slot);
      storeProvenance(EntryIRB, SlotPtr, Info.AllocProv);
    }

    // We push additional slots into the frame header for
    // static allocas.
    for (auto [Idx, AI] : llvm::enumerate(Plan.allocas())) {
      NextNodeIRBuilder IRB(AI);
      Value *Slot = ShadowStack.getStackAllocSlot(EntryIRB);
      Provenance Prov;
      if (!Plan.hasLifetimeStart(AI)) {
        Prov = createAllocaMetadata(EntryIRB);
        initAllocaMetadata(IRB, AI, Prov);
        ProvMap.setProvenance(AI, Prov);
      } else {
        Value *Info = EntryIRB.CreateCall(BS.BsanFuncReserveStackSlot, {});
        Value *InitialTag = ConstantInt::get(BS.IntptrTy, 1);
        Prov = Provenance(InitialTag, Info);
        ProvMap.cacheAllocaProvenance(EntryIRB, AI, Prov);
      }
      auto SlotPtr = getMainProvenancePtr(EntryIRB, Slot);
      storeProvenance(EntryIRB, SlotPtr, Prov);
      if (Plan.hasLifetimeStart(AI)) {
        AllocaFrameSlots[AI] = SlotPtr;
      }
    }

    // We also need a dedicated region of the shadow stack
    // for function-entry retags. The total number of function
    // entry retags is variable, because they can happen across
    // different branches. This is Rust-specific behavior.
    ShadowStack.allocateFnEntryRegion(EntryIRB, Plan.getNumFnEntryRetags());

    // We have initialized the frame header, but we have not updated
    // the frame pointer to reflect it.
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
    Align OperandAlign = Operand->getPointerAlignment(*BS.DL);
    Value *SrcAddr = IRB.CreateAlignedLoad(BS.PtrTy, Operand, OperandAlign);
    Provenance SrcProv = loadProvenanceFromShadow(IRB, Operand, OperandAlign);

    RetagInfo RI(&CB);
    Value *ImArrayLen = getLayoutArrayLength(RI.ImArray);
    Value *PinArrayLen = getLayoutArrayLength(RI.PinArray);
    Value *Slot = allocStackSlot(IRB, RI.isProtected());
    IRB.CreateCall(BS.BsanFuncRetag,
                   {SrcAddr, RI.Size, RI.Perms, RI.ImArray, ImArrayLen,
                    RI.PinArray, PinArrayLen, SrcProv.Tag, SrcProv.Info, Slot,
                    IRB.getInt1(false)});
    Provenance RetaggedProv = loadProvenanceAligned(IRB, Slot);

    auto ShadowPtr = getShadowProvenancePtr(IRB, Operand, OperandAlign);
    storeProvenance(IRB, ShadowPtr, RetaggedProv);
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
      ProvMap.setProvenance(&CB, loadProvenanceAligned(IRB, Dest));
    }
  }

  Value *bumpStackSlot(IRBuilder<> &IRB, bool IsFnEntry,
                       ElementCount Elems = ElementCount::getFixed(1)) {
    return ShadowStack.bumpStackSlot(Cycles, IRB, IsFnEntry, Elems);
  }

  Value *allocStackSlot(IRBuilder<> &IRB, bool IsFnEntry,
                        ElementCount Elems = ElementCount::getFixed(1)) {
    return ShadowStack.allocStackSlot(Cycles, IRB, IsFnEntry, Elems);
  }

  Value *getStackOffset(IRBuilder<> &IRB, bool IsFnEntry) {
    return ShadowStack.getStackPtr(Cycles, IRB, IsFnEntry);
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

    // We store the provenance for each argument into thread-local arrays.
    // First, we calculate where each fixed parameter's provenance is stored.
    Value *NumParamProv = ConstantInt::get(BS.IntptrTy, 0);

    bool Clear = needsBoundaryValidation(Callee);
    SmallVector<std::pair<Value *, Provenance>> ParamOffsets;
    for (const auto &[i, Arg] : llvm::enumerate(CB.args())) {
      // Variadics have special handling.
      bool IsFixed = i < CB.getFunctionType()->getNumParams();
      if (!IsFixed)
        break;

      bool IsByVal = CB.paramHasAttr(i, Attribute::ByVal);
      Type *ArgTy = IsByVal ? CB.getParamByValType(i) : Arg->getType();

      SmallVector<ProvenanceField> ProvDesc =
          BS.getProvenanceLayout(Before, ArgTy, /*ClearGaps=*/Clear);

      for (const auto &[Idx, Desc] : llvm::enumerate(ProvDesc)) {

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

        Value *NumProv = Before.CreateElementCount(BS.IntptrTy, Desc.Elems);
        NumParamProv = Before.CreateAdd(NumParamProv, NumProv);
      }
    }

    if (CB.getFunctionType()->isVarArg()) {
      VAHelper->visitCallBase(CB, Before);
    }

    if (CB.isMustTailCall()) {
      // We need to pop the current frame, since
      // the semantics of a tail call are equivalent
      // to a return and then another call.
      popFrame(Before, CB, nullptr);
    }

    // If we have parameter provenance, then store it to the TLS array.
    if (ShadowStack.getFrameHeaderTop().has_value()) {
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
    }

    for (auto [ByteOffset, Prov] : ParamOffsets) {
      Value *Slot = ptradd(Before, BS.ParamTLS, ByteOffset);
      auto SlotPtr = getMainProvenancePtr(Before, Slot);
      storeProvenance(Before, SlotPtr, Prov);
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
        BasicBlock *Src = II->getParent();
        BasicBlock *Dst = II->getNormalDest();
        BasicBlock *NewBB = SplitEdge(Src, Dst, &DT);
        Cycles.splitCriticalEdge(Src, Dst, NewBB);
        NextInst = &NewBB->front();
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
        BS.getProvenanceLayout(Before, CB.getType());

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
    if (needsBoundaryValidation(Callee)) {
      Value *Marker;
      Value *NullPtr = ConstantPointerNull::get(BS.PtrTy);
      // If this is a function that we can trust (e.g. an allocator)
      // then we write 1 into the boundary marker. This "magic value"
      // indicates to subsequent callees that they can trust that their
      // caller was instrumented. This is necessary for Rust's allocator
      // shims (e.g. `__rust_alloc`) which are thin wrappers around the
      // `__rdl_alloc` family of functions. The wrapper shims are left
      // uninstrumented when we run this pass through Rust's LLVM plugin
      // hooks, so they will clear provenance unless we skip boundary
      // validation.
      // FIXME: Figure out why these functions are skipped over.
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
      Provenance Prov = loadProvenanceAligned(After, Ptr, Elems);
      ProvMap.setProvenance({&CB, Idx}, Prov);
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
          BS.getProvenanceLayout(IRB, Operand->getType());
      for (const auto &[Idx, Comp] : llvm::enumerate(Components)) {
        ProvMap.setProvenance({Operand, Idx}, Provenance::omnivalid(BS));
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
        BS.getProvenanceLayout(IRB, PN.getType());
    for (auto [Idx, Comp] : llvm::enumerate(Components)) {
      Provenance Prov =
          createProvenancePHI(IRB, Comp, predecessors(PN.getParent()));
      ProvMap.setProvenance({&PN, Idx}, Prov);
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
      IRBuilder<> IRB(&II);
      Value *Tag = newBorrowTag(IRB);
      Provenance StartProv = ProvMap.updateTag(IRB, AI, Tag);
      initAllocaMetadata(IRB, AI, StartProv);
      auto SlotIt = AllocaFrameSlots.find(AI);
      if (SlotIt != AllocaFrameSlots.end()) {
        storeProvenance(IRB, SlotIt->second, StartProv);
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
    NextNodeIRBuilder IRB(&I);
    Value *Val = IRB.CreateIntCast(I.getValue(), IRB.getInt32Ty(), false);
    Value *Size = IRB.CreateIntCast(I.getLength(), BS.IntptrTy, false);
    IRB.CreateCall(BS.BsanFuncMemSet, {I.getDest(), Val, Size});
    ReplacedMemIntrinsics.push_back(&I);
  }

  void visitMemMoveInst(MemMoveInst &I) {
    NextNodeIRBuilder IRB(&I);
    Value *Size = IRB.CreateIntCast(I.getLength(), BS.IntptrTy, false);
    IRB.CreateCall(BS.BsanFuncMemMove, {I.getDest(), I.getSource(), Size});
    ReplacedMemIntrinsics.push_back(&I);
  }

  void visitMemCpyInst(MemCpyInst &I) {
    NextNodeIRBuilder IRB(&I);
    Value *Size = IRB.CreateIntCast(I.getLength(), BS.IntptrTy, false);
    IRB.CreateCall(BS.BsanFuncMemCpy, {I.getDest(), I.getSource(), Size});
    ReplacedMemIntrinsics.push_back(&I);
  }

  void visitVAStartInst(VAStartInst &I) { VAHelper->visitVAStartInst(I); }

  void visitVACopyInst(VACopyInst &I) { VAHelper->visitVACopyInst(I); }

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

    SmallVector<ProvenanceField> Components =
        BS.getProvenanceLayout(IRB, LI.getType());

    Value *Base = LI.getPointerOperand();
    for (const auto &[Idx, Comp] : llvm::enumerate(Components)) {
      Value *ByteOffset = Comp.ByteOffset;
      Value *ObjAddr = ptradd(IRB, Base, ByteOffset);
      Align FieldAlign =
          commonAlignment(LI.getAlign(), Comp.FieldAlign.value());
      Provenance Prov = loadProvenanceFromShadow(IRB, ObjAddr, FieldAlign,
                                                 Comp.Elems, LI.getOrdering());
      ProvMap.setProvenance({&LI, Idx}, Prov);
    }
  }

  void visitStoreInst(StoreInst &SI) {
    Value *Ptr, *Val;
    Ptr = SI.getPointerOperand();
    Val = SI.getValueOperand();

    // In addition to propagating provenance, we also need to clear provenance
    // from memory locations that are clobbered by non-pointer stores.
    // This is necessary for accurate reference counting and to
    // make sure that pointers that are cast from integers via load / store
    // type punning receive omnivalid provenance.
    NextNodeIRBuilder AfterIRB(&SI);
    ProvenanceDest ShadowPtr =
        getShadowProvenancePtr(AfterIRB, Ptr, SI.getAlign());
    copyProvenance(AfterIRB, ShadowPtr, Val, SI.getOrdering());
  }

  void copyProvenance(IRBuilder<> &IRB, ProvenanceDest Dest, Value *Val,
                      AtomicOrdering Ordering = AtomicOrdering::NotAtomic) {
    Type *Ty = Val->getType();

    SmallVector<std::pair<ProvenanceField, Provenance>> FieldValues;
    SmallVector<ProvenanceField> Fields = BS.getProvenanceLayout(IRB, Ty);

    for (const auto &[Idx, Desc] : llvm::enumerate(Fields)) {
      Provenance Prov = assertProvenance(IRB, Desc.Elems, {Val, Idx});
      FieldValues.push_back({Desc, Prov});
    }

    TypeSize StoreSize = BS.DL->getTypeStoreSize(Ty);
    Value *TotalSize = IRB.CreateTypeSize(BS.IntptrTy, StoreSize);

    copyProvenance(IRB, Dest, FieldValues, TotalSize, Ordering);
  }

  void copyProvenance(IRBuilder<> &IRB, ProvenanceDest Dest,
                      ArrayRef<std::pair<ProvenanceField, Provenance>> ProvDesc,
                      Value *TotalSize,
                      AtomicOrdering Ordering = AtomicOrdering::NotAtomic) {

    Value *Cursor = ConstantInt::get(BS.IntptrTy, 0);
    SmallVector<std::tuple<ProvenanceOffset, ProvenanceOffset>> SlotsToClear;

    // We are given an address that is aligned to the size of a provenance
    // value, but the size of the type that we are storing might not be aligned.

    Align FieldAlign = kMinProvAlignment;

    for (const auto &[Desc, Prov] : ProvDesc) {

      FieldAlign = commonAlignment(Desc.FieldAlign, kMinProvAlignment.value());

      if (Cursor != Desc.ByteOffset) {
        // There is a gap between provenance values within the layout
        // of the type
        Value *GapSize = IRB.CreateSub(Desc.ByteOffset, Cursor);
        ProvenanceOffset GapSizeRounded;

        if (FieldAlign == kMinProvAlignment) {
          // The field is already slot aligned. It will be
          // disjoint from the slots covered by the gap.
          GapSizeRounded = ProvenanceOffset::alignUp(IRB, GapSize);
        } else {
          // The field covers two slots, so we round down. Otherwise,
          // when we store the next field, we will write to the same
          // slot that we just cleared!
          GapSizeRounded = ProvenanceOffset::alignDown(IRB, GapSize);
        }

        auto GapStart = ProvenanceOffset::alignDown(IRB, Cursor);

        if (!match(GapSize, m_Zero()))
          SlotsToClear.push_back(std::make_tuple(GapStart, GapSize));
      }

      auto AlignedOffset = ProvenanceOffset::alignDown(IRB, Desc.ByteOffset);
      auto ObjAddr = Dest.ptradd(IRB, AlignedOffset);
      storeProvenance(IRB, ObjAddr, Prov, Ordering);

      Cursor = IRB.CreateNUWAdd(Desc.ByteOffset, Desc.ByteWidth);
    }

    // When we are in the middle of a type, we round the gap size down,
    // to avoid clearing a slot that will be immediately overwritten by
    // the next field. At this point, there are no other fields. We can
    // clear everything from the current cursor onward.
    auto FinalGapStart = ProvenanceOffset::alignDown(IRB, Cursor);
    auto FinalGapSize =
        ProvenanceOffset::alignUp(IRB, IRB.CreateSub(TotalSize, Cursor));

    if (!match(FinalGapSize.Val, m_Zero()))
      SlotsToClear.push_back(std::make_tuple(FinalGapStart, FinalGapSize));

    for (auto &[Offset, GapSize] : SlotsToClear) {
      ProvenanceDest BaseAddr = Dest.ptradd(IRB, Offset);
      clearProvenance(IRB, BaseAddr, GapSize, Ordering);
    }
  }

  void clearProvenance(IRBuilder<> &IRB, ProvenanceDest Dest,
                       ProvenanceOffset Size,
                       AtomicOrdering Ordering = AtomicOrdering::NotAtomic) {
    const uint64_t SlotSize = kMinProvAlignment.value();
    const uint64_t MaxInlineSlots = 4;
    if (auto *CI = dyn_cast<ConstantInt>(Size.Val)) {
      uint64_t Bytes = CI->getZExtValue();
      if (Bytes == 0)
        return;
      uint64_t NumSlots = Bytes / SlotSize;
      if (NumSlots <= MaxInlineSlots) {
        for (uint64_t I = 0; I < NumSlots; ++I) {
          ProvenanceOffset SlotOffset(BS.IntptrTy, I * SlotSize);
          ProvenanceDest SlotPtr = Dest.ptradd(IRB, SlotOffset);
          storeProvenance(IRB, SlotPtr, Provenance::omnivalid(BS), Ordering);
        }
        return;
      }
    }

    if (Dest.UpdateRefCt) {
      IRB.CreateCall(BS.BsanFuncShadowClearAligned,
                     {Dest.ShadowPtr, Dest.OriginPtr, Size.Val});

    } else {
      // We only need to clear tag values, since they gate the validity
      // of a provenance value.
      IRB.CreateMemSet(Dest.ShadowPtr,
                       ConstantInt::getNullValue(IRB.getInt8Ty()), Size.Val,
                       kMinProvAlignment);
    }
  }

  void visitGetElementPtrInst(GetElementPtrInst &I) {
    ProvMap.forwardProvenance(&I, I.getPointerOperand());
  }

  void visitPtrToIntInst(PtrToIntInst &I) {
    if (auto Prov = getProvenance(I.getParent(), I.getPointerOperand())) {
      IRBuilder<> IRB(&I);
      IRB.CreateCall(BS.BsanFuncExposeProv, {(*Prov).Tag, (*Prov).Info});
    }
  }

  void visitIntToPtrInst(IntToPtrInst &I) {
    ProvMap.setProvenance(&I, Provenance::wildcard(BS));
  }

  void visitAddrSpaceCastInst(AddrSpaceCastInst &I) {
    // Address space casts do not affect provenance. As with GEPs, we
    // forward lazily rather than snapshotting -- see visitGetElementPtrInst.
    ProvMap.forwardProvenance(&I, I.getPointerOperand());
  }

  void visitBitCastInst(BitCastInst &I) {
    // Bitcasts propagate provenance, forwarded lazily -- see
    // visitGetElementPtrInst.
    // TODO: The arguments to a bitcast are never aggregates, but they can
    // be vectors, which we do not support yet.
    Value *Src = I.getOperand(0);
    if (Src->getType()->isPointerTy() && I.getType()->isPointerTy()) {
      ProvMap.forwardProvenance(&I, Src);
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
            BS.getProvenanceLayout(IRB, ElemType);
        Offset += ProvDesc.size();
      }
      return {ST->getElementType(Idx), Offset};
    }

    if (auto *AT = dyn_cast<ArrayType>(Ty)) {
      SmallVector<ProvenanceField> ProvDesc =
          BS.getProvenanceLayout(IRB, AT->getElementType());
      return {AT->getElementType(), ProvDesc.size() * Idx};
    }

    report_fatal_error("Cannot index into a non-struct or non-array type.");
  }

  void visitExtractValueInst(ExtractValueInst &EI) {
    IRBuilder<> IRB(&EI);
    Value *AggregateSrc = EI.getAggregateOperand();

    SmallVector<ProvenanceField> DestProvDesc =
        BS.getProvenanceLayout(IRB, EI.getType());

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
        ProvMap.setProvenance({&EI, Offset}, *Prov);
      }
    }
  }

  void visitInsertValueInst(InsertValueInst &II) {
    IRBuilder<> IRB(&II);
    ProvMap.transfer(II.getAggregateOperand(), &II);
    Value *ToInsert = II.getInsertedValueOperand();
    SmallVector<ProvenanceField> SrcProvDesc =
        BS.getProvenanceLayout(IRB, ToInsert->getType());

    Type *CurrType = II.getType();
    uint64_t StartIdx = 0;
    for (auto &Idx : II.indices()) {
      unsigned IdxOffset = 0;
      std::tie(CurrType, IdxOffset) = getProvenanceOffset(IRB, CurrType, Idx);
      StartIdx += IdxOffset;
    }

    for (auto [Offset, Desc] : llvm::enumerate(SrcProvDesc)) {
      if (auto Prov = getProvenance(IRB.GetInsertBlock(), {ToInsert, Offset})) {
        ProvMap.setProvenance({&II, StartIdx + Offset}, *Prov);
      }
    }
  }

  void visitSelectInst(SelectInst &SI) {
    IRBuilder<> IRB(&SI);
    SmallVector<ProvenanceField> ProvDesc =
        BS.getProvenanceLayout(IRB, SI.getType());

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
        ProvMap.setProvenance({&SI, Idx}, Provenance(Tag, Info));
      }
    }
  }

  void popFrame(IRBuilder<> &IRB, Instruction &I, Value *RetVal) {
    BasicBlock *BB = IRB.GetInsertBlock();
    if (ShadowStack.wasUsed()) {
      Value *NumStackAllocs =
          ShadowStack.getNumStackAllocSlots(IRB, BS.IntptrTy);
      Value *NumProtectors =
          ShadowStack.getOutgoingOffset(Cycles, IRB, BS.IntptrTy, true);
      Value *MaxNumProtectors =
          ConstantInt::get(BS.IntptrTy, Plan.getNumFnEntryRetags());

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
          BS.getProvenanceLayout(IRB, RetVal->getType());
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
          auto MainPtr = getMainProvenancePtr(IRB, Ptr);
          Provenance Prov =
              assertProvenance(IRB, ProvDesc[Idx].Elems, {RetVal, Idx});
          storeProvenance(IRB, MainPtr, Prov);
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

// Our variadic handling is a direct port from
// MemorySanitizer. All architecture-specific
// decisions, and the overall design, is derived
// from MemorySanitizer. However, unlike MemorySanitizer,
// we always copy the "origin" values, because provenance
// is two words. See `VarArgAMD64Helper` for more documentation
// on the procedure used here. It is a much more representative
struct VarArgHelperBase : public VarArgHelper {
  Function &F;
  BorrowSanitizer &BS;
  BorrowSanitizerVisitor &BSV;
  SmallVector<CallInst *, 16> VAStartInstrumentationList;
  const unsigned VAListTagSize;

  VarArgHelperBase(Function &F, BorrowSanitizer &BS,
                   BorrowSanitizerVisitor &BSV, unsigned VAListTagSize)
      : F(F), BS(BS), BSV(BSV), VAListTagSize(VAListTagSize) {}

  std::pair<Value *, Value *>
  getShadowOriginAddrForVAArgument(IRBuilder<> &IRB, unsigned ArgOffset) {
    unsigned ArgOffsetAligned = alignTo(ArgOffset, kMinProvAlignment);
    Value *TagBase = IRB.CreatePointerCast(BS.VAArgTagTLS, BS.IntptrTy);
    Value *InfoBase = IRB.CreatePointerCast(BS.VAArgInfoTLS, BS.IntptrTy);
    Value *TagAddr =
        IRB.CreateAdd(TagBase, ConstantInt::get(BS.IntptrTy, ArgOffsetAligned));
    Value *InfoAddr = IRB.CreateAdd(
        InfoBase, ConstantInt::get(BS.IntptrTy, ArgOffsetAligned));
    return {TagAddr, InfoAddr};
  }

  ProvenanceDest getShadowPtrForVAArgument(IRBuilder<> &IRB,
                                           unsigned ArgOffset) {
    ProvenanceDest Base(BS.VAArgTagTLS, BS.VAArgInfoTLS, false);
    return Base.ptradd(IRB, ProvenanceOffset(BS.IntptrTy, ArgOffset));
  }

  /// Compute the shadow address for a given va_arg.
  ProvenanceDest getShadowPtrForVAArgument(IRBuilder<> &IRB, unsigned ArgOffset,
                                           unsigned ArgSize) {
    // Make sure we don't overflow __msan_va_arg_tls.
    assert(ArgOffset + ArgSize <= kVarArgTLSSizeBytes);
    return getShadowPtrForVAArgument(IRB, ArgOffset);
  }

  void cleanUnusedTLS(IRBuilder<> &IRB, ProvenanceDest Ptr,
                      unsigned BaseOffset) {
    // The tails of `__msan_va_arg_tls` is not large enough to fit full
    // value shadow, but it will be copied to backup anyway. Make it clean.
    if (BaseOffset >= kVarArgTLSSizeBytes)
      return;

    Value *TailSize = ConstantInt::getSigned(IRB.getInt32Ty(),
                                             kVarArgTLSSizeBytes - BaseOffset);

    // We can use memset here because we are clearing TLS. Any provenance
    // is rooted elsewhere on the shadow stack.
    IRB.CreateMemSet(Ptr.ShadowPtr, ConstantInt::getNullValue(IRB.getInt8Ty()),
                     TailSize, Align(8));
    IRB.CreateMemSet(Ptr.OriginPtr, ConstantInt::getNullValue(IRB.getInt8Ty()),
                     TailSize, Align(8));
  }

  void clearVAListTagForInst(IntrinsicInst &I) {
    IRBuilder<> IRB(&I);
    Value *VAListTag = I.getArgOperand(0);

    ProvenanceOffset Offset(BS.IntptrTy, VAListTagSize);
    ProvenanceDest Shadow = BSV.getShadowProvenancePtr(IRB, VAListTag);
    // Here, we're clearing shadow, so we need to adjust reference counts.
    BSV.clearProvenance(IRB, Shadow, Offset, AtomicOrdering::NotAtomic);
  }

  void visitVAStartInst(VAStartInst &I) override {
    if (F.getCallingConv() == CallingConv::Win64)
      return;
    VAStartInstrumentationList.push_back(&I);
    clearVAListTagForInst(I);
  }

  void visitVACopyInst(VACopyInst &I) override {
    if (F.getCallingConv() == CallingConv::Win64)
      return;
    clearVAListTagForInst(I);
  }
};

struct VarArgAMD64Helper : public VarArgHelperBase {
  // An unfortunate workaround for asymmetric lowering of va_arg stuff.
  // See a comment in visitCallBase for more details.
  static const unsigned kAMD64GpEndOffset = 48; // AMD64 ABI Draft 0.99.6 p3.5.7
  static const unsigned kAMD64FpEndOffsetSSE = 176;
  // If SSE is disabled, fp_offset in va_list is zero.
  static const unsigned kAMD64FpEndOffsetNoSSE = kAMD64GpEndOffset;

  // On AMD64 platforms, variadic arguments are passed into two
  // regions of memory. The first region has a statically known size,
  // which is computed into `AMD64FpEndOffset` below. The second
  // region is adjacent, and holds any "overflow" beyond the static region.
  // It has a dynamic size.
  unsigned AMD64FpEndOffset;
  AllocaInst *VAArgTLSTagCopy = nullptr;
  AllocaInst *VAArgTLSInfoCopy = nullptr;
  Value *VAArgOverflowSize = nullptr;

  enum ArgKind { AK_GeneralPurpose, AK_FloatingPoint, AK_Memory };

  VarArgAMD64Helper(Function &F, BorrowSanitizer &BS,
                    BorrowSanitizerVisitor &BSV)
      : VarArgHelperBase(F, BS, BSV, /*VAListTagSize=*/24) {
    AMD64FpEndOffset = kAMD64FpEndOffsetSSE;
    for (const auto &Attr : F.getAttributes().getFnAttrs()) {
      if (Attr.isStringAttribute() &&
          (Attr.getKindAsString() == "target-features")) {
        if (Attr.getValueAsString().contains("-sse"))
          AMD64FpEndOffset = kAMD64FpEndOffsetNoSSE;
        break;
      }
    }
  }

  uint64_t getFixedRegionSize() override { return AMD64FpEndOffset; }

  ArgKind classifyArgument(Value *Arg) {
    // A very rough approximation of X86_64 argument classification rules.
    Type *T = Arg->getType();
    if (T->isX86_FP80Ty())
      return AK_Memory;
    if (T->isFPOrFPVectorTy())
      return AK_FloatingPoint;
    if (T->isIntegerTy() && T->getPrimitiveSizeInBits() <= 64)
      return AK_GeneralPurpose;
    if (T->isPointerTy())
      return AK_GeneralPurpose;
    return AK_Memory;
  }

  // For VarArg functions, store the argument shadow in an ABI-specific format
  // that corresponds to `va_list` layout.
  // We do this because Clang lowers `va_arg` in the frontend, and this pass
  // only sees the low level code that deals with `va_list` internals.
  void visitCallBase(CallBase &CB, IRBuilder<> &IRB) override {
    unsigned GpOffset = 0;
    unsigned FpOffset = kAMD64GpEndOffset;
    unsigned OverflowOffset = AMD64FpEndOffset;
    const DataLayout &DL = F.getDataLayout();

    // We preemptively clear the fixed section of the variadic array.
    // If there is any disagreement between this emulated instrumentation
    // and how values are copied in practice, then we want to have false
    // negatives, not false positives. Overflow is already cleared.
    IRB.CreateMemSet(BS.VAArgTagTLS, Constant::getNullValue(IRB.getInt8Ty()),
                     ConstantInt::get(IRB.getInt32Ty(), AMD64FpEndOffset),
                     kMinProvAlignment);

    for (const auto &[ArgNo, A] : llvm::enumerate(CB.args())) {
      bool IsFixed = ArgNo < CB.getFunctionType()->getNumParams();
      bool IsByVal = CB.paramHasAttr(ArgNo, Attribute::ByVal);
      if (IsByVal) {
        // ByVal arguments always go to the overflow area.
        // Fixed arguments passed through the overflow area will be
        // stepped over by `va_start`, so don't count them towards the offset.
        if (IsFixed)
          continue;
        assert(A->getType()->isPointerTy());
        Type *RealTy = CB.getParamByValType(ArgNo);
        uint64_t ArgSize = DL.getTypeAllocSize(RealTy);
        uint64_t AlignedSize = alignTo(ArgSize, 8);
        unsigned BaseOffset = OverflowOffset;
        ProvenanceDest DestPtr = getShadowPtrForVAArgument(IRB, OverflowOffset);
        OverflowOffset += AlignedSize;

        if (OverflowOffset > kVarArgTLSSizeBytes) {
          cleanUnusedTLS(IRB, DestPtr, BaseOffset);
          continue; // We have no space to copy shadow there.
        }

        ProvenanceDest SrcPtr =
            BSV.getShadowProvenancePtr(IRB, A, kMinProvAlignment);

        // We are copying provenance into the variadic TLS array. Any provenance
        // value within a TLS array is rooted somewhere else on the shadow
        // stack, so we do not need to adjust reference counts.
        IRB.CreateMemCpy(DestPtr.ShadowPtr, kMinProvAlignment, SrcPtr.ShadowPtr,
                         kMinProvAlignment, ArgSize);
        IRB.CreateMemCpy(DestPtr.OriginPtr, kMinProvAlignment, SrcPtr.OriginPtr,
                         kMinProvAlignment, ArgSize);

      } else {
        ArgKind AK = classifyArgument(A);
        if (AK == AK_GeneralPurpose && GpOffset >= kAMD64GpEndOffset)
          AK = AK_Memory;
        if (AK == AK_FloatingPoint && FpOffset >= AMD64FpEndOffset)
          AK = AK_Memory;
        ProvenanceDest Ptr;
        unsigned Offset = 0;

        switch (AK) {
        case AK_GeneralPurpose:
          Offset = GpOffset;
          GpOffset += 8;
          assert(GpOffset <= kVarArgTLSSizeBytes);
          break;
        case AK_FloatingPoint:
          Offset = FpOffset;
          FpOffset += 16;
          assert(FpOffset <= kVarArgTLSSizeBytes);
          break;
        case AK_Memory:
          if (IsFixed)
            continue;

          uint64_t ArgSize = DL.getTypeAllocSize(A->getType());
          uint64_t AlignedSize = alignTo(ArgSize, kMinProvAlignment);
          unsigned BaseOffset = OverflowOffset;
          Offset = OverflowOffset;
          OverflowOffset += AlignedSize;
          if (OverflowOffset > kVarArgTLSSizeBytes) {
            Ptr = getShadowPtrForVAArgument(IRB, Offset);
            // We have no space to copy shadow there.
            cleanUnusedTLS(IRB, Ptr, BaseOffset);
            continue;
          }
        }
        if (IsFixed)
          continue;
        Ptr = getShadowPtrForVAArgument(IRB, Offset);
        BSV.copyProvenance(IRB, Ptr, A);
      }
    }
    Constant *OverflowSize =
        ConstantInt::get(IRB.getInt64Ty(), OverflowOffset - AMD64FpEndOffset);
    IRB.CreateStore(OverflowSize, BS.VAArgOverflowSizeTLS);
  }

  void finalizeInstrumentation() override {
    assert(!VAArgOverflowSize && !VAArgTLSTagCopy &&
           "finalizeInstrumentation called twice");
    if (!VAStartInstrumentationList.empty()) {
      // If there is a va_start in this function, then make a backup
      // copy of `va_arg_tls` within the function entry block.
      IRBuilder<> IRB(BSV.FnPrologueEnd);
      VAArgOverflowSize = IRB.CreateLoad(BS.IntptrTy, BS.VAArgOverflowSizeTLS);

      Value *CopySize = IRB.CreateAdd(
          ConstantInt::get(BS.IntptrTy, AMD64FpEndOffset), VAArgOverflowSize);

      VAArgTLSTagCopy = IRB.CreateAlloca(Type::getInt8Ty(*BS.C), CopySize);
      VAArgTLSTagCopy->setAlignment(kMinProvAlignment);

      VAArgTLSInfoCopy = IRB.CreateAlloca(Type::getInt8Ty(*BS.C), CopySize);
      VAArgTLSInfoCopy->setAlignment(kMinProvAlignment);

      Value *SrcSize = IRB.CreateBinaryIntrinsic(
          Intrinsic::umin, CopySize,
          ConstantInt::get(BS.IntptrTy, kVarArgTLSSizeBytes));

      // This is an exceedingly rare situation: we are copying shadow
      // values into main memory that isn't TLS. We do not need to increment
      // the reference counts of the provenance values that we are storing,
      // because they originate from anchored TLS. We can also skip decrementing
      // reference counts for the values being overwritten. This may leak
      // provenance, depending on how the stack is used in subsequent
      // instructions, but it is not necessary for soundness.
      IRB.CreateMemCpy(VAArgTLSTagCopy, kMinProvAlignment, BS.VAArgTagTLS,
                       kMinProvAlignment, SrcSize);
      IRB.CreateMemCpy(VAArgTLSInfoCopy, kMinProvAlignment, BS.VAArgInfoTLS,
                       kMinProvAlignment, SrcSize);
    }

    // Instrument `va_start`.
    // Copy `va_list` shadow from the backup copy of the TLS contents.
    for (CallInst *OrigInst : VAStartInstrumentationList) {
      NextNodeIRBuilder IRB(OrigInst);
      Value *VAListTag = OrigInst->getArgOperand(0);
      Value *RegSaveAreaPtrPtr =
          IRB.CreatePtrAdd(VAListTag, ConstantInt::get(BS.IntptrTy, 16));
      Value *RegSaveAreaPtr = IRB.CreateLoad(BS.PtrTy, RegSaveAreaPtrPtr);

      Value *RegSaveSize = ConstantInt::get(BS.IntptrTy, AMD64FpEndOffset);
      IRB.CreateCall(BS.BsanFuncShadowJoin, {RegSaveAreaPtr, VAArgTLSTagCopy,
                                             VAArgTLSInfoCopy, RegSaveSize});

      Value *OverflowArgAreaPtrPtr =
          IRB.CreatePtrAdd(VAListTag, ConstantInt::get(BS.IntptrTy, 8));
      Value *OverflowArgAreaPtr =
          IRB.CreateLoad(BS.PtrTy, OverflowArgAreaPtrPtr);

      Value *TagOverflowPtr = IRB.CreateConstGEP1_32(
          IRB.getInt8Ty(), VAArgTLSTagCopy, AMD64FpEndOffset);
      Value *InfoOverflowPtr = IRB.CreateConstGEP1_32(
          IRB.getInt8Ty(), VAArgTLSInfoCopy, AMD64FpEndOffset);

      IRB.CreateCall(BS.BsanFuncShadowJoin,
                     {OverflowArgAreaPtr, TagOverflowPtr, InfoOverflowPtr,
                      VAArgOverflowSize});
    }
  }
};

struct VarArgAArch64Helper : public VarArgHelperBase {
  static const unsigned kAArch64GrArgSize = 64;
  static const unsigned kAArch64VrArgSize = 128;

  static const unsigned kAArch64GrBegOffset = 0;
  static const unsigned kAArch64GrEndOffset = kAArch64GrArgSize;
  // Make VR space aligned to 16 bytes.
  static const unsigned kAArch64VrBegOffset = kAArch64GrEndOffset;
  static const unsigned kAArch64VrEndOffset =
      kAArch64VrBegOffset + kAArch64VrArgSize;
  static const unsigned kAArch64VAEndOffset = kAArch64VrEndOffset;

  AllocaInst *VAArgTLSTagCopy = nullptr;
  AllocaInst *VAArgTLSInfoCopy = nullptr;

  Value *VAArgOverflowSize = nullptr;

  enum ArgKind { AK_GeneralPurpose, AK_FloatingPoint, AK_Memory };

  VarArgAArch64Helper(Function &F, BorrowSanitizer &BS,
                      BorrowSanitizerVisitor &BSV)
      : VarArgHelperBase(F, BS, BSV, /*VAListTagSize=*/32) {}

  uint64_t getFixedRegionSize() override { return kAArch64VAEndOffset; }

  // A very rough approximation of aarch64 argument classification rules.
  std::pair<ArgKind, uint64_t> classifyArgument(Type *T) {
    if (T->isIntOrPtrTy() && T->getPrimitiveSizeInBits() <= 64)
      return {AK_GeneralPurpose, 1};
    if (T->isFloatingPointTy() && T->getPrimitiveSizeInBits() <= 128)
      return {AK_FloatingPoint, 1};

    if (T->isArrayTy()) {
      auto R = classifyArgument(T->getArrayElementType());
      R.second *= T->getScalarType()->getArrayNumElements();
      return R;
    }

    if (const FixedVectorType *FV = dyn_cast<FixedVectorType>(T)) {
      auto R = classifyArgument(FV->getScalarType());
      R.second *= FV->getNumElements();
      return R;
    }

    return {AK_Memory, 0};
  }

  // Retrieve a va_list field of 'void*' size.
  Value *getVAField64(IRBuilder<> &IRB, Value *VAListTag, int Offset) {
    Value *SaveAreaPtrPtr =
        IRB.CreatePtrAdd(VAListTag, ConstantInt::get(BS.IntptrTy, Offset));
    return IRB.CreateLoad(Type::getInt64Ty(*BS.C), SaveAreaPtrPtr);
  }

  // Retrieve a va_list field of 'int' size.
  Value *getVAField32(IRBuilder<> &IRB, Value *VAListTag, int Offset) {
    Value *SaveAreaPtr =
        IRB.CreatePtrAdd(VAListTag, ConstantInt::get(BS.IntptrTy, Offset));
    Value *SaveArea32 = IRB.CreateLoad(IRB.getInt32Ty(), SaveAreaPtr);
    return IRB.CreateSExt(SaveArea32, BS.IntptrTy);
  }

  // The instrumentation stores the argument shadow in a non ABI-specific
  // format because it does not know which argument is named (since Clang,
  // like x86_64 case, lowers the va_args in the frontend and this pass only
  // sees the low level code that deals with va_list internals).
  // The first seven GR registers are saved in the first 56 bytes of the
  // va_arg tls array, followed by the first 8 FP/SIMD registers, and then
  // the remaining arguments.
  // Using constant offset within the va_arg TLS array allows fast copy
  // in the finalize instrumentation.
  void visitCallBase(CallBase &CB, IRBuilder<> &IRB) override {
    unsigned GrOffset = kAArch64GrBegOffset;
    unsigned VrOffset = kAArch64VrBegOffset;
    unsigned OverflowOffset = kAArch64VAEndOffset;

    IRB.CreateMemSet(BS.VAArgTagTLS, Constant::getNullValue(IRB.getInt8Ty()),
                     ConstantInt::get(IRB.getInt32Ty(), kAArch64VAEndOffset),
                     kMinProvAlignment);

    const DataLayout &DL = F.getDataLayout();
    for (const auto &[ArgNo, A] : llvm::enumerate(CB.args())) {
      bool IsFixed = ArgNo < CB.getFunctionType()->getNumParams();

      auto [AK, RegNum] = classifyArgument(A->getType());
      if (AK == AK_GeneralPurpose &&
          (GrOffset + RegNum * 8) > kAArch64GrEndOffset)
        AK = AK_Memory;
      if (AK == AK_FloatingPoint &&
          (VrOffset + RegNum * 16) > kAArch64VrEndOffset)
        AK = AK_Memory;

      unsigned Offset;
      switch (AK) {
      case AK_GeneralPurpose:
        Offset = GrOffset;
        GrOffset += 8 * RegNum;
        break;
      case AK_FloatingPoint:
        Offset = VrOffset;
        VrOffset += 16 * RegNum;
        break;
      case AK_Memory:
        // Don't count fixed arguments in the overflow area - va_start will
        // skip right over them.
        if (IsFixed)
          continue;
        uint64_t ArgSize = DL.getTypeAllocSize(A->getType());
        uint64_t AlignedSize = alignTo(ArgSize, 8);
        unsigned BaseOffset = OverflowOffset;
        Offset = BaseOffset;
        OverflowOffset += AlignedSize;
        if (OverflowOffset > kVarArgTLSSizeBytes) {
          auto Base = getShadowPtrForVAArgument(IRB, BaseOffset);
          // We have no space to copy shadow there.
          cleanUnusedTLS(IRB, Base, BaseOffset);
          continue;
        }
        break;
      }
      // Count Gp/Vr fixed arguments to their respective offsets, but don't
      // bother to actually store a shadow.
      if (IsFixed)
        continue;

      auto Ptr = getShadowPtrForVAArgument(IRB, Offset);
      BSV.copyProvenance(IRB, Ptr, A);
    }
    Constant *OverflowSize = ConstantInt::get(
        IRB.getInt64Ty(), OverflowOffset - kAArch64VAEndOffset);
    IRB.CreateStore(OverflowSize, BS.VAArgOverflowSizeTLS);
  }

  void finalizeInstrumentation() override {
    assert(!VAArgOverflowSize && !VAArgTLSInfoCopy &&
           "finalizeInstrumentation called twice");

    if (!VAStartInstrumentationList.empty()) {
      // If there is a va_start in this function, make a backup copy of
      // va_arg_tls somewhere in the function entry block.
      IRBuilder<> IRB(BSV.FnPrologueEnd);

      VAArgOverflowSize =
          IRB.CreateLoad(IRB.getInt64Ty(), BS.VAArgOverflowSizeTLS);

      Value *CopySize =
          IRB.CreateAdd(ConstantInt::get(BS.IntptrTy, kAArch64VAEndOffset),
                        VAArgOverflowSize);

      VAArgTLSTagCopy = IRB.CreateAlloca(Type::getInt8Ty(*BS.C), CopySize);
      VAArgTLSTagCopy->setAlignment(kMinProvAlignment);

      VAArgTLSInfoCopy = IRB.CreateAlloca(Type::getInt8Ty(*BS.C), CopySize);
      VAArgTLSInfoCopy->setAlignment(kMinProvAlignment);

      Value *SrcSize = IRB.CreateBinaryIntrinsic(
          Intrinsic::umin, CopySize,
          ConstantInt::get(BS.IntptrTy, kVarArgTLSSizeBytes));

      IRB.CreateMemCpy(VAArgTLSTagCopy, kMinProvAlignment, BS.VAArgTagTLS,
                       kMinProvAlignment, SrcSize);

      IRB.CreateMemCpy(VAArgTLSInfoCopy, kMinProvAlignment, BS.VAArgInfoTLS,
                       kMinProvAlignment, SrcSize);
    }

    Value *GrArgSize = ConstantInt::get(BS.IntptrTy, kAArch64GrArgSize);
    Value *VrArgSize = ConstantInt::get(BS.IntptrTy, kAArch64VrArgSize);

    // Instrument va_start, copy va_list shadow from the backup copy of
    // the TLS contents.
    for (CallInst *OrigInst : VAStartInstrumentationList) {
      NextNodeIRBuilder IRB(OrigInst);

      Value *VAListTag = OrigInst->getArgOperand(0);

      // The variadic ABI for AArch64 creates two areas to save the incoming
      // argument registers (one for 64-bit general register xn-x7 and another
      // for 128-bit FP/SIMD vn-v7).
      // We need then to propagate the shadow arguments on both regions
      // 'va::__gr_top + va::__gr_offs' and 'va::__vr_top + va::__vr_offs'.
      // The remaining arguments are saved on shadow for 'va::stack'.
      // One caveat is it requires only to propagate the non-named arguments,
      // however on the call site instrumentation 'all' the arguments are
      // saved. So to copy the shadow values from the va_arg TLS array
      // we need to adjust the offset for both GR and VR fields based on
      // the __{gr,vr}_offs value (since they are stores based on incoming
      // named arguments).
      Type *RegSaveAreaPtrTy = IRB.getPtrTy();

      // Read the stack pointer from the va_list.
      Value *StackSaveAreaPtr =
          IRB.CreateIntToPtr(getVAField64(IRB, VAListTag, 0), RegSaveAreaPtrTy);

      // Read both the __gr_top and __gr_off and add them up.
      Value *GrTopSaveAreaPtr = getVAField64(IRB, VAListTag, 8);
      Value *GrOffSaveArea = getVAField32(IRB, VAListTag, 24);

      Value *GrRegSaveAreaPtr = IRB.CreateIntToPtr(
          IRB.CreateAdd(GrTopSaveAreaPtr, GrOffSaveArea), RegSaveAreaPtrTy);

      // Read both the __vr_top and __vr_off and add them up.
      Value *VrTopSaveAreaPtr = getVAField64(IRB, VAListTag, 16);
      Value *VrOffSaveArea = getVAField32(IRB, VAListTag, 28);

      Value *VrRegSaveAreaPtr = IRB.CreateIntToPtr(
          IRB.CreateAdd(VrTopSaveAreaPtr, VrOffSaveArea), RegSaveAreaPtrTy);

      // It does not know how many named arguments is being used and, on the
      // callsite all the arguments were saved.  Since __gr_off is defined as
      // '0 - ((8 - named_gr) * 8)', the idea is to just propagate the variadic
      // argument by ignoring the bytes of shadow from named arguments.
      Value *GrRegSaveAreaShadowPtrOff =
          IRB.CreateAdd(GrArgSize, GrOffSaveArea);

      Value *GrSrcTagPtr =
          IRB.CreateInBoundsPtrAdd(VAArgTLSTagCopy, GrRegSaveAreaShadowPtrOff);
      Value *GrSrcInfoPtr =
          IRB.CreateInBoundsPtrAdd(VAArgTLSInfoCopy, GrRegSaveAreaShadowPtrOff);

      Value *GrCopySize = IRB.CreateSub(GrArgSize, GrRegSaveAreaShadowPtrOff);

      IRB.CreateCall(BS.BsanFuncShadowJoin,
                     {GrRegSaveAreaPtr, GrSrcTagPtr, GrSrcInfoPtr, GrCopySize});

      // Again, but for FP/SIMD values.
      Value *VrRegSaveAreaShadowPtrOff =
          IRB.CreateAdd(VrArgSize, VrOffSaveArea);

      Value *VrTagSrcPtr = IRB.CreateInBoundsPtrAdd(
          IRB.CreateInBoundsPtrAdd(VAArgTLSTagCopy,
                                   IRB.getInt32(kAArch64VrBegOffset)),
          VrRegSaveAreaShadowPtrOff);

      Value *VrInfoSrcPtr = IRB.CreateInBoundsPtrAdd(
          IRB.CreateInBoundsPtrAdd(VAArgTLSInfoCopy,
                                   IRB.getInt32(kAArch64VrBegOffset)),
          VrRegSaveAreaShadowPtrOff);

      Value *VrCopySize = IRB.CreateSub(VrArgSize, VrRegSaveAreaShadowPtrOff);

      IRB.CreateCall(BS.BsanFuncShadowJoin,
                     {VrRegSaveAreaPtr, VrTagSrcPtr, VrInfoSrcPtr, VrCopySize});

      Value *StackTagSrcPtr = IRB.CreateInBoundsPtrAdd(
          VAArgTLSTagCopy, IRB.getInt32(kAArch64VAEndOffset));

      Value *StackInfoSrcPtr = IRB.CreateInBoundsPtrAdd(
          VAArgTLSTagCopy, IRB.getInt32(kAArch64VAEndOffset));

      IRB.CreateCall(BS.BsanFuncShadowJoin,
                     {StackSaveAreaPtr, StackTagSrcPtr, StackInfoSrcPtr,
                      VAArgOverflowSize});
    }
  }
};

/// A no-op implementation of VarArgHelper.
struct VarArgNoOpHelper : public VarArgHelper {
  VarArgNoOpHelper(Function &F, BorrowSanitizer &BS,
                   BorrowSanitizerVisitor &BSV) {}

  void visitCallBase(CallBase &CB, IRBuilder<> &IRB) override {}

  void visitVAStartInst(VAStartInst &I) override {}

  void visitVACopyInst(VACopyInst &I) override {}

  void finalizeInstrumentation() override {}

  uint64_t getFixedRegionSize() override { return 0; }
};

} // end anonymous namespace

static VarArgHelper *createVarArgHelper(Function &Func, BorrowSanitizer &BS,
                                        BorrowSanitizerVisitor &BSV) {

  if (ClInstrumentVariadics) {
    // VarArg handling is only implemented on AMD64 and aarch64.
    Triple TargetTriple(Func.getParent()->getTargetTriple());

    if (TargetTriple.getArch() == Triple::x86_64)
      return new VarArgAMD64Helper(Func, BS, BSV);

    if (TargetTriple.isAArch64())
      return new VarArgAArch64Helper(Func, BS, BSV);
  }
  return new VarArgNoOpHelper(Func, BS, BSV);
}

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
