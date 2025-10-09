#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_BORROWSANITIZER_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_BORROWSANITIZER_H

#include "Provenance.h"
#include "llvm/Analysis/StackSafetyAnalysis.h"
#include "llvm/Analysis/TargetLibraryInfo.h"

namespace llvm {

struct BorrowSanitizer {
public:
  BorrowSanitizer(Module &M, ModuleAnalysisManager &MAM) {
    C = &(M.getContext());
    DL = &M.getDataLayout();
    TargetTriple = Triple(M.getTargetTriple());

    PL = ProvenanceLayout(C, DL);
    LongSize = M.getDataLayout().getPointerSizeInBits();

    Int8Ty = Type::getInt8Ty(*C);
    Int16Ty = Type::getInt16Ty(*C);
    Int64Ty = Type::getInt64Ty(*C);
    PtrTy = PointerType::getUnqual(*C);
    IntptrTy = Type::getIntNTy(*C, LongSize);

    ProvenanceTy = StructType::get(IntptrTy, IntptrTy, PtrTy);
    ProvenanceAlign = DL->getABITypeAlign(ProvenanceTy);
    ProvenanceSize = ConstantInt::get(IntptrTy, kProvenanceSize);

    Zero = ConstantInt::get(IntptrTy, 0);
    One = ConstantInt::get(IntptrTy, 1);

    True = ConstantInt::get(Int8Ty, 1);
    False = ConstantInt::get(Int8Ty, 0);

    Constant *InvalidPtr = ConstantPointerNull::get(PtrTy);

    WildcardProvenance = ProvenanceScalar(Zero, Zero, InvalidPtr);
    InvalidProvenance = ProvenanceScalar(One, Zero, InvalidPtr);
  }

  bool instrumentModule(Module &M);
  bool instrumentFunction(Function &F, FunctionAnalysisManager &FAM);

  void initializeCallbacks(Module &M, const TargetLibraryInfo &TLI);
  void instrumentGlobals(IRBuilder<> &IRB, Module &M, bool *CtorComdat);
  Instruction *createBsanModuleDtor(Module &M);

  // Adds thread-local global variables for passing the provenance for
  // arguments and return values
  void createUserspaceApi(Module &M, const TargetLibraryInfo &TLI);

  TypeSize getAllocaSizeInBytes(const AllocaInst &AI) const {
    return *AI.getAllocationSize(AI.getDataLayout());
  }

  LLVMContext *C;
  const DataLayout *DL;
  ProvenanceLayout PL;
  const StackSafetyGlobalInfo *const SSGI = nullptr;

  int LongSize;
  Triple TargetTriple;
  Type *Int8Ty;
  Type *Int16Ty;
  Type *Int64Ty;
  PointerType *PtrTy;

  Type *IntptrTy;
  Align IntptrAlign;

  StructType *ProvenanceTy;
  Align ProvenanceAlign;
  Value *ProvenanceSize;

  bool CallbacksInitialized = false;

  Function *BsanCtorFunction = nullptr;
  Function *BsanDtorFunction = nullptr;

  FunctionCallee BsanFuncRetag;
  FunctionCallee BsanFuncShadowCopy;
  FunctionCallee BsanFuncShadowClear;
  FunctionCallee BsanFuncGetShadowSrc;
  FunctionCallee BsanFuncGetShadowDest;

  FunctionCallee BsanFuncReserveStackSlot;
  FunctionCallee BsanFuncAllocStack;

  FunctionCallee BsanFuncPushAllocaFrame;
  FunctionCallee BsanFuncPushRetagFrame;

  FunctionCallee BsanFuncPopAllocaFrame;
  FunctionCallee BsanFuncPopRetagFrame;

  FunctionCallee BsanFuncAlloc;
  FunctionCallee BsanFuncDealloc;
  FunctionCallee BsanFuncDeallocWeak;
  FunctionCallee BsanFuncExposeTag;
  FunctionCallee BsanFuncRead;
  FunctionCallee BsanFuncWrite;

  FunctionCallee BsanFuncShadowLoadVector;
  FunctionCallee BsanFuncShadowStoreVector;

  FunctionCallee BsanFuncAssertProvenanceInvalid;
  FunctionCallee BsanFuncAssertProvenanceValid;
  FunctionCallee BsanFuncAssertProvenanceNull;
  FunctionCallee BsanFuncAssertProvenanceWildcard;
  FunctionCallee BsanFuncDebugPrint;

  FunctionCallee BsanFuncDebugParamTLS;
  FunctionCallee BsanFuncDebugRetvalTLS;

  FunctionCallee DefaultPersonalityFn;

  ProvenanceScalar WildcardProvenance;
  ProvenanceScalar InvalidProvenance;

  // Thread-local storage for paramters
  // and return values.
  Value *ParamTLS = nullptr;
  Value *RetvalTLS = nullptr;
  Value *AllocIdCounter = nullptr;
  Value *BorTagCounter = nullptr;

  Constant *Zero = nullptr;
  Constant *One = nullptr;

  Constant *True = nullptr;
  Constant *False = nullptr;
};

} // namespace llvm

#endif // LLVM_TRANSFORMS_INSTRUMENTATION_BORROWSANITIZER_H