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

    BoolTy = Type::getInt1Ty(*C);
    Int8Ty = Type::getInt8Ty(*C);
    Int16Ty = Type::getInt16Ty(*C);
    Int32Ty = Type::getInt32Ty(*C);
    Int64Ty = Type::getInt64Ty(*C);
    PtrTy = PointerType::getUnqual(*C);
    IntptrTy = Type::getIntNTy(*C, LongSize);

    Zero = ConstantInt::get(IntptrTy, 0);
    One = ConstantInt::get(IntptrTy, 1);

    True = ConstantInt::get(Int8Ty, 1);
    False = ConstantInt::get(Int8Ty, 0);

    Constant *InvalidPtr = ConstantPointerNull::get(PtrTy);

    WildcardProvenance = ProvenanceScalar(Zero, InvalidPtr);
    InvalidProvenance = ProvenanceScalar(One, InvalidPtr);
  }

  bool instrumentModule(Module &M);
  bool instrumentFunction(Function &F, FunctionAnalysisManager &FAM);

  void initializeCallbacks(Module &M, const TargetLibraryInfo &TLI);

  struct GlobalDescription {
    bool ShouldInstrument;
    std::optional<Function *> AssocFn;
  };
  GlobalDescription getGlobalDescription(GlobalVariable *G) const;

  void instrumentGlobals(IRBuilder<> &IRB, Module &M, bool CtorComdat);
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
  Type *BoolTy;
  Type *Int8Ty;
  Type *Int16Ty;
  Type *Int32Ty;
  Type *Int64Ty;
  PointerType *PtrTy;

  Type *IntptrTy;
  Align IntptrAlign;

  bool CallbacksInitialized = false;

  Function *BsanCtorFunction = nullptr;
  Function *BsanDtorFunction = nullptr;

  FunctionCallee BsanFuncRetag;
  FunctionCallee BsanFuncRead;
  FunctionCallee BsanFuncWrite;
  FunctionCallee BsanFuncAllocStack;
  FunctionCallee BsanFuncDeallocStack;

  FunctionCallee BsanFuncPopFrame;

  FunctionCallee BsanFuncMarkTLS;
  FunctionCallee BsanFuncValidateRetvalTLS;
  FunctionCallee BsanFuncValidateParamTLS;

  FunctionCallee BsanFuncGetShadowSrc;
  FunctionCallee BsanFuncGetShadowDest;

  FunctionCallee BsanFuncMemSet;
  FunctionCallee BsanFuncMemMove;
  FunctionCallee BsanFuncMemCpy;

  FunctionCallee BsanFuncReserveStackSlot;
  FunctionCallee BsanFuncDestroyStackSlot;

  FunctionCallee BsanFuncAssertProvenanceNull;
  FunctionCallee BsanFuncAssertProvenanceWildcard;
  FunctionCallee BsanFuncAssertProvenanceValid;
  FunctionCallee BsanFuncAssertProvenanceInvalid;

  FunctionCallee BsanFuncDebugPrint;
  FunctionCallee BsanFuncDebugPrintBorrowState;
  FunctionCallee BsanFuncDebugTreeSize;
  FunctionCallee BsanFuncDebugSnapshot;
  FunctionCallee BsanFuncDebugPrintDiff;

  FunctionCallee DefaultPersonalityFn;

  ProvenanceScalar WildcardProvenance;
  ProvenanceScalar InvalidProvenance;
  // Thread-local storage for paramters
  // and return values.
  Value *ParamTLS = nullptr;
  Value *RetvalTLS = nullptr;
  Value *ProvStack = nullptr;
  Value *TrustFlag = nullptr;
  Value *AllocIdCounter = nullptr;
  Value *BorTagCounter = nullptr;

  Constant *Zero = nullptr;
  Constant *One = nullptr;

  Constant *True = nullptr;
  Constant *False = nullptr;

  DenseSet<Function *> ExternCalledFns;
};

} // namespace llvm

#endif // LLVM_TRANSFORMS_INSTRUMENTATION_BORROWSANITIZER_H
