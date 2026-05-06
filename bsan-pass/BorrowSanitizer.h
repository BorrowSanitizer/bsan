#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_BORROWSANITIZER_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_BORROWSANITIZER_H

#include "Provenance.h"
#include "llvm/Analysis/TargetLibraryInfo.h"

namespace llvm {

struct BorrowSanitizer {
public:
  BorrowSanitizer(Module &M, ModuleAnalysisManager &MAM) {
    C = &(M.getContext());
    DL = &M.getDataLayout();
    TargetTriple = Triple(M.getTargetTriple());

    PL = ProvenanceLayout(C, DL);
    PtrTy = PointerType::getUnqual(*C);
    unsigned PtrSize = M.getDataLayout().getPointerSize();
    IntptrTy = Type::getIntNTy(*C, PtrSize * 8);
    Zero = ConstantInt::get(IntptrTy, 0);
    One = ConstantInt::get(IntptrTy, 1);
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

  LLVMContext *C;
  const DataLayout *DL;
  ProvenanceLayout PL;

  Triple TargetTriple;
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

  FunctionCallee BsanFuncMark;
  FunctionCallee BsanFuncValidateRetval;
  FunctionCallee BsanFuncValidateParams;

  FunctionCallee BsanFuncShadowLoad;
  FunctionCallee BsanFuncShadowStore;

  FunctionCallee BsanFuncMemSet;
  FunctionCallee BsanFuncMemMove;
  FunctionCallee BsanFuncMemCpy;
  FunctionCallee BsanFuncShadowClear;

  FunctionCallee BsanFuncReserveStackSlot;
  FunctionCallee BsanFuncDestroyStackSlot;

  FunctionCallee DefaultPersonalityFn;

  // Thread-local storage for paramters
  // and return values.
  Value *ProvStack = nullptr;
  Value *Marker = nullptr;
  Value *BorTagCounter = nullptr;

  Constant *Zero = nullptr;
  Constant *One = nullptr;

  bool shouldTrustFunction(const TargetLibraryInfo *TLI, const Value *V);
  bool shouldInstrumentAlloca(const DataLayout &DL, const AllocaInst &AI);
  bool needsBoundaryValidation(const Function *Callee);
};

} // namespace llvm

#endif // LLVM_TRANSFORMS_INSTRUMENTATION_BORROWSANITIZER_H