
#ifndef BSAN_TAINT_ANALYSIS_H
#define BSAN_TAINT_ANALYSIS_H

#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/Support/Compiler.h"
#include <memory>

namespace llvm {

class CallBase;
class Function;
class MDNode;
class MemoryLocation;

class TaintAAResult : public AAResultBase {

public:
  TaintAAResult() {}
  /// Handle invalidation events from the new pass manager.
  ///
  /// By definition, this result is stateless and so remains valid.
  bool invalidate(Function &, const PreservedAnalyses &,
                  FunctionAnalysisManager::Invalidator &) {
    return false;
  }

  LLVM_ABI AliasResult alias(const MemoryLocation &LocA,
                             const MemoryLocation &LocB, AAQueryInfo &AAQI,
                             const Instruction *CtxI);
  LLVM_ABI AliasResult aliasErrno(const MemoryLocation &Loc, const Module *M);
  LLVM_ABI ModRefInfo getModRefInfoMask(const MemoryLocation &Loc,
                                        AAQueryInfo &AAQI, bool IgnoreLocals);

  LLVM_ABI MemoryEffects getMemoryEffects(const CallBase *Call,
                                          AAQueryInfo &AAQI);
  LLVM_ABI MemoryEffects getMemoryEffects(const Function *F);
  using AAResultBase::getModRefInfo;
  LLVM_ABI ModRefInfo getModRefInfo(const CallBase *Call,
                                    const MemoryLocation &Loc,
                                    AAQueryInfo &AAQI);
  LLVM_ABI ModRefInfo getModRefInfo(const CallBase *Call1,
                                    const CallBase *Call2, AAQueryInfo &AAQI);

private:
  bool Aliases(const MDNode *A, const MDNode *B) const;

  /// Returns true if TBAA metadata should be used, that is if TBAA is enabled
  /// and type sanitizer is not used.
  bool shouldUseTBAA() const;
};

/// Analysis pass providing a never-invalidated alias analysis result.
class TaintAA : public AnalysisInfoMixin<TaintAA> {
  friend AnalysisInfoMixin<TaintAA>;

  LLVM_ABI static AnalysisKey Key;

public:
  using Result = TaintAAResult;

  LLVM_ABI TaintAAResult run(Function &F, FunctionAnalysisManager &AM);
};

/// Legacy wrapper pass to provide the TypeBasedAAResult object.
class LLVM_ABI TaintAAWrapperPass : public ImmutablePass {
  std::unique_ptr<TaintAAResult> Result;

public:
  static char ID;

  TaintAAWrapperPass();

  TaintAAResult &getResult() { return *Result; }
  const TaintAAResult &getResult() const { return *Result; }

  bool doInitialization(Module &M) override;
  bool doFinalization(Module &M) override;
  void getAnalysisUsage(AnalysisUsage &AU) const override;
};

LLVM_ABI ImmutablePass *createTaintAAWrapperPass();

} // end namespace llvm

#endif // BSAN_TAINT_ANALYSIS_H