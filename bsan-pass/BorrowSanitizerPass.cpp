#include "BorrowSanitizerPass.h"
#include "BorrowSanitizer.h"
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

PreservedAnalyses BorrowSanitizerPass::run(Module &M,
                                           ModuleAnalysisManager &MAM) {
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
  // GlobalsAA is considered stateless and does not get invalidated unless
  // explicitly invalidated; PreservedAnalyses::none() is not enough. Sanitizers
  // make changes that require GlobalsAA to be invalidated.
  PA.abandon<GlobalsAA>();
  return PA;
}

static llvm::PassPluginLibraryInfo getBorrowSanitizerPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "BorrowSanitizer", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "bsan") {
                    MPM.addPass(BorrowSanitizerPass(BorrowSanitizerOptions()));
                    return true;
                  }
                  return false;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getBorrowSanitizerPluginInfo();
}
