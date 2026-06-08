#include "BorrowSanitizerPass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Plugins/PassPlugin.h"

using namespace llvm;

static llvm::PassPluginLibraryInfo getBorrowSanitizerPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "BorrowSanitizer", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback([](ModulePassManager &MPM,
                                                  OptimizationLevel Level,
                                                  ThinOrFullLTOPhase Phase) {
              switch (Phase) {
              case ThinOrFullLTOPhase::FullLTOPreLink:
              case ThinOrFullLTOPhase::ThinLTOPreLink:
              case ThinOrFullLTOPhase::None: {
                MPM.addPass(BorrowSanitizerPass(BorrowSanitizerOptions()));
              } break;
              default:
                break;
              }
            });
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
