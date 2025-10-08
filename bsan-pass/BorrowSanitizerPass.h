#ifndef BORROWSANITIZER_PASS_H
#define BORROWSANITIZER_PASS_H

#include "llvm/IR/PassManager.h"
#include "llvm/Support/CommandLine.h"

namespace llvm {

struct BorrowSanitizerOptions {
  BorrowSanitizerOptions(){};
};

struct BorrowSanitizerPass : public PassInfoMixin<BorrowSanitizerPass> {
  BorrowSanitizerPass(BorrowSanitizerOptions Options) : Options(Options) {}

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
  static bool isRequired() { return true; }

private:
  BorrowSanitizerOptions Options;
};

} // namespace llvm

#endif // BORROWSANITIZER_PASS_H