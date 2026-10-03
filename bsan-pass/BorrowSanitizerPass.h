#ifndef BORROWSANITIZER_PASS_H
#define BORROWSANITIZER_PASS_H

#include "llvm/IR/PassManager.h"
#include "llvm/Support/CommandLine.h"

namespace llvm {

struct BorrowSanitizerOptions {
  BorrowSanitizerOptions() {};
};

struct BorrowSanitizerPass : public PassInfoMixin<BorrowSanitizerPass> {
  BorrowSanitizerPass(BorrowSanitizerOptions Options) : Options(Options) {}

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
  static bool isRequired() { return true; }

private:
  BorrowSanitizerOptions Options;
};

// Marks BorrowSanitizer's retag intrinsics as `nomerge`. This needs to run at
// the start of the pipeline, before SimplifyCFG has a chance to merge retags
// that have different permissions.
//
// This is a temporary fix until `nomerge` semantics are upstreamed to rustc.
struct BorrowSanitizerNoMergeRetagsPass
    : public PassInfoMixin<BorrowSanitizerNoMergeRetagsPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
  static bool isRequired() { return true; }
};

} // namespace llvm

#endif // BORROWSANITIZER_PASS_H
