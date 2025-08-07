#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_BORROWSANITIZER_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_BORROWSANITIZER_H

#include "Provenance.h"
#include "llvm/IR/PassManager.h"

namespace llvm {

const char kBsanModuleCtorName[] = "bsan.module_ctor";
const char kBsanModuleDtorName[] = "bsan.module_dtor";

#define BSAN_PREFIX "__bsan_"
#define BSAN_FN(name) BSAN_PREFIX name

const char kBsanPrefix[] = BSAN_FN();

const char kBsanFuncInitName[] = BSAN_FN("init");
const char kBsanFuncDeinitName[] = BSAN_FN("deinit");

const char kBsanFuncPushAllocaFrameName[] = BSAN_FN("push_alloca_frame");
const char kBsanFuncPushRetagFrameName[] = BSAN_FN("push_retag_frame");

const char kBsanFuncPopAllocaFrameName[] = BSAN_FN("pop_alloca_frame");
const char kBsanFuncPopRetagFrameName[] = BSAN_FN("pop_retag_frame");

const char kBsanFuncShadowCopyName[] = BSAN_FN("shadow_copy");
const char kBsanFuncShadowClearName[] = BSAN_FN("shadow_clear");

const char kBsanFuncGetShadowDestName[] = BSAN_FN("shadow_dest");
const char kBsanFuncGetShadowSrcName[] = BSAN_FN("shadow_src");

const char kBsanFuncShadowLoadVectorName[] = BSAN_FN("shadow_load_vector");
const char kBsanFuncShadowStoreVectorName[] = BSAN_FN("shadow_store_vector");

const char kBsanFuncRetagName[] = BSAN_FN("retag");
const char kBsanFuncAllocName[] = BSAN_FN("alloc");

const char kBsanFuncReserveStackSlotName[] = BSAN_FN("reserve_stack_slot");
const char kBsanFuncAllocInPlace[] = BSAN_FN("alloc_in_place");

const char kBsanFuncNewBorrowTagName[] = BSAN_FN("new_tag");
const char kBsanFuncNewAllocIDName[] = BSAN_FN("new_alloc_id");
const char kBsanFuncDeallocName[] = BSAN_FN("dealloc");
const char kBsanFuncExposeTagName[] = BSAN_FN("expose_tag");
const char kBsanFuncReadName[] = BSAN_FN("read");
const char kBsanFuncWriteName[] = BSAN_FN("write");


// Helper functions for debugging and testing.
#define BSAN_DEBUG_PREFIX BSAN_FN("debug_")
#define BSAN_DEBUG_FN(name) BSAN_DEBUG_PREFIX name

const char kBsanDebugPrefix[] = BSAN_DEBUG_FN();

const char kBsanFuncAssertProvenanceNull[] = BSAN_DEBUG_FN("assert_null");
const char kBsanFuncAssertProvenanceWildcard[] = BSAN_DEBUG_FN("assert_wildcard");
const char kBsanFuncAssertProvenanceValid[] = BSAN_DEBUG_FN("assert_valid");
const char kBsanFuncAssertProvenanceInvalid[] = BSAN_DEBUG_FN("assert_invalid");
const char kBsanFuncDebugPrint[] = BSAN_DEBUG_FN("print");

const char kBsanParamTLSName[] = "__BSAN_PARAM_TLS";
const char kBsanRetvalTLSName[] = "__BSAN_RETVAL_TLS";

static const unsigned kTLSSize = 100;

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

#endif // LLVM_TRANSFORMS_INSTRUMENTATION_BORROWSANITIZER_H