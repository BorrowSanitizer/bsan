#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_BORROWSANITIZER_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_BORROWSANITIZER_H

#include "Provenance.h"
#include "llvm/IR/PassManager.h"

namespace llvm {

const char kBsanPrefix[] = "__bsan_";
const char kBsanModuleCtorName[] = "bsan.module_ctor";
const char kBsanModuleDtorName[] = "bsan.module_dtor";
const char kBsanFuncInitName[] = "__bsan_init";
const char kBsanFuncDeinitName[] = "__bsan_deinit";
const char kBsanFuncPushFrameName[] = "__bsan_push_frame";
const char kBsanFuncPopFrameName[] = "__bsan_pop_frame";
const char kBsanFuncShadowCopyName[] = "__bsan_shadow_clear";
const char kBsanFuncShadowClearName[] = "__bsan_shadow_copy";
const char kBsanFuncGetShadowDestName[] = "__bsan_get_shadow_dest";
const char kBsanFuncGetShadowSrcName[] = "__bsan_get_shadow_src";
const char kBsanFuncJoinProvName[] = "__bsan_join_provenance";
const char kBsanFuncSplitProvName[] = "__bsan_split_provenance";
const char kBsanFuncShadowLoadArrayName[] = "__bsan_shadow_load_array";
const char kBsanFuncShadowLoadVectorName[] = "__bsan_shadow_load_vector";
const char kBsanFuncShadowStoreArrayName[] = "__bsan_shadow_store_array";
const char kBsanFuncShadowStoreVectorName[] = "__bsan_shadow_store_vector";
const char kBsanFuncRetagName[] = "__bsan_retag";
const char kBsanFuncAllocName[] = "__bsan_alloc";
const char kBsanFuncNewBorrowTagName[] = "__bsan_new_tag";
const char kBsanFuncNewAllocIDName[] = "__bsan_new_alloc_id";
const char kBsanFuncDeallocName[] = "__bsan_dealloc";
const char kBsanFuncExposeTagName[] = "__bsan_expose_tag";
const char kBsanFuncReadName[] = "__bsan_read";
const char kBsanFuncWriteName[] = "__bsan_write";

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