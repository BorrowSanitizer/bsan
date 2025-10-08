#ifndef BORROWSANITIZER_DECLARATIONS
#define BORROWSANITIZER_DECLARATIONS

#define BSAN_PREFIX "__bsan_"
#define RUST_SHIM_PREFIX "__rust_"

#define BSAN_FN(name) BSAN_PREFIX name
#define BSAN_DEBUG_PREFIX BSAN_FN("debug_")

#define BSAN_DEBUG_FN(name) BSAN_DEBUG_PREFIX name
#define RUST_SHIM_FN(name) RUST_SHIM_PREFIX name

const char kBsanModuleCtorName[] = "bsan.module_ctor";
const char kBsanModuleDtorName[] = "bsan.module_dtor";

const char kBsanPrefix[] = BSAN_FN();
const char kBsanRetagPrefix[] = BSAN_FN("retag_");
const char kBsanIntrinsicRetagPlaceName[] = BSAN_FN("retag_place");
const char kBsanIntrinsicRetagOperandName[] = BSAN_FN("retag_operand");

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
const char kBsanFuncAllocStack[] = BSAN_FN("alloc_stack");

const char kBsanFuncNewBorrowTagName[] = BSAN_FN("new_tag");
const char kBsanFuncNewAllocIDName[] = BSAN_FN("new_alloc_id");
const char kBsanFuncDeallocName[] = BSAN_FN("dealloc");
const char kBsanFuncDeallocWeakName[] = BSAN_FN("dealloc_weak");
const char kBsanFuncExposeTagName[] = BSAN_FN("expose_tag");
const char kBsanFuncReadName[] = BSAN_FN("read");
const char kBsanFuncWriteName[] = BSAN_FN("write");

const char kBsanDebugPrefix[] = BSAN_DEBUG_FN();

const char kBsanFuncAssertProvenanceNull[] = BSAN_DEBUG_FN("assert_null");
const char kBsanFuncAssertProvenanceWildcard[] =
    BSAN_DEBUG_FN("assert_wildcard");
const char kBsanFuncAssertProvenanceValid[] = BSAN_DEBUG_FN("assert_valid");
const char kBsanFuncAssertProvenanceInvalid[] = BSAN_DEBUG_FN("assert_invalid");
const char kBsanFuncDebugPrint[] = BSAN_DEBUG_FN("print");
const char kBsanFuncDebugParamTLS[] = BSAN_DEBUG_FN("param_tls");
const char kBsanFuncDebugRetvalTLS[] = BSAN_DEBUG_FN("retval_tls");

const char kBsanParamTLSName[] = "__BSAN_PARAM_TLS";
const char kBsanRetvalTLSName[] = "__BSAN_RETVAL_TLS";
const char kBsanBorTagCounterName[] = "__BSAN_BOR_TAG_CTR";
const char kBsanAllocIdCounterName[] = "__BSAN_ALLOC_ID_CTR";

static const unsigned kTLSSize = 100;

const char *kRustAllocFns[] = {
    RUST_SHIM_FN("alloc"),
    RUST_SHIM_FN("dealloc"),
    RUST_SHIM_FN("realloc"),
    RUST_SHIM_FN("alloc_zeroed"),
};

#endif // BORROWSANITIZER_DECLARATIONS