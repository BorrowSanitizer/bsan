#ifndef BORROWSANITIZER_DECLARATIONS
#define BORROWSANITIZER_DECLARATIONS

#define BSAN_PREFIX "__bsan_"
#define RUST_PREFIX "__rust_"
#define RUST_RDL_PREFIX "__rdl_"

#define BSAN_FN(name) BSAN_PREFIX name
#define BSAN_DEBUG_PREFIX BSAN_FN("debug_")

#define BSAN_DEBUG_FN(name) BSAN_DEBUG_PREFIX name
#define RUST_FN(name) RUST_PREFIX name
#define RUST_RDL_FN(name) RUST_RDL_PREFIX name

// @__rust_retag(ptr, ptr, i64, i64)
const char kBsanRustIntrinsicRetagPrefix[] = RUST_FN("retag");
const char kBsanRustIntrinsicRetagOperand[] = RUST_FN("retag_operand");
const char kBsanRustIntrinsicRetagPlace[] = RUST_FN("retag_place");

// @__rust_expose_tag(ptr)
// Indicates that this pointer is a reference being cast into a raw pointer.
const char kBsanRustIntrinsicExposeTag[] = RUST_FN("expose_tag");

const char kBsanModuleCtorName[] = "bsan.module_ctor";
const char kBsanModuleDtorName[] = "bsan.module_dtor";

const char kBsanPrefix[] = BSAN_FN();

const char kBsanFuncInitName[] = BSAN_FN("init");
const char kBsanFuncDeinitName[] = BSAN_FN("deinit");

const char kBsanFuncPushAllocaFrameName[] = BSAN_FN("push_alloca_frame");
const char kBsanFuncPopAllocaFrameName[] = BSAN_FN("pop_alloca_frame");
const char kBsanFuncRemoveProtectedTags[] = BSAN_FN("remove_protected_tags");

const char kBsanFuncShadowCopyName[] = BSAN_FN("shadow_copy");
const char kBsanFuncShadowClearName[] = BSAN_FN("shadow_clear");

const char kBsanFuncGetShadowDestName[] = BSAN_FN("shadow_dest");
const char kBsanFuncGetShadowSrcName[] = BSAN_FN("shadow_src");

const char kBsanFuncGetShadowLoadName[] = BSAN_FN("shadow_load");
const char kBsanFuncGetShadowStoreName[] = BSAN_FN("shadow_store");

const char kBsanFuncRetagName[] = BSAN_FN("retag");
const char kBsanFuncAllocName[] = BSAN_FN("alloc");

const char kBsanFuncPopFrame[] = BSAN_FN("pop_frame");

const char kBsanFuncReserveStackSlotName[] = BSAN_FN("reserve_stack_slot");
const char kBsanFuncDestroyStackSlotName[] = BSAN_FN("destroy_stack_slot");
const char kBsanFuncAllocStackName[] = BSAN_FN("alloc_stack");

const char kBsanFuncNewBorrowTagName[] = BSAN_FN("new_tag");
const char kBsanFuncNewAllocIDName[] = BSAN_FN("new_alloc_id");
const char kBsanFuncDeallocName[] = BSAN_FN("dealloc");
const char kBsanFuncExposeTagName[] = BSAN_FN("expose_tag");
const char kBsanFuncReadName[] = BSAN_FN("read");
const char kBsanFuncWriteName[] = BSAN_FN("write");

const char kBsanFuncValidateRetvalTLSName[] = BSAN_FN("validate_retval_tls");
const char kBsanFuncValidateParamTLSName[] = BSAN_FN("validate_param_tls");
const char kBsanFuncMarkTLSName[] = BSAN_FN("mark_tls");

const char kBsanDebugPrefix[] = BSAN_DEBUG_FN();

const char kBsanFuncAssertProvenanceNull[] = BSAN_DEBUG_FN("assert_null");
const char kBsanFuncAssertProvenanceWildcard[] =
    BSAN_DEBUG_FN("assert_wildcard");
const char kBsanFuncAssertProvenanceValid[] = BSAN_DEBUG_FN("assert_valid");
const char kBsanFuncAssertProvenanceInvalid[] = BSAN_DEBUG_FN("assert_invalid");
const char kBsanFuncDebugPrint[] = BSAN_DEBUG_FN("print");
const char kBsanFuncDebugPrintBorrowState[] =
    BSAN_DEBUG_FN("print_borrow_state");
const char kBsanFuncDebugGC[] = BSAN_DEBUG_FN("gc");
const char kBsanFuncDebugTreeSize[] = BSAN_DEBUG_FN("tree_size");
const char kBsanFuncDebugSnapshot[] = BSAN_DEBUG_FN("snapshot");
const char kBsanFuncDebugPrintDiff[] = BSAN_DEBUG_FN("print_diff");
const char kBsanFuncDebugParamTLS[] = BSAN_DEBUG_FN("param_tls");
const char kBsanFuncDebugRetvalTLS[] = BSAN_DEBUG_FN("retval_tls");

const char kBsanProvStackName[] = "__BSAN_PROV_STACK";
const char kBsanParamTLSName[] = "__BSAN_PARAM_TLS";
const char kBsanRetvalTLSName[] = "__BSAN_RETVAL_TLS";
const char kBsanBorTagCounterName[] = "__BSAN_BOR_TAG_CTR";
const char kBsanAllocIdCounterName[] = "__BSAN_ALLOC_ID_CTR";

static const unsigned kTLSSize = 100;

const char *kRustAllocFns[] = {
    RUST_FN("alloc"),
    RUST_FN("dealloc"),
    RUST_FN("realloc"),
    RUST_FN("alloc_zeroed"),
};

const char *kRustAllocShimFns[] = {
    RUST_RDL_FN("alloc"),
    RUST_RDL_FN("dealloc"),
    RUST_RDL_FN("realloc"),
    RUST_RDL_FN("alloc_zeroed"),
};

#endif // BORROWSANITIZER_DECLARATIONS
