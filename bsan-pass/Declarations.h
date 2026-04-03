#ifndef BORROWSANITIZER_DECLARATIONS
#define BORROWSANITIZER_DECLARATIONS

#define BSAN_PREFIX "__bsan_"
#define RUST_PREFIX "__rust_"

#define BSAN_FN(name) BSAN_PREFIX name
#define BSAN_DEBUG_PREFIX BSAN_FN("debug_")

#define BSAN_DEBUG_FN(name) BSAN_DEBUG_PREFIX name
#define RUST_FN(name) RUST_PREFIX name

// @__rust_retag(ptr, ptr, i64, i64)
const char kBsanRustIntrinsicRetagPrefix[] = RUST_FN("retag");
const char kBsanRustIntrinsicRetagReg[] = RUST_FN("retag_reg");
const char kBsanRustIntrinsicRetagMem[] = RUST_FN("retag_mem");

const char kBsanModuleCtorName[] = "bsan.module_ctor";
const char kBsanModuleDtorName[] = "bsan.module_dtor";

const char kBsanPrefix[] = BSAN_FN();

const char kBsanFuncInitName[] = BSAN_FN("init");
const char kBsanFuncDeinitName[] = BSAN_FN("deinit");

const char kBsanFuncMemMoveName[] = BSAN_FN("memmove");
const char kBsanFuncMemCpyName[] = BSAN_FN("memcpy");
const char kBsanFuncMemSetName[] = BSAN_FN("memset");

const char kBsanFuncShadowClearName[] = BSAN_FN("shadow_clear");
const char kBsanFuncGetShadowLoadName[] = BSAN_FN("shadow_load");
const char kBsanFuncGetShadowStoreName[] = BSAN_FN("shadow_store");

const char kBsanFuncRetagName[] = BSAN_FN("retag");
const char kBsanFuncAllocName[] = BSAN_FN("alloc");

const char kBsanFuncPopFrame[] = BSAN_FN("pop_frame");

const char kBsanFuncReserveStackSlotName[] = BSAN_FN("reserve_stack_slot");
const char kBsanFuncDestroyStackSlotName[] = BSAN_FN("destroy_stack_slot");
const char kBsanFuncAllocStackName[] = BSAN_FN("alloc_stack");
const char kBsanFuncDeallocStackName[] = BSAN_FN("dealloc_stack");

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
const char kBsanFuncDebugGC[] = BSAN_DEBUG_FN("gc");
const char kBsanFuncDebugSnapshot[] = BSAN_DEBUG_FN("snapshot");
const char kBsanFuncDebugParamTLS[] = BSAN_DEBUG_FN("param_tls");
const char kBsanFuncDebugRetvalTLS[] = BSAN_DEBUG_FN("retval_tls");

const char kBsanProvStackName[] = "__BSAN_PROV_STACK";
const char kBsanParamTLSName[] = "__BSAN_PARAM_TLS";
const char kBsanRetvalTLSName[] = "__BSAN_RETVAL_TLS";
const char kBsanTLSMarkerName[] = "__BSAN_TLS_MARKER";

const char kBsanBorTagCounterName[] = "__BSAN_BOR_TAG_CTR";
const char kBsanAllocIdCounterName[] = "__BSAN_ALLOC_ID_CTR";

static const unsigned kTLSSize = 100;

#endif // BORROWSANITIZER_DECLARATIONS
