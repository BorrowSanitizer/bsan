
#include "llvm/IR/Type.h"
#include "llvm/Transforms/Utils/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

namespace llvm {
    uint64_t numPointersInType(Type *T);
    InstrumentationIRBuilder getInsertionPointAfterCall(CallBase *CB);
}