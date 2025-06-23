#include "Utils.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/DerivedTypes.h"

using namespace llvm;

namespace llvm {

uint64_t numPointersInType(Type *Ty) {
    switch (Ty->getTypeID()) {
        default: return 0;
        case Type::PointerTyID: return 1;
        case Type::ArrayTyID: {
            ArrayType *AT = cast<ArrayType>(Ty);
            return AT->getNumElements() * numPointersInType(AT->getElementType());
        }
        case Type::FixedVectorTyID: {
            VectorType *VT = cast<VectorType>(Ty);
            uint64_t NumElements = VT->getElementCount().getKnownMinValue();
            return NumElements * numPointersInType(VT->getElementType());
        }
        case Type::ScalableVectorTyID: {
            return 0;
        }
        case Type::StructTyID: {
            StructType *ST = cast<StructType>(Ty);
            uint64_t NumSlots = 0;
            for (Type *ET : ST->elements())
                NumSlots += numPointersInType(ET);
            return NumSlots;
        }
    }
}

InstrumentationIRBuilder getInsertionPointAfterCall(CallBase *CB) {
    BasicBlock::iterator NextInsn;
    if (isa<CallInst>(CB)) {
        NextInsn = ++CB->getIterator();
        assert(NextInsn != CB->getParent()->end());
    }else {
        BasicBlock *NormalDest = cast<InvokeInst>(CB)->getNormalDest();
        if (!NormalDest->getSinglePredecessor()) {
            BasicBlock *Intermediate = SplitEdge(CB->getParent(), NormalDest);
            NextInsn = Intermediate->getFirstInsertionPt();
        }else{
            NextInsn = NormalDest->getFirstInsertionPt();
            assert(NextInsn != NormalDest->end() &&
                    "Could not find insertion point for retval shadow load");
        }
    }
    return InstrumentationIRBuilder(&*NextInsn);
}

/// With the exception of homogenous scalable vector structs, only sized structs can be used in loads or stores. 
void instrumentPointers(IRBuilder<> &IRB, DataLayout &DL, Type *Ty, uint64_t CurrOffset) {
    switch (Ty->getTypeID()) {
        case Type::PointerTyID: {
        } break;
        case Type::StructTyID: {
            StructType *ST = cast<StructType>(Ty);
            if(!ST->isScalableTy()) {
                const StructLayout *SL = DL.getStructLayout(ST);
                for (const auto &[ElemIdx, Elem] : llvm::enumerate(ST->elements())) {
                    instrumentPointers(IRB, DL, Elem, CurrOffset + SL->getElementOffset(ElemIdx));
                }
            }
        } break;
        case Type::ArrayTyID: {
            ArrayType *AT = cast<ArrayType>(Ty);
            Type *ElemType = AT->getElementType();
            if(!ElemType->isSingleValueType() || (ElemType->isPointerTy() 
                    || !ElemType->isVectorTy())) {
                TypeSize ElemSize = DL.getTypeAllocSize(AT->getElementType());
                for(int ElemIdx = 0; ElemIdx < AT->getNumElements(); ++ElemIdx) {
                    instrumentPointers(IRB, DL, ElemType, CurrOffset + ElemIdx * ElemSize);
                }
            }
        } break;
        case Type::ScalableVectorTyID: {
            return;
        }
        default: break;
    }
}


}