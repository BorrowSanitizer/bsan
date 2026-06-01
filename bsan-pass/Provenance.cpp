#include "Provenance.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/PatternMatch.h"

using namespace llvm;

// Provides a list of the locations of provenance values inside a type.
SmallVector<ProvenanceDesc>
ProvenanceLayout::getProvenanceDesc(IRBuilder<> &IRB, Type *Ty) {
  SmallVector<ProvenanceDesc> Desc;
  if (Ty->isSized()) {
    Value *Zero = ConstantInt::get(IRB.getIntPtrTy(*DL), 0);
    getProvenanceDesc(IRB, Desc, Ty, Zero);
  }
  return Desc;
}

// Populates a vector with the list of locations of provenance
// values within a type.
Value *
ProvenanceLayout::getProvenanceDesc(IRBuilder<> &IRB,
                                    SmallVector<ProvenanceDesc> &ProvDesc,
                                    Type *CurrentTy, Value *ByteOffset) {
  assert(CurrentTy->isSized() && "expected a sized type");
  Type *IntptrTy = IRB.getIntPtrTy(*DL);

  switch (CurrentTy->getTypeID()) {
  case Type::PointerTyID: {
    TypeSize AllocTySize = DL->getTypeAllocSize(CurrentTy);
    Value *AllocSize = IRB.CreateTypeSize(IntptrTy, AllocTySize);
    ProvenanceDesc Desc(ByteOffset, AllocSize, ElementCount::get(1, false));
    ProvDesc.push_back(Desc);
    Value *Elems = IRB.CreateElementCount(IntptrTy, Desc.Elems);
    return ConstantInt::get(IntptrTy, 1);
  } break;
  case Type::StructTyID: {
    StructType *ST = cast<StructType>(CurrentTy);
    const StructLayout *SL = DL->getStructLayout(ST);
    Value *CurrProvOffset = ConstantInt::get(IntptrTy, 0);
    for (auto [Idx, ElemTy] : llvm::enumerate(ST->elements())) {
      Value *ElemOffset =
          IRB.CreateTypeSize(IntptrTy, SL->getElementOffset(Idx));
      Value *CurrByteOffset = IRB.CreateAdd(ByteOffset, ElemOffset);
      auto *ProvOffset =
          getProvenanceDesc(IRB, ProvDesc, ElemTy, CurrByteOffset);
      CurrProvOffset = IRB.CreateAdd(CurrProvOffset, ProvOffset);
    }
    return CurrProvOffset;
  } break;
  case Type::ArrayTyID: {
    ArrayType *AT = cast<ArrayType>(CurrentTy);
    Value *CurrProvOffset = ConstantInt::get(IntptrTy, 0);
    TypeSize ElemTySize = DL->getTypeAllocSize(AT->getElementType());
    Value *ElemSize = IRB.CreateTypeSize(IntptrTy, ElemTySize);
    for (unsigned Idx = 0; Idx < AT->getNumElements(); ++Idx) {
      Value *CurrByteOffset =
          IRB.CreateMul(ConstantInt::get(IntptrTy, Idx), ElemSize);
      CurrByteOffset = IRB.CreateAdd(ByteOffset, CurrByteOffset);
      auto *ProvOffset = getProvenanceDesc(IRB, ProvDesc, AT->getElementType(),
                                           CurrByteOffset);
      CurrProvOffset = IRB.CreateAdd(CurrProvOffset, ProvOffset);
    }
    return CurrProvOffset;
  } break;
  default: {
    return ConstantInt::get(IntptrTy, 0);
  } break;
  }
}

void Provenance::addIncoming(BasicBlock *IncomingBlock,
                             Provenance &IncomingProv) {
  assert(isa<PHINode>(this->Tag));
  PHINode *TagNode = cast<PHINode>(this->Tag);

  assert(isa<PHINode>(this->Info));
  PHINode *InfoNode = cast<PHINode>(this->Info);

  TagNode->setIncomingValueForBlock(IncomingBlock, IncomingProv.Tag);
  InfoNode->setIncomingValueForBlock(IncomingBlock, IncomingProv.Info);
}

Provenance Provenance::load(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                            Value *Src, ElementCount Elems) {
  if (Elems.isScalar()) {
    Type *IntTy = PL.IntptrTy;
    Type *PtrTy = PL.PtrTy;

    Value *ZeroIdx = ConstantInt::get(IRB.getInt64Ty(), 0);
    Value *TagPtr = Src;
    Value *InfoPtr = IRB.CreateGEP(
        PL.ProvenanceTy, Src, {ZeroIdx, ConstantInt::get(IRB.getInt32Ty(), 1)});

    LoadInst *Tag = IRB.CreateLoad(IntTy, TagPtr);
    LoadInst *Info = IRB.CreateLoad(PtrTy, InfoPtr);

    return Provenance(Tag, Info, ElementCount::getFixed(1));
  }
  report_fatal_error("Vector provenance is not supported yet");
}

void Provenance::store(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                       Value *Base) {
  if (Elems.isScalar()) {
    Value *ZeroIdx = ConstantInt::get(IRB.getInt64Ty(), 0);
    Value *TagPtr = Base;
    Value *InfoPtr =
        IRB.CreateGEP(PL.ProvenanceTy, Base,
                      {ZeroIdx, ConstantInt::get(IRB.getInt32Ty(), 1)});
    IRB.CreateStore(this->Tag, TagPtr);
    IRB.CreateStore(this->Info, InfoPtr);
  } else {
    report_fatal_error("Vector provenance is not supported yet");
  }
}

Provenance Provenance::omnivalid(const ProvenanceLayout &PL,
                                 ElementCount Elems) {
  if (Elems.isScalar()) {
    Value *Zero = ConstantInt::get(PL.IntptrTy, 0);
    Value *InvalidPtr = ConstantPointerNull::get(PL.PtrTy);
    return Provenance(Zero, InvalidPtr, Elems);
  }
  report_fatal_error("Vector provenance is not supported yet");
}