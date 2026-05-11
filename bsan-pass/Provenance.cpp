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
    getProvenanceDesc(IRB, Desc, Ty, Zero, Zero);
  }
  return Desc;
}

// Populates a vector with the list of locations of provenance
// values within a type.
std::tuple<Value *, Value *> ProvenanceLayout::getProvenanceDesc(
    IRBuilder<> &IRB, SmallVector<ProvenanceDesc> &ProvDesc, Type *CurrentTy,
    Value *ByteOffset, Value *ProvOffset) {
  assert(CurrentTy->isSized() && "expected a sized type");
  TypeSize AllocSize = DL->getTypeAllocSize(CurrentTy);
  Value *TypeSize = IRB.CreateTypeSize(IRB.getIntPtrTy(*DL), AllocSize);
  Value *NextProvOffset = ProvOffset;
  switch (CurrentTy->getTypeID()) {
  case Type::PointerTyID: {
    ProvenanceDesc Desc(ByteOffset, TypeSize, ElementCount::get(1, false));
    ProvDesc.push_back(Desc);
    Value *Elems = IRB.CreateElementCount(IRB.getIntPtrTy(*DL), Desc.Elems);
    NextProvOffset = IRB.CreateAdd(ProvOffset, Elems);
  } break;
  case Type::StructTyID: {
    StructType *ST = cast<StructType>(CurrentTy);
    Value *CurrByteOffset = ByteOffset;
    for (Type *ElemType : ST->elements()) {
      auto [BOffset, POffset] = getProvenanceDesc(
          IRB, ProvDesc, ElemType, CurrByteOffset, NextProvOffset);
      CurrByteOffset = BOffset;
      NextProvOffset = POffset;
    }
  } break;
  case Type::ArrayTyID: {
    ArrayType *AT = cast<ArrayType>(CurrentTy);
    Value *CurrByteOffset = ByteOffset;
    for (unsigned Idx = 0; Idx < AT->getNumElements(); ++Idx) {
      auto [BOffset, POffset] = getProvenanceDesc(
          IRB, ProvDesc, AT->getElementType(), CurrByteOffset, NextProvOffset);
      CurrByteOffset = BOffset;
      NextProvOffset = POffset;
    }
  } break;
  default:
    break;
  }
  Value *NextByteOffset = IRB.CreateAdd(ByteOffset, TypeSize);
  return std::make_tuple(NextByteOffset, NextProvOffset);
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

bool Provenance::isWildcard() const {
  if (this->Elems.isScalar()) {
    if (auto *CI = dyn_cast<ConstantInt>(this->Tag)) {
      return CI->isZero();
    }
    return false;
  }
  report_fatal_error("Vector provenance is not supported yet");
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

Provenance Provenance::wildcard(const ProvenanceLayout &PL,
                                ElementCount Elems) {
  if (Elems.isScalar()) {
    Value *Zero = ConstantInt::get(PL.IntptrTy, 0);
    Value *InvalidPtr = ConstantPointerNull::get(PL.PtrTy);
    return Provenance(Zero, InvalidPtr, Elems);
  }
  report_fatal_error("Vector provenance is not supported yet");
}