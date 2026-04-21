#include "Provenance.h"
#include "llvm/IR/IRBuilder.h"

using namespace llvm;

Type *ProvenanceLayout::getPtrTy(ElementCount Elems) const {
  if (Elems.isScalar()) {
    return this->PtrTy;
  }
  return VectorType::get(this->PtrTy, Elems);
}

Type *ProvenanceLayout::getIntTy(ElementCount Elems) const {
  if (Elems.isScalar()) {
    return this->IntptrTy;
  }
  return VectorType::get(this->IntptrTy, Elems);
}

std::optional<ProvenanceScalar> Provenance::getScalar() const {
  if (Elems.isScalar()) {
    return *static_cast<const ProvenanceScalar *>(this);
  }
  return std::nullopt;
}

ProvenanceScalar Provenance::assertScalar() const {
  return this->getScalar().value();
}

std::optional<ProvenanceVector> Provenance::getVector() const {
  if (Elems.isVector()) {
    return *static_cast<const ProvenanceVector *>(this);
  }
  return std::nullopt;
}

ProvenanceVector Provenance::assertVector() const {
  return this->getVector().value();
}

ProvenancePtr::ProvenancePtr(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                             Value *Base, ElementCount Elems) {
  if (Elems.isScalar()) {
    *this = ProvenancePtrScalar(IRB, PL, Base);
  } else {
    *this = ProvenancePtrVector(IRB, PL, Base, Elems);
  }
}

ProvenancePtrScalar::ProvenancePtrScalar(IRBuilder<> &IRB,
                                         const ProvenanceLayout &PL,
                                         Value *Base) {

  Value *ZeroIdx = ConstantInt::get(IRB.getInt64Ty(), 0);
  this->TagPtr = Base;
  this->InfoPtr = IRB.CreateGEP(
      PL.ProvenanceTy, Base, {ZeroIdx, ConstantInt::get(IRB.getInt32Ty(), 1)});
}

ProvenancePtrVector::ProvenancePtrVector(IRBuilder<> &IRB,
                                         const ProvenanceLayout &PL,
                                         Value *Base, ElementCount Elems) {
  this->TagPtr = Base;
  this->Elems = Elems;
  Value *IntVecSize = IRB.CreateTypeSize(
      PL.IntptrTy,
      PL.DL->getTypeAllocSize(VectorType::get(PL.IntptrTy, Elems)));
  Value *TagOffset = IRB.CreateAdd(Base, this->TagPtr);
  this->InfoPtr =
      IRB.CreateIntToPtr(IRB.CreateAdd(TagOffset, IntVecSize), PL.PtrTy);
}

void Provenance::addIncoming(BasicBlock *IncomingBlock,
                             Provenance &IncomingProv) {
  PHINode *TagNode = cast<PHINode>(this->Tag);
  PHINode *InfoNode = cast<PHINode>(this->Info);

  TagNode->setIncomingValueForBlock(IncomingBlock, IncomingProv.Tag);
  InfoNode->setIncomingValueForBlock(IncomingBlock, IncomingProv.Info);
}

Provenance Provenance::load(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                            ProvenancePtr ProvPtr) {

  Type *IntTy = PL.getIntTy(ProvPtr.Elems);
  Type *PtrTy = PL.getPtrTy(ProvPtr.Elems);

  LoadInst *Tag = IRB.CreateLoad(IntTy, ProvPtr.TagPtr);
  LoadInst *Info = IRB.CreateLoad(PtrTy, ProvPtr.InfoPtr);

  return Provenance(Tag, Info, ProvPtr.Elems);
}

ProvenanceScalar ProvenanceScalar::load(IRBuilder<> &IRB,
                                        const ProvenanceLayout &PL,
                                        ProvenancePtrScalar ProvPtr) {
  return Provenance::load(IRB, PL, ProvPtr).assertScalar();
}
ProvenanceVector ProvenanceVector::load(IRBuilder<> &IRB,
                                        const ProvenanceLayout &PL,
                                        ProvenancePtrVector ProvPtr) {
  return Provenance::load(IRB, PL, ProvPtr).assertVector();
}

void Provenance::store(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                       Value *Base) {
  this->store(IRB, PL, ProvenancePtr(IRB, PL, Base, this->Elems));
}

void Provenance::store(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                       ProvenancePtr Dest) {

  StoreInst *Tag = IRB.CreateStore(this->Tag, Dest.TagPtr);
  StoreInst *Info = IRB.CreateStore(this->Info, Dest.InfoPtr);
}

Provenance Provenance::wildcard(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                                ElementCount Elems) {
  if (Elems.isScalar()) {
    return ProvenanceScalar::wildcard(PL);
  }
  return ProvenanceVector::wildcard(IRB, PL, Elems);
}

ProvenanceScalar ProvenanceScalar::wildcard(const ProvenanceLayout &PL) {
  Value *Zero = ConstantInt::get(PL.IntptrTy, 0);
  Value *InvalidPtr = ConstantPointerNull::get(PL.PtrTy);
  return ProvenanceScalar(Zero, InvalidPtr);
}

ProvenanceVector ProvenanceVector::wildcard(IRBuilder<> &IRB,
                                            const ProvenanceLayout &PL,
                                            ElementCount Elems) {
  Constant *Zero = ConstantInt::get(PL.IntptrTy, 0);
  Value *Tag = ConstantVector::getSplat(Elems, Zero);
  Value *Info =
      ConstantVector::getSplat(Elems, ConstantPointerNull::get(PL.PtrTy));
  return ProvenanceVector(Tag, Info, Elems);
}
