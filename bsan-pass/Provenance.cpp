#include "Provenance.h"
#include "llvm/IR/IRBuilder.h"

using namespace llvm;

Type *ProvenanceLayout::getPtrTy(ProvenanceKind Kind,
                                 ElementCount Elems) const {
  if (Kind == ProvenanceKind::Vector) {
    return VectorType::get(this->PtrTy, Elems);
  }
  return this->PtrTy;
}

Type *ProvenanceLayout::getIntTy(ProvenanceKind Kind,
                                 ElementCount Elems) const {
  if (Kind == ProvenanceKind::Vector) {
    return VectorType::get(this->IntptrTy, Elems);
  }
  return this->IntptrTy;
}

std::optional<ProvenanceScalar> Provenance::getScalar() const {
  if (isScalar()) {
    return *static_cast<const ProvenanceScalar *>(this);
  }
  return std::nullopt;
}

ProvenanceScalar Provenance::assertScalar() const {
  return this->getScalar().value();
}

std::optional<ProvenanceVector> Provenance::getVector() const {
  if (isVector()) {
    return *static_cast<const ProvenanceVector *>(this);
  }
  return std::nullopt;
}

ProvenanceVector Provenance::assertVector() const {
  return this->getVector().value();
}

ProvenancePointer::ProvenancePointer(IRBuilder<> &IRB,
                                     const ProvenanceLayout &PL, Value *Base,
                                     ElementCount Elems, ProvenanceKind Kind)
    : WithProvenanceKind(Kind) {
  if (Kind == ProvenanceKind::Scalar) {
    *this = ProvenancePointerScalar(IRB, PL, Base);
  } else {
    *this = ProvenancePointerVector(IRB, PL, Base, Elems);
  }
}

ProvenancePointerScalar::ProvenancePointerScalar(IRBuilder<> &IRB,
                                                 const ProvenanceLayout &PL,
                                                 Value *Base) {

  Value *ZeroIdx = ConstantInt::get(IRB.getInt64Ty(), 0);

  this->IdPtr = Base;

  this->TagPtr = IRB.CreateGEP(
      PL.ProvenanceTy, Base, {ZeroIdx, ConstantInt::get(IRB.getInt32Ty(), 1)});

  this->InfoPtr = IRB.CreateGEP(
      PL.ProvenanceTy, Base, {ZeroIdx, ConstantInt::get(IRB.getInt32Ty(), 2)});
}

ProvenancePointerVector::ProvenancePointerVector(IRBuilder<> &IRB,
                                                 const ProvenanceLayout &PL,
                                                 Value *Base,
                                                 ElementCount Elems) {
  this->IdPtr = Base;
  this->Elems = Elems;
  Value *IntVecSize = IRB.CreateTypeSize(
      PL.IntptrTy,
      PL.DL->getTypeAllocSize(VectorType::get(PL.IntptrTy, Elems)));

  Value *PtrVecSize = IRB.CreateTypeSize(
      PL.PtrTy, PL.DL->getTypeAllocSize(VectorType::get(PL.PtrTy, Elems)));

  Value *TagBase = IRB.CreatePointerCast(IdPtr, IRB.getIntPtrTy(*PL.DL));
  Value *TagOffset = IRB.CreateAdd(Base, IntVecSize);
  this->TagPtr = IRB.CreateIntToPtr(TagOffset, PL.PtrTy);
  this->InfoPtr =
      IRB.CreateIntToPtr(IRB.CreateAdd(TagOffset, IntVecSize), PL.PtrTy);
}

void Provenance::addIncoming(BasicBlock *IncomingBlock,
                             Provenance &IncomingProv) {
  PHINode *IdNode = cast<PHINode>(this->Id);
  PHINode *TagNode = cast<PHINode>(this->Tag);
  PHINode *InfoNode = cast<PHINode>(this->Info);
  IdNode->setIncomingValueForBlock(IncomingBlock, IncomingProv.Id);
  TagNode->setIncomingValueForBlock(IncomingBlock, IncomingProv.Tag);
  InfoNode->setIncomingValueForBlock(IncomingBlock, IncomingProv.Info);
}

Provenance Provenance::load(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                            ProvenancePointer ProvPtr) {

  Type *IntTy = PL.getIntTy(ProvPtr.Kind, ProvPtr.Elems);
  Type *PtrTy = PL.getPtrTy(ProvPtr.Kind, ProvPtr.Elems);

  LoadInst *Id = IRB.CreateLoad(IntTy, ProvPtr.IdPtr);
  Id->setVolatile(1);

  LoadInst *Tag = IRB.CreateLoad(IntTy, ProvPtr.TagPtr);
  Tag->setVolatile(1);

  LoadInst *Info = IRB.CreateLoad(PtrTy, ProvPtr.InfoPtr);
  Info->setVolatile(1);

  return Provenance(Id, Tag, Info, ProvPtr.Elems, ProvPtr.Kind);
}

ProvenanceScalar Provenance::loadScalar(IRBuilder<> &IRB,
                                        const ProvenanceLayout &PL,
                                        ProvenancePointerScalar ProvPtr) {
  return Provenance::load(IRB, PL, ProvPtr).assertScalar();
}
ProvenanceVector Provenance::loadVector(IRBuilder<> &IRB,
                                        const ProvenanceLayout &PL,
                                        ProvenancePointerVector ProvPtr) {
  return Provenance::load(IRB, PL, ProvPtr).assertVector();
}

void Provenance::store(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                       ProvenancePointer Dest) {

  StoreInst *Id = IRB.CreateStore(this->Id, Dest.IdPtr);
  Id->setVolatile(1);

  StoreInst *Tag = IRB.CreateStore(this->Tag, Dest.TagPtr);
  Tag->setVolatile(1);

  StoreInst *Info = IRB.CreateStore(this->Info, Dest.InfoPtr);
  Info->setVolatile(1);
}

Provenance Provenance::wildcard(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                                ElementCount Elems, ProvenanceKind Kind) {
  if (Kind == ProvenanceKind::Scalar) {
    return ProvenanceScalar::wildcard(PL);
  }
  return ProvenanceVector::wildcard(IRB, PL, Elems);
}

ProvenanceScalar ProvenanceScalar::wildcard(const ProvenanceLayout &PL) {
  Value *Zero = ConstantInt::get(PL.IntptrTy, 0);
  Value *InvalidPtr = ConstantPointerNull::get(PL.PtrTy);
  return ProvenanceScalar(Zero, Zero, InvalidPtr);
}

ProvenanceVector ProvenanceVector::wildcard(IRBuilder<> &IRB,
                                            const ProvenanceLayout &PL,
                                            ElementCount Elems) {
  Constant *Zero = ConstantInt::get(PL.IntptrTy, 0);
  Value *Id = ConstantVector::getSplat(Elems, Zero);
  Value *Tag = ConstantVector::getSplat(Elems, Zero);
  Value *Info =
      ConstantVector::getSplat(Elems, ConstantPointerNull::get(PL.PtrTy));
  return ProvenanceVector(Id, Tag, Info, Elems);
}