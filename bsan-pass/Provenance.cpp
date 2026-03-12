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
  this->TagPtr = Base;
  this->InfoPtr = IRB.CreateGEP(
      PL.ProvenanceTy, Base, {ZeroIdx, ConstantInt::get(IRB.getInt32Ty(), 1)});
}

ProvenancePointerVector::ProvenancePointerVector(IRBuilder<> &IRB,
                                                 const ProvenanceLayout &PL,
                                                 Value *Base,
                                                 ElementCount Elems) {
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
                            ProvenancePointer ProvPtr,
                            AtomicOrdering Ordering) {

  Type *IntTy = PL.getIntTy(ProvPtr.Kind, ProvPtr.Elems);
  Type *PtrTy = PL.getPtrTy(ProvPtr.Kind, ProvPtr.Elems);

  LoadInst *Tag = IRB.CreateLoad(IntTy, ProvPtr.TagPtr, true);
  LoadInst *Info = IRB.CreateLoad(PtrTy, ProvPtr.InfoPtr, true);
  // Info->setAtomic(Ordering);  // TODO: Tag and Info should be loaded
  // atomically together as U128

  return Provenance(Tag, Info, ProvPtr.Elems, ProvPtr.Kind);
}

ProvenanceScalar
Provenance::loadScalar(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                       ProvenancePointerScalar ProvPtr,
                       AtomicOrdering Ordering = AtomicOrdering::NotAtomic) {
  return Provenance::load(IRB, PL, ProvPtr, Ordering).assertScalar();
}
ProvenanceVector Provenance::loadVector(IRBuilder<> &IRB,
                                        const ProvenanceLayout &PL,
                                        ProvenancePointerVector ProvPtr,
                                        AtomicOrdering Ordering) {
  return Provenance::load(IRB, PL, ProvPtr, Ordering).assertVector();
}

void Provenance::store(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                       Value *Base, AtomicOrdering Ordering) {
  this->store(IRB, PL,
              ProvenancePointer(IRB, PL, Base, this->Elems, this->Kind),
              Ordering);
}

void Provenance::store(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                       ProvenancePointer Dest, AtomicOrdering Ordering) {

  StoreInst *Tag = IRB.CreateStore(this->Tag, Dest.TagPtr, true);
  StoreInst *Info = IRB.CreateStore(this->Info, Dest.InfoPtr, true);
  // Info->setAtomic(Ordering);  // TODO: Tag and Info should be loaded
  // atomically together as U128
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
