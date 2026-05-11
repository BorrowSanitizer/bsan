#ifndef BORROWSANITIZER_PROVENANCE_H
#define BORROWSANITIZER_PROVENANCE_H

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/AtomicOrdering.h"
#include "llvm/Transforms/Utils/Instrumentation.h"
#include <optional>
#include <variant>

namespace llvm {

// Provenance is two words: a borrow tag and
// a pointer to an allocation metadata object.
static const unsigned kProvenanceSize = 16;

// A component of a type that carries provenance information.
// This is either a pointer or a vector of pointers.
struct ProvenanceDesc {
  // The offset where this field is located.
  Value *ByteOffset;
  // The byte width of this field.
  Value *ByteWidth;
  // The number of provenance values in this field.
  ElementCount Elems;

public:
  ProvenanceDesc(Value *ByteOffset, Value *ByteWidth, ElementCount Elems)
      : ByteOffset(ByteOffset), ByteWidth(ByteWidth), Elems(Elems) {}
};

struct ProvenanceLayout {
  const DataLayout *DL;
  Type *IntptrTy = nullptr;
  PointerType *PtrTy = nullptr;
  Value *ProvenanceSize = nullptr;
  Type *ProvenanceTy = nullptr;
  Align ProvenanceAlign = Align(1);
  ProvenanceLayout() {}
  ProvenanceLayout(LLVMContext *C, const DataLayout *DL) : DL(DL) {
    PtrTy = PointerType::getUnqual(*C);
    IntptrTy = Type::getIntNTy(*C, DL->getPointerSizeInBits());
    ProvenanceTy = StructType::get(IntptrTy, PtrTy);
    ProvenanceSize = ConstantInt::get(IntptrTy, kProvenanceSize);
    ProvenanceAlign = DL->getABITypeAlign(ProvenanceTy);
  }

  SmallVector<ProvenanceDesc> getProvenanceDesc(IRBuilder<> &IRB, Type *Ty);

private:
  std::tuple<Value *, Value *>
  getProvenanceDesc(IRBuilder<> &IRB, SmallVector<ProvenanceDesc> &Dest,
                    Type *CurrentTy, Value *ByteOffset, Value *ProvOffset);
};

class ProvenanceScalar;
class ProvenanceVector;

class Provenance {
public:
  Value *Tag = nullptr;
  Value *Info = nullptr;
  ElementCount Elems = ElementCount::getFixed(1);

  Provenance() {}
  Provenance(Value *Tag, Value *Info) : Tag(Tag), Info(Info) {}
  Provenance(Value *Tag, Value *Info, ElementCount Elems)
      : Tag(Tag), Info(Info), Elems(Elems) {}
  bool operator==(const Provenance &other) const {
    return this->Tag == other.Tag && this->Info == other.Info &&
           this->Elems == other.Elems;
  }
  bool operator!=(const Provenance &other) const { return !(*this == other); }

  void addIncoming(BasicBlock *IncomingBlock, Provenance &IncomingProv);
  void store(IRBuilder<> &IRB, const ProvenanceLayout &PL, Value *Dest);
  static Provenance load(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                         Value *Src,
                         ElementCount Elems = ElementCount::getFixed(1));
  static Provenance wildcard(const ProvenanceLayout &PL,
                             ElementCount Elems = ElementCount::getFixed(1));
  bool isWildcard() const;
};

struct ProvenanceKey {
  Value *V;
  unsigned long Offset;
  ProvenanceKey(Value *V) : V(V), Offset(0) {}
  ProvenanceKey(Value *V, unsigned long Offset) : V(V), Offset(Offset) {}
};

struct ProvenanceMap {
  DenseMap<Value *, SmallDenseMap<unsigned, Provenance>> Inner;

public:
  Provenance *find(ProvenanceKey Key) {
    auto InnerIt = Inner.find(Key.V);
    if (InnerIt == Inner.end())
      return nullptr;

    auto &SubMap = InnerIt->second;
    auto SubIt = SubMap.find(Key.Offset);
    if (SubIt == SubMap.end())
      return nullptr;

    return &SubIt->second;
  }

  void transfer(Value *Src, Value *Dest) {
    auto It = Inner.find(Src);
    if (It != Inner.end()) {
      SmallDenseMap<unsigned, Provenance> *DestMap = &Inner[Dest];
      for (const auto &[Idx, Prov] : It->second) {
        (*DestMap)[Idx] = Prov;
      }
    }
  }

  void set(ProvenanceKey Key, Provenance Prov) {
    Inner[Key.V][Key.Offset] = Prov;
  }

  std::optional<Provenance> get(ProvenanceKey Key) {
    if (Provenance *Prov = this->find(Key)) {
      return *Prov;
    }
    return std::nullopt;
  }
};

} // namespace llvm

#endif // BORROWSANITIZER_PROVENANCE_H
