#ifndef BORROWSANITIZER_PROVENANCE_H
#define BORROWSANITIZER_PROVENANCE_H

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/Instrumentation.h"
#include <optional>
#include <variant>

namespace llvm {

// Provenance is three words, and consists of three
// components: an allocation ID, a borrow tag, and
// a pointer to an allocation metadata object.
static const unsigned kProvenanceSize = 24;

// We have two ways of loading provenance into memory. When we
// need a singular provenance value, we create each of its component
// via function calls, taking the result by value. This happens recursively
// for structs and arrays, covering each pointer. However, this approach
// does not work for scalable vectors, which are dynamically sized. In those
// cases, we allocate a vector of each provenance component.
enum ProvenanceKind { Scalar, Vector };

struct ProvenanceLayout {
  const DataLayout *DL;
  Type *IntptrTy = nullptr;
  PointerType *PtrTy = nullptr;
  Value *ProvenanceSize = nullptr;
  Type *ProvenanceTy = nullptr;
  ProvenanceLayout() {}
  ProvenanceLayout(LLVMContext *C, const DataLayout *DL) : DL(DL) {
    PtrTy = PointerType::getUnqual(*C);
    IntptrTy = Type::getIntNTy(*C, DL->getPointerSizeInBits());
    ProvenanceTy = StructType::get(IntptrTy, IntptrTy, PtrTy);
    ProvenanceSize = ConstantInt::get(IntptrTy, kProvenanceSize);
  }
  Type *getPtrTy(ProvenanceKind Kind, ElementCount Elems) const;
  Type *getIntTy(ProvenanceKind Kind, ElementCount Elems) const;
};

class WithProvenanceKind {
public:
  ProvenanceKind Kind;
  WithProvenanceKind(ProvenanceKind K) : Kind(K) {}
  bool isScalar() const { return Kind == ProvenanceKind::Scalar; }
  bool isVector() const { return Kind == ProvenanceKind::Vector; }
};

class ProvenancePointerScalar;
class ProvenancePointerVector;

// A pointer to one or more adjacent provenance values in memory.
// Represents a "provenancy-carrying-component" of a typed value,
// offset from a given location in an array of provenance values.
struct ProvenancePointer : public WithProvenanceKind {
  Value *IdPtr = nullptr;
  Value *TagPtr = nullptr;
  Value *InfoPtr = nullptr;
  ElementCount Elems;
  ProvenancePointer() : WithProvenanceKind(ProvenanceKind::Scalar) {}
  ProvenancePointer(Value *Id, Value *Tag, Value *Info, ElementCount Elems,
                    ProvenanceKind Kind)
      : IdPtr(Id), TagPtr(Tag), InfoPtr(Info), WithProvenanceKind(Kind) {}

  ProvenancePointer(IRBuilder<> &IRB, const ProvenanceLayout &PL, Value *Base,
                    ElementCount Elems, ProvenanceKind Kind);
};

class ProvenancePointerScalar : public ProvenancePointer {
  using ProvenancePointer::ProvenancePointer;

public:
  ProvenancePointerScalar(Value *I, Value *T, Value *F)
      : ProvenancePointer(I, T, F, ElementCount::get(0, false),
                          ProvenanceKind::Scalar) {}
  ProvenancePointerScalar(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                          Value *Base);
};

class ProvenancePointerVector : public ProvenancePointer {
  using ProvenancePointer::ProvenancePointer;

public:
  ProvenancePointerVector(Value *I, Value *T, Value *F, ElementCount Elems)
      : ProvenancePointer(I, T, F, Elems, ProvenanceKind::Vector) {}
  ProvenancePointerVector(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                          Value *Base, ElementCount Elems);
  static ProvenancePointerVector
  alloc(IRBuilder<> &IRB, const ProvenanceLayout &PL, ElementCount Elems);
};

class ProvenanceScalar;
class ProvenanceVector;
class Provenance : public WithProvenanceKind {
public:
  Value *Id = nullptr;
  Value *Tag = nullptr;
  Value *Info = nullptr;
  ElementCount Elems;

  Provenance() : WithProvenanceKind(ProvenanceKind::Scalar) {}
  Provenance(Value *I, Value *T, Value *F, ElementCount E, ProvenanceKind K)
      : Id(I), Tag(T), Info(F), Elems(E), WithProvenanceKind(K) {}
  bool operator==(const Provenance &other) const {
    return this->Id == other.Id && this->Tag == other.Tag &&
           this->Info == other.Info && this->Elems == other.Elems;
  }
  bool operator!=(const Provenance &other) const { return !(*this == other); }

  void addIncoming(BasicBlock *IncomingBlock, Provenance &IncomingProv);
  std::optional<ProvenanceScalar> getScalar() const;
  ProvenanceScalar assertScalar() const;

  std::optional<ProvenanceVector> getVector() const;
  ProvenanceVector assertVector() const;
  void store(IRBuilder<> &IRB, const ProvenanceLayout &PL,
             ProvenancePointer Dest);
  static Provenance load(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                         ProvenancePointer ProvPtr);
  static ProvenanceScalar loadScalar(IRBuilder<> &IRB,
                                     const ProvenanceLayout &PL,
                                     ProvenancePointerScalar ProvPtr);
  static ProvenanceVector loadVector(IRBuilder<> &IRB,
                                     const ProvenanceLayout &PL,
                                     ProvenancePointerVector ProvPtr);
  static Provenance wildcard(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                             ElementCount Elems, ProvenanceKind Kind);
};

class ProvenanceScalar : public Provenance {
  using Provenance::Provenance;

public:
  ProvenanceScalar(Value *I, Value *T, Value *F)
      : Provenance(I, T, F, ElementCount::get(0, false),
                   ProvenanceKind::Scalar) {}
  static ProvenanceScalar wildcard(const ProvenanceLayout &PL);
};

class ProvenanceVector : public Provenance {
  using Provenance::Provenance;

public:
  ProvenanceVector(Value *I, Value *T, Value *F, ElementCount E)
      : Provenance(I, T, F, E, ProvenanceKind::Vector) {}
  static ProvenanceVector wildcard(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                                   ElementCount Elems);
};

// The "footprint" within shadow memory of a provenance-carrying component of
// a type. Each pointer-sized word of shadow memory corresponds to three words
// of provenance
struct ShadowFootprint {
  Value *ByteOffset;
  Value *ByteWidth;
  ShadowFootprint(Value *BO, Value *BW) : ByteOffset(BO), ByteWidth(BW) {}
};

// A component of a type that carries provenance information.
// This is either a pointer or a vector of pointers.
struct ProvenanceComponent : public WithProvenanceKind {
  // The range within shadow memory that would contain this many
  // provenance values.
  ShadowFootprint Footprint;
  // The number of provenance values in previous components.
  Value *ProvenanceOffset;
  // The number of provenance values in this components.
  Value *NumProvenanceValues;
  // The unevaluated static object representing the number
  // of provenance values in this component.
  ElementCount Elems;

public:
  ProvenanceComponent(Value *B, Value *BW, Value *P, Value *PW, ElementCount E,
                      ProvenanceKind Kind)
      : Footprint(B, BW), ProvenanceOffset(P), NumProvenanceValues(PW),
        Elems(E), WithProvenanceKind(Kind) {}

  // Given a pointer to the start of an array of contiguous provenance values,
  // this function will return a pointer to the start of this provenance
  // component.
  ProvenancePointer getPointerToProvenance(IRBuilder<> &IRB,
                                           const ProvenanceLayout &PL,
                                           Value *StartAddr) {
    Type *IntegerTy = ProvenanceOffset->getType();
    Value *PointerAsInt = IRB.CreatePointerCast(StartAddr, IntegerTy);
    Value *ProvByteOffset = IRB.CreateMul(
        ProvenanceOffset, ConstantInt::get(IntegerTy, kProvenanceSize));
    Value *BaseInt = IRB.CreateAdd(PointerAsInt, ProvByteOffset);
    Value *BasePointer = IRB.CreateIntToPtr(BaseInt, StartAddr->getType());
    return ProvenancePointer(IRB, PL, BasePointer, this->Elems, this->Kind);
  }
};

using ProvenanceKey = std::pair<Value *, unsigned>;

struct ProvenanceMap {
public:
  DenseMap<Value *, DenseMap<unsigned, Provenance>> Inner;

  bool contains(Value *V) { return this->contains({V, 0}); }

  bool contains(ProvenanceKey Key) {
    return Inner.contains(Key.first) && Inner[Key.first].contains(Key.second);
  }

  void transferToValue(Value *Src, Value *Dest) {
    if (this->contains(Src)) {
      DenseMap<unsigned, Provenance> *DestMap = &Inner[Dest];
      for (const auto &[Idx, Prov] : Inner[Src]) {
        (*DestMap)[Idx] = Prov;
      }
    }
  }
  void set(ProvenanceKey Key, Provenance Prov) {
    Inner[Key.first][Key.second] = Prov;
  }

  std::optional<Provenance> get(ProvenanceKey Key) {
    if (this->contains(Key)) {
      return Inner[Key.first][Key.second];
    } else {
      return std::nullopt;
    }
  }
};

} // namespace llvm

#endif // BORROWSANITIZER_PROVENANCE_H
