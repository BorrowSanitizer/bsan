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
  Type *getPtrTy(ElementCount Elems) const;
  Type *getIntTy(ElementCount Elems) const;
};

class ProvenancePtrScalar;
class ProvenancePtrVector;

// A pointer to one or more adjacent provenance values in memory.
// Represents a "provenancy-carrying-component" of a typed value,
// offset from a given location in an array of provenance values.
struct ProvenancePtr {
  Value *TagPtr = nullptr;
  Value *InfoPtr = nullptr;
  ElementCount Elems = ElementCount::getFixed(1);
  ProvenancePtr() {}
  ProvenancePtr(Value *Tag, Value *Info, ElementCount Elems)
      : TagPtr(Tag), InfoPtr(Info), Elems(Elems) {}

  ProvenancePtr(IRBuilder<> &IRB, const ProvenanceLayout &PL, Value *Base,
                ElementCount Elems);
};

class ProvenancePtrScalar : public ProvenancePtr {
  using ProvenancePtr::ProvenancePtr;

public:
  ProvenancePtrScalar(Value *T, Value *F)
      : ProvenancePtr(T, F, ElementCount::getFixed(1)) {}
  ProvenancePtrScalar(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                      Value *Base);
};

class ProvenancePtrVector : public ProvenancePtr {
  using ProvenancePtr::ProvenancePtr;

public:
  ProvenancePtrVector(Value *T, Value *F, ElementCount Elems)
      : ProvenancePtr(T, F, Elems) {}
  ProvenancePtrVector(IRBuilder<> &IRB, const ProvenanceLayout &PL, Value *Base,
                      ElementCount Elems);
  static ProvenancePtrVector alloc(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                                   ElementCount Elems);
};

class ProvenanceScalar;
class ProvenanceVector;
class Provenance {
public:
  Value *Tag = nullptr;
  Value *Info = nullptr;
  ElementCount Elems = ElementCount::getFixed(1);

  Provenance() {}
  Provenance(Value *Tag, Value *Info, ElementCount Elems)
      : Tag(Tag), Info(Info), Elems(Elems) {}
  bool operator==(const Provenance &other) const {
    return this->Tag == other.Tag && this->Info == other.Info &&
           this->Elems == other.Elems;
  }
  bool operator!=(const Provenance &other) const { return !(*this == other); }

  void addIncoming(BasicBlock *IncomingBlock, Provenance &IncomingProv);
  std::optional<ProvenanceScalar> getScalar() const;
  ProvenanceScalar assertScalar() const;

  std::optional<ProvenanceVector> getVector() const;
  ProvenanceVector assertVector() const;
  void store(IRBuilder<> &IRB, const ProvenanceLayout &PL, Value *Dest);
  void store(IRBuilder<> &IRB, const ProvenanceLayout &PL, ProvenancePtr Dest);
  static Provenance load(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                         ProvenancePtr ProvPtr);
  static Provenance wildcard(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                             ElementCount Elems);
};

class ProvenanceScalar : public Provenance {
  using Provenance::Provenance;

public:
  ProvenanceScalar(Value *Tag, Value *Info)
      : Provenance(Tag, Info, ElementCount::getFixed(1)) {}
  static ProvenanceScalar load(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                               ProvenancePtrScalar ProvPtr);
  static ProvenanceScalar wildcard(const ProvenanceLayout &PL);
};

class ProvenanceVector : public Provenance {
  using Provenance::Provenance;

public:
  ProvenanceVector(Value *Tag, Value *Info, ElementCount Elems)
      : Provenance(Tag, Info, Elems) {}
  static ProvenanceVector load(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                               ProvenancePtrVector ProvPtr);
  static ProvenanceVector wildcard(IRBuilder<> &IRB, const ProvenanceLayout &PL,
                                   ElementCount Elems);
};

// When loading and storing provenance, we need a way to
// handle dynamically sized values, which can be placed at any
// position within an aggregate type. The `DynSize` type makes
// it far easier to reason about arithmetic and other operations
// on values with both static and dynamic components.
struct DynSize {
  unsigned Static = 0;
  SmallVector<Value *, 2> Dynamic;

public:
  DynSize() {}

  DynSize(unsigned Off) : Static(Off) {}

  DynSize(Value *Val) { this->append(Val); }

  Value *getValue(IRBuilder<> &IRB, Type *Ty) {
    Value *V = ConstantInt::get(Ty, Static);
    for (Value *D : Dynamic) {
      V = IRB.CreateAdd(V, D);
    }
    return V;
  }

  void append(Value *Val) {
    if (ConstantInt *CI = dyn_cast<ConstantInt>(Val)) {
      Static += CI->getZExtValue();
    } else {
      Dynamic.push_back(Val);
    }
  }

  std::optional<unsigned> constant() {
    if (Dynamic.empty()) {
      return Static;
    } else {
      return std::nullopt;
    }
  }

  DynSize add(DynSize RHS) {
    DynSize Off;
    Off.Static = this->Static + RHS.Static;
    Off.Dynamic.append(this->Dynamic);
    Off.Dynamic.append(RHS.Dynamic);
    return Off;
  }

  DynSize sub(IRBuilder<> &IRB, Type *Ty, DynSize RHS) {
    std::optional<unsigned> LConst = this->constant();
    std::optional<unsigned> RConst = RHS.constant();
    if (LConst.has_value() && RConst.has_value()) {
      return DynSize(LConst.value() - RConst.value());
    } else {
      Value *LVal = this->getValue(IRB, Ty);
      Value *RVal = RHS.getValue(IRB, Ty);
      return IRB.CreateSub(LVal, RVal);
    }
  }

  bool operator==(const DynSize &other) const {
    if (this->Static != other.Static) {
      return false;
    }
    if (this->Dynamic.size() != other.Dynamic.size()) {
      return false;
    }
    return std::is_permutation(this->Dynamic.begin(), this->Dynamic.end(),
                               other.Dynamic.begin());
  }

  bool operator!=(const DynSize &other) const { return !(*this == other); }
};

// The "footprint" within shadow memory of a provenance-carrying component of
// a type. Each pointer-sized word of shadow memory corresponds to three words
// of provenance
struct ShadowFootprint {
  DynSize ByteOffset;
  DynSize ByteWidth;
  ShadowFootprint(Value *BO, Value *BW)
      : ByteOffset(DynSize(BO)), ByteWidth(DynSize(BW)) {}
};

// A component of a type that carries provenance information.
// This is either a pointer or a vector of pointers.
struct ProvenanceComponent {
  // The range within shadow memory that would contain this many
  // provenance values.
  ShadowFootprint Footprint;
  // The number of provenance values in previous components.
  Value *ProvenanceOffset;
  // The unevaluated static object representing the number
  // of provenance values in this component.
  ElementCount Elems;

public:
  ProvenanceComponent(Value *B, Value *BW, Value *P, ElementCount E)
      : Footprint(B, BW), ProvenanceOffset(P), Elems(E) {}

  // Given a pointer to the start of an array of contiguous provenance values,
  // this function will return a pointer to the start of this provenance
  // component.
  ProvenancePtr getPointerToProvenance(IRBuilder<> &IRB,
                                       const ProvenanceLayout &PL,
                                       Value *StartAddr) {
    Type *IntegerTy = ProvenanceOffset->getType();
    Value *PointerAsInt = IRB.CreatePointerCast(StartAddr, IntegerTy);
    Value *ProvByteOffset = IRB.CreateMul(
        ProvenanceOffset, ConstantInt::get(IntegerTy, kProvenanceSize));
    Value *BaseInt = IRB.CreateAdd(PointerAsInt, ProvByteOffset);
    Value *BasePointer = IRB.CreateIntToPtr(BaseInt, StartAddr->getType());
    return ProvenancePtr(IRB, PL, BasePointer, Elems);
  }
};

struct ProvenanceKey {
  Value *V;
  unsigned long Offset;
  ProvenanceKey(Value *V) : V(V), Offset(0) {}
  ProvenanceKey(Value *V, unsigned long Offset) : V(V), Offset(Offset) {}
};

struct ProvenanceMap {
public:
  DenseMap<Value *, DenseMap<unsigned, Provenance>> Inner;

  bool contains(Value *V) { return this->contains({V, 0}); }

  bool contains(ProvenanceKey Key) {
    return Inner.contains(Key.V) && Inner[Key.V].contains(Key.Offset);
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
    Inner[Key.V][Key.Offset] = Prov;
  }

  std::optional<Provenance> get(ProvenanceKey Key) {
    if (this->contains(Key)) {
      return Inner[Key.V][Key.Offset];
    } else {
      return std::nullopt;
    }
  }
};

} // namespace llvm

#endif // BORROWSANITIZER_PROVENANCE_H
