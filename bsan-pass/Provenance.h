#ifndef BORROWSANITIZER_PROVENANCE_H
#define BORROWSANITIZER_PROVENANCE_H

#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/Instrumentation.h"
#include <variant>
#include <optional>

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
enum ProvenanceKind {
    Scalar,
    Vector
};

// Each component of provenance needs to be representable as either a scalar or a vector
// of these components.
template<typename ScalarType, typename VectorType>
class ScalarOrVector {
public:
    using Variant = std::variant<ScalarType, VectorType>;

    ScalarOrVector() : data_(ScalarType{}) {}
    ScalarOrVector(const ScalarType& scalar) : data_(scalar) {}
    ScalarOrVector(const VectorType& vector) : data_(vector) {}
    ScalarOrVector(const Variant& variant) : data_(variant) {}
    ProvenanceKind getKind() const {
        return std::holds_alternative<ScalarType>(data_) ? ProvenanceKind::Scalar : ProvenanceKind::Vector;
    }

    bool isScalar() const { return getKind() == ProvenanceKind::Scalar; }
    bool isVector() const { return getKind() == ProvenanceKind::Vector; }

    std::optional<ScalarType> getScalar() const {
        if (auto* scalar = std::get_if<ScalarType>(&data_)) {
            return *scalar;
        }
        return std::nullopt;
    }

    ScalarType assertScalar() const {
        return this->getScalar().value();
    }

    std::optional<VectorType> getVector() const {
        if (auto* vector = std::get_if<VectorType>(&data_)) {
            return *vector;
        }
        return std::nullopt;
    }

    VectorType assertVector() const {
        return this->getVector().value();
    }

    bool operator==(const ScalarOrVector& other) const {
        return data_ == other.data_;
    }

    bool operator!=(const ScalarOrVector& other) const {
        return !(*this == other);
    }

private:
    Variant data_;
};

// A single provenance value
struct ProvenanceScalar {
    Value *Id = nullptr;
    Value *Tag = nullptr;
    Value *Info = nullptr;
    ProvenanceScalar() {}
    ProvenanceScalar(Value *I, Value *T, Value *F) : Id(I), Tag(T), Info(F) {}
    bool operator==(const ProvenanceScalar &other) const {
        return this->Id == other.Id
            && this->Tag == other.Tag
            && this->Info == other.Info; 
    }
    bool operator!=(const ProvenanceScalar &other) const {
        return !(*this == other);
    }
};

// A vector of provenance values.
struct ProvenanceVector {
    Value *IdVector = nullptr;
    Value *TagVector = nullptr;
    Value *InfoVector = nullptr;
    Value *Length = nullptr;
    ElementCount Elems;

    ProvenanceVector() {}
    ProvenanceVector(Value *I, Value *T, Value *F, Value *L, ElementCount E) : IdVector(I), TagVector(T), InfoVector(F), Length(L), Elems(E) {}
    bool operator==(const ProvenanceVector &other) const {
        return this->IdVector == other.IdVector
            && this->TagVector == other.TagVector
            && this->InfoVector == other.InfoVector 
            && this->Length == other.Length
            && this->Elems == other.Elems;
    }
    bool operator!=(const ProvenanceVector &other) const {
        return !(*this == other);
    }
};

using Provenance = ScalarOrVector<ProvenanceScalar, ProvenanceVector>;

// A pointer to one or more adjacent provenance values in memory.
// Represents a "provenancy-carrying-component" of a typed value,
// offset from a given location in an array of provenance values.
struct ProvenancePointer {
    Value *Base;
    Value *Length;
    ElementCount Elems;
    ProvenancePointer(Value *B, Value *L, ElementCount E) : Base(B), Length(L), Elems(E) {}

    bool isVector() {
        return Elems.isScalable();
    }
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
struct ProvenanceComponent {
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

    ProvenanceComponent(Value *B, Value *BW, Value *P, Value *PW, ElementCount E) : 
       Footprint(B, BW), ProvenanceOffset(P), NumProvenanceValues(PW), Elems(E) {
    }

    // Given a pointer to the start of an array of contiguous provenance values,
    // this function will return a pointer to the start of this provenance
    // component. 
    ProvenancePointer getPointerToProvenance(IRBuilder<> &IRB, Value *StartAddr) {
        Type *IntegerTy = ProvenanceOffset->getType();
        Value *PointerAsInt = IRB.CreatePointerCast(StartAddr, IntegerTy);
        Value *ProvByteOffset = IRB.CreateMul(ProvenanceOffset, ConstantInt::get(IntegerTy, kProvenanceSize));
        Value *BaseInt = IRB.CreateAdd(PointerAsInt, ProvByteOffset);
        Value *BasePointer = IRB.CreateIntToPtr(BaseInt, StartAddr->getType());
        return ProvenancePointer(BasePointer, NumProvenanceValues, Elems);
    } 

    bool isVector() {
        return Elems.isScalable();
    }
};

using ProvenanceKey = std::pair<Value *, unsigned>;


struct ProvenanceMap {
    public:
    DenseMap<Value *, DenseMap<unsigned, Provenance>> Inner;

    bool contains(Value *V) {
        return this->contains({V, 0});
    }

    bool contains(ProvenanceKey Key) {
        return Inner.contains(Key.first) && Inner[Key.first].contains(Key.second);
    }

    void transferToValue(Value *Src, Value *Dest) {
        if(this->contains(Src)){
            DenseMap<unsigned, Provenance> *DestMap = &Inner[Dest];
            for(const auto &[Idx, Prov] : Inner[Src]) {
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
        }else{
            return std::nullopt;
        }
    }
};

} // namespace llvm

#endif // BORROWSANITIZER_PROVENANCE_H