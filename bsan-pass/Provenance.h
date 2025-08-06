#ifndef BORROWSANITIZER_PROVENANCE_H
#define BORROWSANITIZER_PROVENANCE_H

#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/Instrumentation.h"

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

// A single provenance value
struct ScalarProvenance {
    Value *ID = nullptr;
    Value *Tag = nullptr;
    Value *Info = nullptr;
    ScalarProvenance() {}

    ScalarProvenance(Value *I, Value *T, Value *F) : ID(I), Tag(T), Info(F) {}
    bool operator==(const ScalarProvenance &other) const {
        return this->ID == other.ID 
            && this->Tag == other.Tag 
            && this->Info == other.Info;
    }
    bool operator!=(const ScalarProvenance &other) const {
        return !(*this == other);
    }
};

// A vector of provenance values.
struct VectorProvenance {
    Value *IDVector = nullptr;
    Value *TagVector = nullptr;
    Value *InfoVector = nullptr;
    Value *Length = nullptr;
    ElementCount Elems;

    VectorProvenance() {}
    VectorProvenance(Value *ID, Value *Tag, Value *Info, Value *L, ElementCount E) :
        IDVector(ID), TagVector(Tag), InfoVector(Info), Length(L), Elems(E) {}
};


// Either a scalar or vector provenance value. This struct is returned
// whenever we query the provenance for a value. We use a union here;
// alternatively, we could create an abstract class, but that would require
// additional indirection.
struct LoadedProvenance {
    ProvenanceKind Kind;
    LoadedProvenance() : Kind(Scalar) {}
    LoadedProvenance(ScalarProvenance P) : Kind(Scalar), ScalarProv(P) {}
    LoadedProvenance(VectorProvenance V) : Kind(Vector), VectorProv(V) {}

    bool isVector() {
        return Kind == ProvenanceKind::Vector;
    }

    bool isScalar() {
        return Kind == ProvenanceKind::Scalar;
    }

    std::optional<ScalarProvenance> getScalarProvenance() {
        if(isScalar()) {
            return ScalarProv;
        }else{
            return std::nullopt;
        }
    }

    std::optional<VectorProvenance> getVectorProvenance() {
        if(isVector()) {
            return VectorProv;
        }else{
            return std::nullopt;
        }
    }

    private:
    union {
        VectorProvenance VectorProv;
        ScalarProvenance ScalarProv;
    };
};

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

} // namespace llvm

#endif // BORROWSANITIZER_PROVENANCE_H