#include "BorrowSanitizer.h"

#include "llvm/Transforms/Utils/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/EscapeEnumerator.h"

#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/StackSafetyAnalysis.h"
#include "llvm/Analysis/MemorySSA.h"
#include "llvm/Analysis/ValueTracking.h"

#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/Module.h"

#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/Statistic.h"

#include "llvm/Analysis/MemoryBuiltins.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/DebugCounter.h"

#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

#define DEBUG_TYPE "bsan"

// Command-line flags:
static cl::opt<bool>
    ClWithComdat("bsan-with-comdat",
                 cl::desc("Place BSan constructors in comdat sections"),
                 cl::Hidden, cl::init(true));

static cl::opt<bool>
    ClUseStackSafety("bsan-use-stack-safety", cl::Hidden, cl::init(true),
                     cl::Hidden, cl::desc("Use Stack Safety analysis results"),
                     cl::Optional);

STATISTIC(NumAllocaEliminated, "Number of times that instrumentation is eliminated for an alloca.");
STATISTIC(NumReadsEliminated, "Number of times that instrumentation is eliminated for an read.");
STATISTIC(NumWritesEliminated, "Number of times that instrumentation is eliminated for a write.");


namespace {
struct BorrowSanitizer {

    BorrowSanitizer(Module &M) : UseCtorComdat(ClWithComdat) {
        C = &(M.getContext());
        DL = &M.getDataLayout();
        TargetTriple = Triple(M.getTargetTriple());

        LongSize = M.getDataLayout().getPointerSizeInBits();

        Int8Ty = Type::getInt8Ty(*C);
        Int64Ty = Type::getInt64Ty(*C);
        PtrTy = PointerType::getUnqual(*C);
        IntptrTy = Type::getIntNTy(*C, LongSize);
        
        ProvenanceTy = StructType::get(IntptrTy, IntptrTy, PtrTy);
        ProvenanceAlign = DL->getABITypeAlign(ProvenanceTy);
        ProvenanceSize = ConstantInt::get(IntptrTy, kProvenanceSize);
        
        Zero = ConstantInt::get(IntptrTy, 0);
        One = ConstantInt::get(IntptrTy, 1);
        
        Constant *InvalidPtr = ConstantPointerNull::get(PtrTy);

        // Wildcard provenance permits any access. It has an allocation ID of 1.
        // For the moment, we only assign pointers this provenance value when they
        // are cast from integers (inttoptr), so we do not need a VectorProvenance
        // counterpart.
        WildcardProvenance = ScalarProvenance(One, Zero, InvalidPtr);
        
        // Null provenance does not permit any access. All components are set to zero.
        NullScalarProvenance = ScalarProvenance(Zero, Zero, InvalidPtr);
        NullVectorProvenance = VectorProvenance(InvalidPtr, InvalidPtr, InvalidPtr, Zero);

    }
    bool instrumentModule(Module &);
    bool instrumentFunction(Function &F, FunctionAnalysisManager &FAM,
        const StackSafetyGlobalInfo *const SSGI);

    // Adds thread-local global variables for passing the provenance for
    // arguments and return values 
    void createUserspaceApi(Module &M, const TargetLibraryInfo &TLI);

    TypeSize getAllocaSizeInBytes(const AllocaInst &AI) const {
        return *AI.getAllocationSize(AI.getDataLayout());
    }

private:
    friend struct BorrowSanitizerVisitor;
    
    void initializeCallbacks(Module &M, const TargetLibraryInfo &TLI);
    void instrumentGlobals(IRBuilder<> &IRB, Module &M, bool *CtorComdat);
    Instruction *CreateBsanModuleDtor(Module &M);

    bool UseCtorComdat;
    LLVMContext *C;
    const DataLayout *DL;

    int LongSize;
    Triple TargetTriple;
    Type *Int8Ty;
    Type *Int64Ty;
    PointerType *PtrTy;
    Type *IntptrTy;

    StructType *ProvenanceTy;
    Align ProvenanceAlign;
    Value *ProvenanceSize;

    bool CallbacksInitialized = false;

    Function *BsanCtorFunction = nullptr;
    Function *BsanDtorFunction = nullptr;

    FunctionCallee BsanFuncRetag;
    FunctionCallee BsanFuncPushFrame;
    FunctionCallee BsanFuncPopFrame;
    FunctionCallee BsanFuncShadowCopy;
    FunctionCallee BsanFuncShadowClear;
    FunctionCallee BsanFuncSplitProv;
    FunctionCallee BsanFuncJoinProv;
    FunctionCallee BsanFuncGetShadowSrc;
    FunctionCallee BsanFuncGetShadowDest;

    FunctionCallee BsanFuncAlloc;
    FunctionCallee BsanFuncDealloc;
    FunctionCallee BsanFuncExposeTag;
    FunctionCallee BsanFuncRead;
    FunctionCallee BsanFuncWrite;

    FunctionCallee BsanFuncNewBorrowTag;
    FunctionCallee BsanFuncNewAllocID;

    FunctionCallee BsanFuncShadowLoadArray;
    FunctionCallee BsanFuncShadowLoadVector;
    FunctionCallee BsanFuncShadowStoreArray;
    FunctionCallee BsanFuncShadowStoreVector;

    ScalarProvenance WildcardProvenance;
    ScalarProvenance NullScalarProvenance;
    VectorProvenance NullVectorProvenance;

    // Thread-local storage for paramters
    // and return values. 
    Value *ParamTLS = nullptr;
    Value *RetvalTLS = nullptr;

    Value *Zero = nullptr;
    Value *One = nullptr;
};

// This class implements function-level instrumentation.
struct BorrowSanitizerVisitor : public InstVisitor<BorrowSanitizerVisitor> {
    Function &F;
    BorrowSanitizer &BS;
    DIBuilder DIB;
    LLVMContext *C;

    const StackSafetyGlobalInfo *SSGI;
    const TargetLibraryInfo *TLI;
    AliasAnalysis &AA;
    MemorySSA &MSSA;

    // The first instruction in the body of the function, which is set to be
    // a call to __bsan_push_frame. 
    Instruction *FnPrologueStart;

    // The last instruction within the "prologue" of the function. All paths are
    // guaranteed to execute each instruction between the start and end of the prologue.
    Instruction *FnPrologueEnd;

    // Every instruction in the function's body, arranged in reverse postorder.
    SmallVector<Instruction *, 16> Instructions;

    // Alloca instructions. For the moment, static allocas are handled the same as
    // dynamic ones, but we will adjust this behavior in the future to support optimizations
    // such as combining static stack allocations into a single, larger allocation 
    // (see AddressSanitizer).
    SmallVector<AllocaInst *, 16> AllocaVec;

    // A temporary cache of local allocas that are always accessed safely and will never
    // escape the current function. If these variables are never retagged, then we can skip
    // tracking their provenance at runtime, since they will never be a source of UB.
    SmallSet<AllocaInst *, 16> LocalSafeAllocas;

    // Pointers to the sections of the thread-local array (BS.ParamTLS) where the provenance
    // values for each argument are stored. Whenever we need to get the provenance for an argument,
    // we take its pointer from this array and then insert the necessary instructions to load it from
    // thread-local storage within the prologue of the function. 
    DenseMap<Argument *, SmallVector<ProvenancePointer>> ArgumentProvenance;

    // The "provenance-carrying components" of each type, cached for performance.
    DenseMap<Type *, SmallVector<ProvenanceComponent>> ProvenanceComponents;

    // Loaded provenanced values, which are indexed by each provenance carrying component. For example,
    // if `ProvenanceComponents[V]` has length 3, and we have loaded the third provenance value for
    // this value, then `ProvenanceMap[std::make_pair(V, 2)]` would return the loaded provenance value.
    DenseMap<std::pair<Value *, unsigned>, LoadedProvenance> ProvenanceMap;

    BorrowSanitizerVisitor(Function &F, BorrowSanitizer &BS, const StackSafetyGlobalInfo *const SSGI,
                            AliasAnalysis &AA, MemorySSA &MSSA, const TargetLibraryInfo &TLI)
        : F(F), BS(BS), DIB(*F.getParent(), /*AllowUnresolved*/ false), C(BS.C),
            AA(AA), MSSA(MSSA), TLI(&TLI), SSGI(SSGI)
    {
        removeUnreachableBlocks(F);
        initPrologue();
    }

    // Populates the array of argument provenance pointers and initializes the start and end of the
    // function prologue.
    void initPrologue() {
        IRBuilder<> IRB(&F.getEntryBlock(), F.getEntryBlock().getFirstNonPHIIt());
        Value *Array = BS.ParamTLS;
        
        for (auto &Arg : F.args()) {
            SmallVector<ProvenanceComponent> *Components = getProvenanceComponents(IRB, Arg.getType());
            for (auto &C : *Components) {
                ProvenancePointer Ptr = C.getPointerToProvenance(IRB, Array);
                ArgumentProvenance[&Arg].push_back(Ptr);
                Value *Offset = IRB.CreateMul(C.NumProvenanceValues, BS.ProvenanceSize);
                Array = offsetPointer(IRB, Array, Offset);
            }
        }

        FnPrologueStart = IRB.CreateCall(BS.BsanFuncPushFrame, {});
        FnPrologueEnd = IRB.CreateIntrinsic(Intrinsic::donothing, {}, {});
    }


    // Will fail with an error if anything other than a scalar provenance value is present.
    // If no provenance has been assigned yet, then the null provenance value is returned.
    ScalarProvenance assertSingleProvenanceAtIndex(Value *V, unsigned Idx) {
        std::optional<LoadedProvenance> OptProv = getProvenanceAtIndex(V, Idx);
        if(OptProv.has_value()) { 
            LoadedProvenance Prov = OptProv.value();
            if(Prov.isScalar()) {
                return Prov.getScalarProvenance().value();
            }else{
                report_fatal_error("Expected scalar provenance, but found vector provenance!");
            }  
        }else{
            return BS.NullScalarProvenance;
        }
    }

    ScalarProvenance assertSingleProvenance(Value *V) {
        return assertSingleProvenanceAtIndex(V, 0);
    }

    // Will fail with an error if anything other than a vector provenance value is present.
    // If no provenance has been assigned yet, then the null provenance value is returned.
    VectorProvenance assertVectorProvenanceAtIndex(Value *V, unsigned Idx) {
        std::optional<LoadedProvenance> OptProv = getProvenanceAtIndex(V, Idx);
        if(OptProv.has_value()) { 
            LoadedProvenance Prov = OptProv.value();
            if(Prov.isVector()) {
                return Prov.getVectorProvenance().value();
            }else{
                report_fatal_error("Expected scalable vector provenance, but found scalar provenance!");
            }  
        }else{
            return BS.NullVectorProvenance;
        }
    }

    VectorProvenance assertVectorProvenance(Value *V) {
        return assertVectorProvenanceAtIndex(V, 0);
    }

    // Asserts that there is either a provenance value at the given index, or that no provenance
    // values have been loaded for the given value, in which case we return the null provenance value.
    // Used whenever we need a provenance value but do not care whether it's a vector or scalar. Checks
    // for consistency against a given provenance component.
    LoadedProvenance assertProvenanceAtIndex(Value *V, ProvenanceComponent &Comp, unsigned Idx) {
        std::optional<LoadedProvenance> OptProv = getProvenanceAtIndex(V, Idx);
        if(OptProv.has_value()) {
            LoadedProvenance Prov = OptProv.value();
            if(Prov.isVector() != Comp.isVector()) {
                report_fatal_error("Provenance type mismatch.");
            }
            return Prov;
        }else{
            if(Comp.isVector()) {
                return BS.NullVectorProvenance;
            }else{
                return BS.NullScalarProvenance;
            }
        }
    }

    // Asserts that there is either a provenance value at the given index, or that no provenance
    // values have been loaded for the given value. Does not reutrn the null provenance value, and
    // does not check for consistency. This should never be used directly, since it does not check
    // that the given provenance value is consistent with the caller's assumption about whether or
    // not a scalar or vector provenance value is required.
    std::optional<LoadedProvenance> getProvenanceAtIndex(Value *V, unsigned Idx) {
        if (Argument *A = dyn_cast<Argument>(V)) {
            // We always need to load the provenance for arguments right at the
            // beginning of the function. Otherwise, subsequent function calls could
            // overwrite these values before they're first read from the thread-local array
            IRBuilder<> EntryIRB(FnPrologueEnd);
            if (ArgumentProvenance.count(A)) {
                if(ArgumentProvenance[A].size() == 0){
                    report_fatal_error("Empty argument provenance!");
                }
                for (auto [ArgIdx, ArgPtr] : llvm::enumerate(ArgumentProvenance[A])) {
                    setProvenanceAtIndex(V, ArgIdx, loadProvenance(EntryIRB, ArgPtr));
                }
            }
        }
        std::pair<Value *, unsigned> Key = std::make_pair(V, Idx);
        if(ProvenanceMap.count(Key)) {
            return ProvenanceMap[Key];
        } else {
            return std::nullopt;
        }
    }

    void setProvenanceAtIndex(Value *V, unsigned Idx, LoadedProvenance Prov) {
        std::pair<Value *, unsigned> Key = std::make_pair(V, Idx);
        ProvenanceMap[Key] = Prov;
    }

    void setProvenance(Value *V, LoadedProvenance Prov) {
        setProvenanceAtIndex(V, 0, Prov);
    }

    // Returns the list of provenance-carrying components for a type.
    SmallVector<ProvenanceComponent> *getProvenanceComponents(IRBuilder<> &IRB, Type *Ty) {
        if(ProvenanceComponents.contains(Ty)){
            return &ProvenanceComponents[Ty];
        }else{
            Value *Zero = ConstantInt::get(BS.IntptrTy, 0);
            populateProvenanceComponents(IRB, ProvenanceComponents[Ty], Ty, Ty, Zero, Zero);
            return &ProvenanceComponents[Ty];
        }
    }

    // Recursively populates a given vector with the list of provenance-carrying components for
    // a type. A `ProvenanceComponent` contains all of the static information that we need about
    // the location of each pointer within a type.
    std::tuple<Value *, Value *> populateProvenanceComponents(
            IRBuilder<> &IRB, 
            SmallVector<ProvenanceComponent> &Components,
            Type *ParentTy, 
            Type *CurrentTy, 
            Value *ByteOffset, 
            Value *ProvOffset
            
    ) {
        Value *TypeSize = IRB.CreateTypeSize(BS.IntptrTy, BS.DL->getTypeAllocSize(CurrentTy));
        Value *NextProvOffset = ProvOffset;
        switch (CurrentTy->getTypeID()) {
            case Type::PointerTyID: {
                ProvenanceComponent Comp(
                    ByteOffset, 
                    TypeSize, 
                    ProvOffset, 
                    BS.One, 
                    ElementCount::get(1, false)
                );
                Components.push_back(Comp);
                NextProvOffset = IRB.CreateAdd(ProvOffset, BS.One);
            } break;
            case Type::StructTyID: {
                StructType *ST = cast<StructType>(CurrentTy);
                Value *CurrByteOffset = ByteOffset;
                for (const auto ElemType : ST->elements()) {
                    auto [BOffset, POffset] = populateProvenanceComponents(
                        IRB, Components, ParentTy, ElemType, CurrByteOffset, NextProvOffset);
                    CurrByteOffset = BOffset;
                    NextProvOffset = POffset;
                }
            } break;
            case Type::ArrayTyID: {
                ArrayType *AT = cast<ArrayType>(CurrentTy);
                Value *CurrByteOffset = ByteOffset;
                for (unsigned Idx = 0; Idx < AT->getNumElements(); ++Idx) {
                    auto [BOffset,POffset] = populateProvenanceComponents(
                            IRB, Components, ParentTy, AT->getElementType(), CurrByteOffset, NextProvOffset);
                    CurrByteOffset = BOffset;
                    NextProvOffset = POffset;
                }
            } break;
            case Type::ScalableVectorTyID:
            case Type::FixedVectorTyID: {
                FixedVectorType *VT = cast<FixedVectorType>(CurrentTy);
                Value *CurrByteOffset = ByteOffset;
                if(VT->getElementType()->isPointerTy()){
                    for (unsigned Idx = 0; Idx < VT->getElementCount().getFixedValue(); ++Idx) {
                        auto [BOffset,POffset] = populateProvenanceComponents(
                                IRB, Components, ParentTy, VT->getElementType(), CurrByteOffset, NextProvOffset);
                        CurrByteOffset = BOffset;
                        NextProvOffset = POffset;
                    }
                }
            } break;
            default: break;
        }
        Value *NextByteOffset = IRB.CreateAdd(ByteOffset, TypeSize);
        return std::make_tuple(NextByteOffset, NextProvOffset);
    }
    
    // Computes the offset in terms of provenance components for an index into an aggregate or array value.
    // Used for implementing `extractelement` and `insertelement`. 
    std::tuple<Type *, uint64_t> offsetIntoProvenanceIndex(IRBuilder<> &IRB, Type *CurrentTy, uint64_t Idx, uint64_t PrevOffset = 0) {            
        switch (CurrentTy->getTypeID()) {
            case Type::StructTyID: {
                StructType *ST = cast<StructType>(CurrentTy);
                assert(Idx < ST->getNumElements() && "Index out of bounds for struct type.");
                uint64_t Offset = PrevOffset;
                for (unsigned CurrIdx = 0; CurrIdx < Idx; ++CurrIdx) {
                    Type *ElemType = ST->getElementType(CurrIdx);
                    SmallVector<ProvenanceComponent> *Components = getProvenanceComponents(IRB, ElemType);
                    Offset += Components->size();
                }
                return std::make_tuple(ST->getElementType(Idx), Offset);
            } break;
            case Type::ArrayTyID: {
                ArrayType *AT = cast<ArrayType>(CurrentTy);
                assert(Idx < AT->getNumElements() && "Index out of bounds for array type.");
                SmallVector<ProvenanceComponent> *Components = getProvenanceComponents(IRB, AT->getElementType());
                return std::make_tuple(AT->getElementType(), PrevOffset + Components->size());
            } break;
            default: {
                report_fatal_error("Cannot index into a non-struct or non-array type.");
            }
        }
    }

    // Stores a provenance value into shadow memory, starting at the given object address.
    void storeProvenanceToShadow(IRBuilder<> &IRB, Value *ObjAddr, LoadedProvenance Prov) {
        if(Prov.isVector()) {
            VectorProvenance PV = Prov.getVectorProvenance().value();
            IRB.CreateCall(BS.BsanFuncShadowStoreVector, {ObjAddr, PV.Length, PV.IDVector, PV.TagVector, PV.InfoVector});
        }else{
            ScalarProvenance PS = Prov.getScalarProvenance().value();
            Value *ShadowPointer = IRB.CreateCall(BS.BsanFuncGetShadowDest, {ObjAddr});
            storeSingleProvenanceValue(IRB, PS, ShadowPointer);
        }
    }

    // Stores a provenance values into an array, where we expect that each element of the array
    // will be a provenance value.
    Value *storeProvenance(IRBuilder<> &IRB, LoadedProvenance Prov, Value *Dest) {
        if(Prov.isVector()) {
            VectorProvenance PV = Prov.getVectorProvenance().value();
            // To store a vector provenance value into the array, we need to join each of its components into
            // an array of provenance values. To do this, we call a special helper function in our runtime library.
            // This conversion means that storing and loading vectors of provenance values will likely be much more
            // expensive than scalar provenance values. 
            IRB.CreateCall(BS.BsanFuncJoinProv, {Dest, PV.Length, PV.IDVector, PV.TagVector, PV.InfoVector});
            Value *Offset = IRB.CreateMul(BS.ProvenanceSize, PV.Length);
            return offsetPointer(IRB, Dest, Offset);
        }else{
            ScalarProvenance PS = Prov.getScalarProvenance().value();
            return storeSingleProvenanceValue(IRB, PS, Dest);
        }
    }

    // Loads a provenance value into shadow memory, starting at the given object address.
    LoadedProvenance loadProvenanceFromShadow(IRBuilder<> &IRB, ProvenanceComponent &Comp, Value *ObjAddr) {
        if(Comp.isVector()) {
            // We're dealing with a scalable vector of pointers.
            // First, we create vectors to store each of the three components 
            // of provenance values. We can't create an array of provenance values 
            // because the vector might be scalable, and arrays need to have a static size.
            Value *IDVector, *TagVector, *InfoVector;
            std::tie(IDVector, TagVector, InfoVector) = allocateVectorProvenances(IRB, Comp.Elems);

            // When we load a vector from memory , we do the reverse of storing it; we split each of the provenance
            // values into their components, storing them into each of the component vectors.
            IRB.CreateCall(BS.BsanFuncShadowLoadVector, {ObjAddr, Comp.NumProvenanceValues, IDVector, TagVector, InfoVector});
            return LoadedProvenance(VectorProvenance(IDVector, TagVector, InfoVector, Comp.NumProvenanceValues));
        }else{
            Value *ShadowPointer = IRB.CreateCall(BS.BsanFuncGetShadowSrc, {ObjAddr});
            return loadSingleProvenanceValue(IRB, ShadowPointer);
        }
    }

    // Stores a provenance value into an array, where we expect that each element of the array
    // will be a provenance value.
    LoadedProvenance loadProvenance(IRBuilder<> &IRB, ProvenancePointer Prov) {
        if(Prov.isVector()) {
            // We're dealing with a scalable vector of pointers.
            // First, we create vectors to store each of the three components 
            // of provenance values. We can't create an array of provenance values 
            // because the vector might be scalable, and arrays need to have a static size.
            Value *IDVector, *TagVector, *InfoVector;
            std::tie(IDVector, TagVector, InfoVector) = allocateVectorProvenances(IRB, Prov.Elems);
            // When we load a vector from memory , we do the reverse of storing it; we split each of the provenance
            // values into their components, storing them into each of the component vectors.
            IRB.CreateCall(BS.BsanFuncSplitProv, {Prov.Base, Prov.Length, IDVector, TagVector, InfoVector});
            return LoadedProvenance(VectorProvenance(IDVector, TagVector, InfoVector, Prov.Length));
        }else{
            return loadSingleProvenanceValue(IRB, Prov.Base);
        }
    }

    // Loads a single provenance value from either shadow or main memory.
    LoadedProvenance loadSingleProvenanceValue(IRBuilder<> &IRB, Value *Src) {
        Value *IDPtr, *TagPtr, *InfoPtr;
        std::tie(IDPtr, TagPtr, InfoPtr) = getProvenanceElements(IRB, Src);
        Value *ID = IRB.CreateLoad(BS.IntptrTy, IDPtr);
        Value *Tag = IRB.CreateLoad(BS.IntptrTy, TagPtr);
        Value *Info = IRB.CreateLoad(BS.PtrTy, InfoPtr);
        return LoadedProvenance(ScalarProvenance(ID, Tag, Info));
    }

    // Stores a single provenance value from either shadow or main memory.
    Value *storeSingleProvenanceValue(IRBuilder<> &IRB, ScalarProvenance P, Value *Dest) {
        Value *IDPtr, *TagPtr, *InfoPtr;
        std::tie(IDPtr, TagPtr, InfoPtr) = getProvenanceElements(IRB, Dest);
        IRB.CreateStore(P.ID, IDPtr);
        IRB.CreateStore(P.Tag, TagPtr);
        IRB.CreateStore(P.Info, InfoPtr);
        return offsetPointer(IRB, Dest, BS.ProvenanceSize);
    }

    // Calculates GEP offsets into each component of a provenance value.
    std::tuple<Value *, Value *, Value *> getProvenanceElements(IRBuilder<> &IRB, Value *Prov) {
        Value *ZeroIdx = ConstantInt::get(IRB.getInt64Ty(), 0);
        // When indexing into a struct, subsequent indices must be of type i32.
        Value *IDPtr = IRB.CreateGEP(BS.ProvenanceTy, Prov, {ZeroIdx, ConstantInt::get(IRB.getInt32Ty(), 0)});
        Value *TagPtr = IRB.CreateGEP(BS.ProvenanceTy, Prov, {ZeroIdx, ConstantInt::get(IRB.getInt32Ty(), 1)});
        Value *InfoPtr = IRB.CreateGEP(BS.ProvenanceTy, Prov, {ZeroIdx, ConstantInt::get(IRB.getInt32Ty(), 2)});
        return std::make_tuple(IDPtr, TagPtr, InfoPtr);
    }

    // Allocates vectors of each provenance component for a vector provenance value.
    std::tuple<Value *, Value *, Value *> allocateVectorProvenances(IRBuilder<> &IRB, ElementCount Elems) {                
        Value *IDVector = IRB.CreateAlloca(VectorType::get(BS.IntptrTy, Elems));
        Value *TagVector = IRB.CreateAlloca(VectorType::get(BS.IntptrTy, Elems));
        Value *InfoVector = IRB.CreateAlloca(VectorType::get(BS.PtrTy, Elems));
        return std::make_tuple(IDVector, TagVector, InfoVector);
    }

    // A helper function to offset a pointer by the given number of bytes.
    Value *offsetPointer(IRBuilder<> &IRB, Value *Pointer, Value *Offset) {
        Value *Base = IRB.CreatePointerCast(Pointer, BS.IntptrTy);
        Base = IRB.CreateAdd(Base, Offset);
        return IRB.CreateIntToPtr(Base, BS.PtrTy);
    }

    // The main function of the instrumentation pass. 
    bool runOnFunction() {
        // First, we reorder every instruction in reverse postorder. This guarantees that when we visit
        // an instruction in a given block, we will have already visited each of the instructions in 
        // all of the incoming blocks in the CFG. This is expensive, but is simplifies subsequent steps of
        // our instrumentation pass. Whenever we visit an instruction, we can assume that we have already computed
        // the provenance for its inputs. In the future, if this becomes a major performance issue, then we can do
        // a simple depth-first reordering, like MemorySanitizer. This would require splitting up our insturmentation;
        // first, we'd visit all provenance "sources", like allocations and load instructions, and then return to add runtime
        // checks to provenance "sinks": instructions that require provenance for run-time checks. 
        for (BasicBlock *BB : ReversePostOrderTraversal<BasicBlock *>(&F.getEntryBlock())) {
            visit(*BB);
        }
        
        NumAllocaEliminated += LocalSafeAllocas.size();

        if (Instructions.empty())
            return false;

        // Initialize all stack allocations, including calls to allocate metadata objects. This has the side effect
        // of reordering all allocas---both static and dynamic---to occur within the prologue. This makes it easier to
        // implement the subsequent calls to deallocate metadata when we deinitialize the stack. Instead of having to compute
        // which allocations are live along each execution path, we can just assume that every allocation is live. 
        initStack();

        // This is where most of the work occurs; we visit each instruction and insert every run-time check in a single pass.
        for (Instruction *I : Instructions) {
            InstVisitor<BorrowSanitizerVisitor>::visit(*I);
        }

        // Deinitializes the stack, adding cleanup blocks before every instruction that can exit the function. This ensures
        // that our metadata is deinitialized in every situation---even when an exception is thrown. 
        deinitStack();

        return true;
    }

    void initStack() {
        for (AllocaInst *AI : AllocaVec) {
            initializeProvenanceForStaticAllocation(AI);
        }
    }

    void deinitStack() {
        EscapeEnumerator EE(F, "bsan_cleanup", true);
        while (IRBuilder<> *AtExit = EE.Next()) {
            for (AllocaInst *AI : AllocaVec) {
                processDeallocation(*AtExit, AI);
            }
            InstrumentationIRBuilder::ensureDebugInfo(*AtExit, F);
            AtExit->CreateCall(BS.BsanFuncPopFrame);
        }
    }

    // Allocates object metadata for a stack allocation.
    void initializeProvenanceForStaticAllocation(AllocaInst *AI) {
        AI->moveBefore(FnPrologueStart->getIterator());
        IRBuilder<> IRB(FnPrologueStart);
        TypeSize TS = BS.getAllocaSizeInBytes(*AI);
        Value *Size = IRB.CreateTypeSize(BS.IntptrTy, TS);
        registerAllocation(IRB, AI, Size);
    }


    // Allocates object metadata for a heap allocation.
    void initializeProvenanceForDynamicAllocation(IRBuilder<> &IRB, CallBase *CB,
        std::optional<APInt> &AllocSize) {
        if(AllocSize.has_value()) {
            Value *Size = ConstantInt::get(BS.IntptrTy, AllocSize->getZExtValue());
            registerAllocation(IRB, CB, Size);
        }
    }
    
    // Allocates object metadata for a stack or heap allocation.
    void registerAllocation(IRBuilder<> &IRB, Value *Address, Value *Size) {
        Value *ID = IRB.CreateCall(BS.BsanFuncNewAllocID, {});
        Value *Tag = IRB.CreateCall(BS.BsanFuncNewBorrowTag, {});
        Value *Info = IRB.CreateCall(BS.BsanFuncAlloc, {ID, Tag, Address, Size});
        setProvenance(Address, ScalarProvenance(ID, Tag, Info));
    }


    // We only instrument allocations that have a non-zero size.
    bool shouldInstrumentAlloca(AllocaInst &AI) {
        bool ShouldInstrument =
            (AI.getAllocatedType()->isSized() &&
                !BS.getAllocaSizeInBytes(AI).isZero());
        return ShouldInstrument;
    }

    // We can ignore accesses through pointers that alias with
    // the allocas that we skip instrumenting.
    bool ignoreAccess(Instruction *Inst, Value *Ptr) {
        AllocaInst *AI = findAllocaForValue(Ptr);
        return AI && LocalSafeAllocas.contains(AI);
    }
    
    // Deallocates a pointer.
    void processDeallocation(IRBuilder<> &IRB, Value *Val) {
        ScalarProvenance Prov = assertSingleProvenance(Val);
        IRB.CreateCall(BS.BsanFuncDealloc, {Val, Prov.ID, Prov.Tag, Prov.Info});
    }
    
    using InstVisitor<BorrowSanitizerVisitor>::visit;

    // We use this visitor function when reordering instructions in reverse postorder;
    // none of the other visitors are called until the subsequent step, after we initialize
    // the stack.
    void visit(Instruction &I) {
        if (I.getMetadata(LLVMContext::MD_nosanitize))
            return;
        if (I.getOpcode() == Instruction::Alloca) {
            AllocaInst &AI = static_cast<AllocaInst &>(I);
            if (shouldInstrumentAlloca(AI)) {
                if(SSGI && SSGI->isSafe(AI) && !isEscapeSource(&AI)) {
                    LocalSafeAllocas.insert(&AI);
                }else{
                    AllocaVec.push_back(&AI);
                }
            }
            return;
        }else if (CallBase::classof(&I)) {
            CallBase *CB = dyn_cast<CallBase>(&I);
            if(CB->getIntrinsicID() == Intrinsic::retag) {
                assert(CB->arg_size() > 0 && "Missing arguments to retag.");
                Value *PtrToRetag = CB->getArgOperand(0);
                for(auto AI : LocalSafeAllocas) {
                    if(AA.alias(AI, PtrToRetag) != AliasResult::NoAlias) {
                        AllocaVec.push_back(AI);
                    }
                }
            }
        }
        Instructions.push_back(&I);
    }

    void visitCallBase(CallBase &CB) {
        LibFunc TLIFn;
        Function *Callee = CB.getCalledFunction();
        // If we're calling a heap allocation or deallocation function,
        // then we can skip handling argument provenance and defer to our
        // run-time calls.
        LibFunc LF;
        if(Callee && TLI->getLibFunc(*Callee, TLIFn) && TLI->has(TLIFn)) {
            std::optional<APInt> AllocSize = getAllocSize(&CB, TLI);
            if (isAllocLikeFn(&CB, TLI)) {
                IRBuilder<> IRB = getInsertionPointAfterCall(&CB);
                initializeProvenanceForDynamicAllocation(IRB, &CB, AllocSize);
                return;
            } else if(isReallocLikeFn(Callee)) {
                IRBuilder<> IRB = getInsertionPointAfterCall(&CB);
                initializeProvenanceForDynamicAllocation(IRB, &CB, AllocSize);
                Value *Operand = getReallocatedOperand(&CB);
                processDeallocation(IRB, Operand);
                return;
            } else if (isLibFreeFunction(Callee, TLIFn)) {
                Value* Operand = getFreedOperand(&CB, TLI);
                IRBuilder<> IRB = getInsertionPointAfterCall(&CB);
                processDeallocation(IRB, Operand);
                return;
            }
        }


        // If we've made it here, then we don't have a hard-coded way to handle this
        // function. We need to pass its arguments into our thread-local array, and then
        // read the provenance for the return value.
        InstrumentationIRBuilder Before(&CB); 
    
        // Store the provenance for each argument into the thread-local storage for parameters.
        // Because the process for computing provenance components is deterministic, we can guarantee
        // that the callee will expect a provenance value everywhere it's been stored here, unless we're
        // dealing with a situation where function bindings are incorrect, which is undefined behavior.
        Value *ParamArray = BS.ParamTLS;
        for (const auto &[i, A] : llvm::enumerate(CB.args())) {
            SmallVector<ProvenanceComponent> *Components = getProvenanceComponents(Before, A->getType());
            for (const auto &[Idx, Comp] : llvm::enumerate(*Components)) {
                LoadedProvenance Prov = assertProvenanceAtIndex(A, Comp, Idx);
                ParamArray = storeProvenance(Before, Prov, ParamArray);
            }
        }

        // Unsized return types do not have provenance, so we can skip handling the return array.
        if (CB.getType()->isSized()) {
            // Don't emit the epilogue for musttail call returns.
            // We can assume that the return value is processed later up the callstack.
            if (isa<CallInst>(CB) && cast<CallInst>(CB).isMustTailCall())
                return;
            

            SmallVector<ProvenanceComponent> *ReturnComponents = getProvenanceComponents(Before, CB.getType());
            
            // We need to do some extra work here to compute where to insert our instructions,
            // since some function calls occur within terminators.
            IRBuilder<> After = getInsertionPointAfterCall(&CB);

            // Load each provenance component for the return type from the thread-local return value array.
            // Also, compute the byte-width of the provenance components that we expect to be here. If the function
            // that we are calling is uninstrumented, then we need ensure that the return array is populated with
            // default values. 
            Value *ReturnArray = BS.RetvalTLS;
            Value *RetvalByteWidth = BS.Zero;    
            for (const auto &[Idx, Comp] : llvm::enumerate(*ReturnComponents)) {               
                ProvenancePointer Ptr = Comp.getPointerToProvenance(After, ReturnArray);
                setProvenanceAtIndex(&CB, Idx, loadProvenance(After, Ptr));

                Value *ByteWidth = Before.CreateMul(Comp.NumProvenanceValues, BS.ProvenanceSize);
                RetvalByteWidth = Before.CreateAdd(RetvalByteWidth, ByteWidth);
                ReturnArray = offsetPointer(After, ReturnArray, ByteWidth);
            }

            Function *Func = CB.getCalledFunction();
            if (!Func || (Func && Func->isDeclaration())) { 
                // If a function is external, then there's no way to tell if we've instrumented it.
                // To ensure that our provenance values are valid, we need to zero-initialize the return array
                Before.CreateMemSet(BS.RetvalTLS, ConstantInt::get(BS.Int8Ty, 0), RetvalByteWidth, Align(1));
            }
        }
    }

    void visitIntrinsicInst(IntrinsicInst &I) {
        switch (I.getIntrinsicID()) {
            case Intrinsic::retag: {
                ScalarProvenance Prov = assertSingleProvenance(I.getOperand(0));
                CallInst *CIRetag = CallInst::Create(BS.BsanFuncRetag, {
                        Prov.ID, 
                        Prov.Tag, 
                        Prov.Info, 
                        I.getOperand(0), 
                        I.getOperand(1), 
                        I.getOperand(2), 
                        I.getOperand(3)
                });
                ReplaceInstWithInst(&I, CIRetag);
            } break;
            default:
                break;
        }
    }

    // Inserts a check to validate a read access.
    void insertReadCheck(IRBuilder<> &IRB, Instruction *Inst, Value *Ptr, Value *Size) {
        if(!ignoreAccess(Inst, Ptr)) {
            ScalarProvenance Prov = assertSingleProvenance(Ptr);
            IRB.CreateCall(BS.BsanFuncRead, {Prov.ID, Prov.Tag, Prov.Info, Ptr, Size});
        }else{
            NumReadsEliminated += 1;
        }
    }

    // Inserts a check to validate a write access.
    void insertWriteCheck(IRBuilder<> &IRB, Instruction *Inst, Value *Ptr, Value *Size) {
        if(!ignoreAccess(Inst, Ptr)) {
            ScalarProvenance Prov = assertSingleProvenance(Ptr);
            IRB.CreateCall(BS.BsanFuncWrite, {Prov.ID, Prov.Tag, Prov.Info, Ptr, Size});
        }else{
            NumWritesEliminated += 1;
        }
    }          

    void visitLoadInst(LoadInst &LI) {
        IRBuilder<> IRB(&LI);
        Value *Ptr = LI.getPointerOperand();
        
        Value *Size = IRB.CreateTypeSize(BS.IntptrTy, BS.DL->getTypeAllocSize(LI.getType()));
        insertReadCheck(IRB, &LI, Ptr, Size);    

        // Load provenance for the value from shadow memory.
        SmallVector<ProvenanceComponent> *Components = getProvenanceComponents(IRB, LI.getType());
        Value *Base = LI.getPointerOperand();
        for (const auto &[Idx, Comp] : llvm::enumerate(*Components)) {
            ShadowFootprint Footprint = Comp.Footprint;
            Value *ObjAddr = offsetPointer(IRB, Base, Footprint.ByteOffset);
            LoadedProvenance Prov = loadProvenanceFromShadow(IRB, Comp, ObjAddr);
            setProvenanceAtIndex(&LI, Idx, Prov);
        }
    }

    void visitStoreInst(StoreInst &SI) {
        IRBuilder<> IRB(&SI);
        Value *Ptr, *Val;
        Ptr = SI.getPointerOperand();
        Val = SI.getValueOperand();

        Value *Size = IRB.CreateTypeSize(BS.IntptrTy, BS.DL->getTypeAllocSize(Val->getType()));
        insertReadCheck(IRB, &SI, Ptr, Size);          

        // Store provenance for the value into shadow memory.
        SmallVector<ProvenanceComponent> *Components = getProvenanceComponents(IRB, Val->getType());
        Value *Base = SI.getPointerOperand();
        for (const auto &[Idx, Comp] : llvm::enumerate(*Components)) {
            ShadowFootprint Footprint = Comp.Footprint;
            Value *ObjAddr = offsetPointer(IRB, Base, Footprint.ByteOffset);
            if(Comp.isVector()) {
                std::optional<LoadedProvenance> Prov = assertVectorProvenanceAtIndex(SI.getValueOperand(), Idx);
                if(Prov.has_value()) {
                    storeProvenanceToShadow(IRB, ObjAddr, Prov.value());
                } else {
                    // If the value is not a vector, then we need to zero-initialize the shadow memory.
                    Value *ByteWidth = IRB.CreateMul(Comp.NumProvenanceValues, BS.ProvenanceSize);
                    IRB.CreateCall(BS.BsanFuncShadowClear, {ObjAddr, Footprint.ByteWidth});
                }
            }else{
                LoadedProvenance Prov = assertSingleProvenanceAtIndex(SI.getValueOperand(), Idx);
                storeProvenanceToShadow(IRB, ObjAddr, Prov);
            }                
        }
    }

    void visitGetElementPtrInst(GetElementPtrInst &I) { 
        // Pointer arithmetic does not affect provenance, so we can propagage the provenance
        // of the input to the output value.
        LoadedProvenance Prov = assertSingleProvenance(I.getPointerOperand());
        setProvenance(&I, Prov);
    }


    void visitPtrToIntInst(PtrToIntInst &I) {
        // Mark this pointer as "exposed", indicating that its provenance can be used
        // to validate an access through a wildcard pointer. Tree Borrows does not implement
        // this behavior yet, but it will in the future. 
        IRBuilder<> IRB(&I);
        ScalarProvenance Prov = assertSingleProvenanceAtIndex(&I, 0);
        IRB.CreateCall(BS.BsanFuncExposeTag, {Prov.ID, Prov.Tag, Prov.Info});
    }

    void visitIntToPtrInst(IntToPtrInst &I) {
        // Pointers converted from integers receive a wildcard provenance value.
        setProvenance(&I, BS.WildcardProvenance);
    }

    void visitExtractValueInst(ExtractValueInst &EI) {
        IRBuilder<> IRB(&EI);
        Value *AggregateSrc = EI.getAggregateOperand();

        SmallVector<ProvenanceComponent> *SrcComponents = getProvenanceComponents(IRB, AggregateSrc->getType());
        SmallVector<ProvenanceComponent> *DestComponents = getProvenanceComponents(IRB, EI.getType());

        // We don't need to do anything if the value that we're loading doesn't have any provenance
        if(DestComponents->size() > 0) {
            Type *CurrType = AggregateSrc->getType();

            // For each index into the aggregate, compute and add the offset for the provenance component
            // index. The final value will point to the start of the series of provenance components that
            // we need to extract from the aggregate.
            uint64_t CurrIdx = 0;
            for (auto &Idx: EI.indices()) {
                std::tie(CurrType, CurrIdx) = offsetIntoProvenanceIndex(IRB, CurrType, Idx, CurrIdx);
            }
            
                for (auto [Idx, Comp] : llvm::enumerate(*DestComponents)) { 
                LoadedProvenance Prov = assertProvenanceAtIndex(AggregateSrc, Comp, CurrIdx + Idx);
                setProvenanceAtIndex(&EI, Idx, Prov);
            }
        }
    }

    void visitInsertValueInst(InsertValueInst &II) {
        IRBuilder<> IRB(&II);
        Value *ToInsert = II.getInsertedValueOperand();
        Value *AggregateDest = II.getAggregateOperand();
        
        SmallVector<ProvenanceComponent> *SrcComponents = getProvenanceComponents(IRB, ToInsert->getType());
        SmallVector<ProvenanceComponent> *DestComponents = getProvenanceComponents(IRB, AggregateDest->getType()); 
    
        // We don't need to do anything if the aggregate that we're inserting 
        // into doesn't have any provenance.
        if(SrcComponents->size() > 0) {
            Type *CurrType = AggregateDest->getType();
            uint64_t CurrIdx = 0;

            // For each index into the aggregate, compute and add the offset for the provenance component
            // index. The final value will be the base index that we need to use for inserting each loaded
            // provenance value from the value that's being inserted.
            for (auto &Idx: II.indices()) {
                std::tie(CurrType, CurrIdx) = offsetIntoProvenanceIndex(IRB, CurrType, Idx, CurrIdx);
            }

            for (auto [OffsetIdx, Comp] : llvm::enumerate(*SrcComponents)) { 
                LoadedProvenance Prov = assertProvenanceAtIndex(ToInsert, Comp, OffsetIdx);
                setProvenanceAtIndex(AggregateDest, CurrIdx + OffsetIdx, Prov);
            }
        }
    }

    void visitSelectInst(SelectInst &SI) {
        IRBuilder<> IRB(&SI);
        SmallVector<ProvenanceComponent> *Components = getProvenanceComponents(IRB, SI.getType());

        // A select instruction returns one of two inputs depending on a boolean value. This means that if
        // the output type has provenance, then we need to conditionally assign the result a provenance value.
        for (auto [Idx, Comp] : llvm::enumerate(*Components)) {
            if(Comp.isVector()) {

                // For scalable vectors, we need a select instruction for each component vector, as well as
                // for the length. Even though the length of a scalable vector will be fixed at runtime (only
                // the scaling factor is dynamically determined, and remains fixed), we still need to account for
                // null provenance inputs, and the length of the null vector provenance is zero.
                std::optional<VectorProvenance> OptProvL = assertVectorProvenanceAtIndex(SI.getTrueValue(), Idx);
                std::optional<VectorProvenance> OptProvR = assertVectorProvenanceAtIndex(SI.getFalseValue(), Idx);
                
                if(OptProvL.has_value() || OptProvR.has_value()) {
                    Value *TagL, *TagR, *InfoL, *InfoR, *IDL, *IDR, *LenL, *LenR;
                    if (OptProvL.has_value()) {
                        VectorProvenance ProvVec = OptProvL.value();
                        IDL = ProvVec.IDVector;
                        TagL = ProvVec.TagVector;
                        InfoL = ProvVec.InfoVector;
                        LenL = ProvVec.Length;
                    } else{
                        IDL = BS.Zero;
                        TagL = BS.Zero;
                        InfoL = ConstantPointerNull::get(BS.PtrTy);
                        LenL = BS.Zero;
                    }
                    if (OptProvR.has_value()) {
                        VectorProvenance ProvVec = OptProvR.value();
                        IDR = ProvVec.IDVector;
                        TagR = ProvVec.TagVector;
                        InfoR = ProvVec.InfoVector;
                        LenR = ProvVec.Length;
                    } else{
                        IDR = BS.Zero;
                        TagR = BS.Zero;
                        InfoR = ConstantPointerNull::get(BS.PtrTy);
                        LenR = BS.Zero;
                    }

                    Value *ID = IRB.CreateSelect(SI.getCondition(), IDL, IDR);
                    Value *Tag = IRB.CreateSelect(SI.getCondition(), TagL, TagR);
                    Value *Info = IRB.CreateSelect(SI.getCondition(), InfoL, InfoR);
                    Value *Len = IRB.CreateSelect(SI.getCondition(), LenL, LenR);
                    setProvenanceAtIndex(&SI, Idx, LoadedProvenance(VectorProvenance(ID, Tag, Info, Len)));
                }
            }else{
                // For scalable provenance vectors, we just select on each of the three components.
                ScalarProvenance ProvL = assertSingleProvenanceAtIndex(SI.getTrueValue(), Idx); 
                ScalarProvenance ProvR = assertSingleProvenanceAtIndex(SI.getFalseValue(), Idx);
                
                Value *ID = IRB.CreateSelect(SI.getCondition(), ProvL.ID, ProvR.ID);
                Value *Tag = IRB.CreateSelect(SI.getCondition(), ProvL.Tag, ProvR.Tag);
                Value *Info = IRB.CreateSelect(SI.getCondition(), ProvL.Info, ProvR.Info);
                setProvenanceAtIndex(&SI, Idx, LoadedProvenance(ScalarProvenance(ID, Tag, Info)));
            }
        }
    }

    void visitPHINode(PHINode &PN) {
        IRBuilder<> IRB(&PN);
        SmallVector<ProvenanceComponent> *Components = getProvenanceComponents(IRB, PN.getType());

        // PHI nodes work similar to select instructions, but instead of two inputs, we have one for
        // each incoming basic block. Since we're visiting these instructions in reverse postorder,
        // we can guarantee that each block has been visited prior to seeing this node. Otherwise, we'd need
        // to insert the shadow PHI nodes here, and then later, after we visit every other instruction, we'd
        // return to them and "patch in" the missing input values. 
        for (auto [Idx, Comp] : llvm::enumerate(*Components)) {
            if(Comp.isVector()) {
                // TODO: we only create a PHI node for the length to handle situations where one or more
                // of the possibly incoming values has null provenance. That way, we can ensure that the
                // resulting provenance value will have a length of 0, instead of the fixed length of the
                // vector. However, if all of the inputs have provenance, then we can just assign the fixed
                // dynamic length and eliminate the extra PHI node. A similar approach could be used for 
                // select instructions.  
                PHINode *IDShadow = IRB.CreatePHI(BS.IntptrTy, PN.getNumIncomingValues(), "_bsphi_vec_id");
                PHINode *TagShadow = IRB.CreatePHI(BS.IntptrTy, PN.getNumIncomingValues(), "_bsphi_vec_tag");
                PHINode *InfoShadow = IRB.CreatePHI(BS.PtrTy, PN.getNumIncomingValues(), "_bsphi_vec_info");
                PHINode *LenShadow = IRB.CreatePHI(BS.IntptrTy, PN.getNumIncomingValues(), "_bsphi_vec_len");
                for (auto [V, BB] : llvm::zip(PN.incoming_values(), PN.blocks())) {
                    Value *Incoming = V;
                    std::optional<VectorProvenance> OptProvVec = assertVectorProvenanceAtIndex(Incoming, Idx);
                    if (OptProvVec.has_value()) {
                        VectorProvenance ProvVec = OptProvVec.value();
                        IDShadow->addIncoming(ProvVec.IDVector, BB);
                        TagShadow->addIncoming(ProvVec.TagVector, BB);
                        InfoShadow->addIncoming(ProvVec.InfoVector, BB);
                        LenShadow->addIncoming(ProvVec.Length, BB);
                    }else{
                        IDShadow->addIncoming(BS.Zero, BB);
                        TagShadow->addIncoming(BS.Zero, BB);
                        InfoShadow->addIncoming(ConstantPointerNull::get(BS.PtrTy), BB);
                        LenShadow->addIncoming(BS.Zero, BB);
                    }
                }
                setProvenanceAtIndex(&PN, Idx, LoadedProvenance(VectorProvenance(IDShadow, TagShadow, InfoShadow, LenShadow)));
            }else{
                PHINode *IDShadow = IRB.CreatePHI(BS.IntptrTy, PN.getNumIncomingValues(), "_bsphi_id");
                PHINode *TagShadow = IRB.CreatePHI(BS.IntptrTy, PN.getNumIncomingValues(), "_bsphi_tag");
                PHINode *InfoShadow = IRB.CreatePHI(BS.PtrTy, PN.getNumIncomingValues(), "_bsphi_info");
                for (auto [V, BB] : llvm::zip(PN.incoming_values(), PN.blocks())) {
                    Value *Incoming = V;
                    ScalarProvenance Prov = assertSingleProvenanceAtIndex(Incoming, Idx);
                    IDShadow->addIncoming(Prov.ID, BB);
                    TagShadow->addIncoming(Prov.Tag, BB);
                    InfoShadow->addIncoming(Prov.Info, BB);
                }
                setProvenanceAtIndex(&PN, Idx, LoadedProvenance(ScalarProvenance(IDShadow, TagShadow, InfoShadow)));
            }
        }
    }
    void visitReturnInst(ReturnInst &I) {
        IRBuilder<> IRB(&I);
        Value *RetVal = I.getReturnValue();
        if (RetVal) {
            SmallVector<ProvenanceComponent> *Components = getProvenanceComponents(IRB, RetVal->getType());
            Value *RetvalArray = BS.RetvalTLS;
            for (const auto &[Idx, Comp] : llvm::enumerate(*Components)) {
                LoadedProvenance Prov = assertProvenanceAtIndex(RetVal, Comp, Idx);
                RetvalArray = storeProvenance(IRB, Prov, RetvalArray);
            }
        }
    }

    IRBuilder<> getInsertionPointAfterCall(CallBase *CB) {
        Instruction *Next = nullptr;
        if (InvokeInst *II = dyn_cast<InvokeInst>(CB)) {                    
            if (II->getNormalDest()->getSinglePredecessor()) {
                Next = &II->getNormalDest()->front();
            } else {
                BasicBlock *NewBB =
                    SplitEdge(II->getParent(), II->getNormalDest());
                Next = &NewBB->front();
            }
        } else {
            assert(CB->getIterator() != CB->getParent()->end());
            Next = CB->getNextNode();
        }
        return IRBuilder<>(Next);
    }
};
} // end anonymous namespace

PreservedAnalyses BorrowSanitizerPass::run(Module &M, ModuleAnalysisManager &MAM) {

    BorrowSanitizer ModuleSanitizer(M);

    bool Modified = false;

    auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();

    const StackSafetyGlobalInfo *const SSGI =
        ClUseStackSafety ? &MAM.getResult<StackSafetyGlobalAnalysis>(M) : nullptr;

    for (Function &F : M) {

        Modified |= ModuleSanitizer.instrumentFunction(F, FAM, SSGI);
    }
    if (!Modified)
        return PreservedAnalyses::all();

    Modified |= ModuleSanitizer.instrumentModule(M);

    PreservedAnalyses PA = PreservedAnalyses::none();
    // GlobalsAA is considered stateless and does not get invalidated unless
    // explicitly invalidated; PreservedAnalyses::none() is not enough. Sanitizers
    // make changes that require GlobalsAA to be invalidated.
    PA.abandon<GlobalsAA>();
    return PA;
}

Instruction *BorrowSanitizer::CreateBsanModuleDtor(Module &M) {
    IRBuilder<> IRB(M.getContext());

    BsanDtorFunction = Function::createWithDefaultAttr(
        FunctionType::get(IRB.getVoidTy(), false), GlobalValue::InternalLinkage,
        0, kBsanModuleDtorName, &M);
    BsanDtorFunction->addFnAttr(Attribute::NoUnwind);

    BasicBlock *BsanDtorBB = BasicBlock::Create(*C, "", BsanDtorFunction);
    ReturnInst *BsanDtorRet = ReturnInst::Create(*C, BsanDtorBB);

    auto *FnTy = FunctionType::get(IRB.getVoidTy(), false);
    FunctionCallee DeinitFn = M.getOrInsertFunction(kBsanFuncDeinitName, FnTy);

    IRB.SetInsertPoint(BsanDtorRet);
    CallInst *DeinitCall = IRB.CreateCall(DeinitFn, {});

    appendToUsed(M, {BsanDtorFunction});
    return DeinitCall;
}

bool BorrowSanitizer::instrumentModule(Module &M) {
    // TODO: add version check.
    std::tie(BsanCtorFunction, std::ignore) =
        createSanitizerCtorAndInitFunctions(
            M, kBsanModuleCtorName, kBsanFuncInitName, /*InitArgTypes=*/{},
            /*InitArgs=*/{}, "");

    bool CtorComdat = true;

    IRBuilder<> IRB(BsanCtorFunction->getEntryBlock().getTerminator());
    instrumentGlobals(IRB, M, &CtorComdat);

    assert(BsanCtorFunction && BsanDtorFunction);
    uint64_t Priority = 1;

    // Put the constructor and destructor in comdat if both
    // (1) global instrumentation is not TU-specific
    // (2) target is ELF.
    if (UseCtorComdat && TargetTriple.isOSBinFormatELF() && CtorComdat) {
        BsanCtorFunction->setComdat(M.getOrInsertComdat(kBsanModuleCtorName));
        appendToGlobalCtors(M, BsanCtorFunction, Priority, BsanCtorFunction);

        BsanDtorFunction->setComdat(M.getOrInsertComdat(kBsanModuleDtorName));
        appendToGlobalDtors(M, BsanDtorFunction, Priority, BsanDtorFunction);
    } else {
        appendToGlobalCtors(M, BsanCtorFunction, Priority);
        appendToGlobalDtors(M, BsanDtorFunction, Priority);
    }
    return true;
}

static Constant *getOrInsertGlobal(Module &M, StringRef Name, Type *Ty) {
  return M.getOrInsertGlobal(Name, Ty, [&] {
    return new GlobalVariable(M, Ty, false, GlobalVariable::ExternalLinkage,
                              nullptr, Name, nullptr,
                              GlobalVariable::InitialExecTLSModel);
  });
}



void BorrowSanitizer::instrumentGlobals(IRBuilder<> &IRB, Module &M, bool *CtorComdat) {
    CreateBsanModuleDtor(M);
}

void BorrowSanitizer::initializeCallbacks(Module &M, const TargetLibraryInfo &TLI) {
    if (CallbacksInitialized)
        return;

    IRBuilder<> IRB(*C);

    AttributeList AL;
    AL = AL.addFnAttribute(*C, Attribute::NoUnwind);

    BsanFuncRetag = M.getOrInsertFunction(
        kBsanFuncRetagName, AL,
        IntptrTy,
        IntptrTy, IntptrTy, PtrTy, PtrTy, IntptrTy, Int8Ty, Int8Ty
    );

    BsanFuncPushFrame = M.getOrInsertFunction(
        kBsanFuncPushFrameName,
        FunctionType::get(IRB.getVoidTy(), /*isVarArg=*/false),
        AL
    );

    BsanFuncPopFrame = M.getOrInsertFunction(
        kBsanFuncPopFrameName,
        FunctionType::get(IRB.getVoidTy(), /*isVarArg=*/false),
        AL
    );

    BsanFuncShadowCopy = M.getOrInsertFunction(
        kBsanFuncShadowCopyName, AL,
        IRB.getVoidTy(), 
        PtrTy, PtrTy, IntptrTy
    );

    BsanFuncShadowClear = M.getOrInsertFunction(
        kBsanFuncShadowClearName, AL,
        IRB.getVoidTy(), 
        PtrTy, IntptrTy
    );

    BsanFuncJoinProv =  M.getOrInsertFunction(
        kBsanFuncJoinProvName, AL,
        IRB.getVoidTy(), 
        PtrTy, IntptrTy, PtrTy, PtrTy, PtrTy
    );

    BsanFuncSplitProv =  M.getOrInsertFunction(
        kBsanFuncSplitProvName, AL,
        IRB.getVoidTy(), 
        PtrTy, IntptrTy, PtrTy, PtrTy, PtrTy
    );

    BsanFuncGetShadowDest = M.getOrInsertFunction(
        kBsanFuncGetShadowDestName, AL,
        PtrTy, 
        PtrTy
    );

    BsanFuncGetShadowSrc = M.getOrInsertFunction(
        kBsanFuncGetShadowSrcName, AL,
        PtrTy, 
        PtrTy
    );

    BsanFuncNewAllocID = M.getOrInsertFunction(
        kBsanFuncNewAllocIDName,
        FunctionType::get(IntptrTy, /*isVarArg=*/false),
        AL
    );

    BsanFuncNewBorrowTag = M.getOrInsertFunction(
        kBsanFuncNewBorrowTagName,
        FunctionType::get(IntptrTy, /*isVarArg=*/false),
        AL
    );

    BsanFuncAlloc = M.getOrInsertFunction(
        kBsanFuncAllocName, AL,
        PtrTy,
        IntptrTy, IntptrTy, PtrTy, IntptrTy  
    );

    BsanFuncDealloc = M.getOrInsertFunction(
        kBsanFuncDeallocName, AL,
        IRB.getVoidTy(), 
        PtrTy, IntptrTy, IntptrTy, PtrTy
    );

    BsanFuncExposeTag = M.getOrInsertFunction(
        kBsanFuncExposeTagName, AL,
        IRB.getVoidTy(), 
        IntptrTy, IntptrTy, PtrTy);

    BsanFuncRead = M.getOrInsertFunction(
        kBsanFuncReadName, AL,
        IRB.getVoidTy(), 
        IntptrTy, IntptrTy, PtrTy, PtrTy, IntptrTy
    );

    BsanFuncWrite = M.getOrInsertFunction(
        kBsanFuncWriteName, AL,
        IRB.getVoidTy(), 
        IntptrTy, IntptrTy, PtrTy, PtrTy, IntptrTy
    );

    BsanFuncShadowLoadArray = M.getOrInsertFunction(
        kBsanFuncShadowLoadArrayName, AL,
        IRB.getVoidTy(), 
        PtrTy, PtrTy, IntptrTy
    );

    BsanFuncShadowLoadVector = M.getOrInsertFunction(
        kBsanFuncShadowLoadVectorName, AL,
        IRB.getVoidTy(),
        PtrTy, IntptrTy, PtrTy, PtrTy, PtrTy
    );

    BsanFuncShadowStoreArray = M.getOrInsertFunction(
        kBsanFuncShadowStoreArrayName, AL,
        IRB.getVoidTy(), 
        PtrTy, PtrTy, IntptrTy
    );

    BsanFuncShadowStoreVector = M.getOrInsertFunction(
        kBsanFuncShadowStoreVectorName, AL,
        IRB.getVoidTy(),
        PtrTy, IntptrTy, PtrTy, PtrTy, PtrTy
    );

    createUserspaceApi(M, TLI);

    CallbacksInitialized = true;
}

void BorrowSanitizer::createUserspaceApi(Module &M, const TargetLibraryInfo &TLI) {
    IRBuilder<> IRB(*C);

    RetvalTLS =
        getOrInsertGlobal(M, kBsanRetvalTLSName,
                            ArrayType::get(ProvenanceTy, kTLSSize));
    ParamTLS =
        getOrInsertGlobal(M, kBsanParamTLSName,
                            ArrayType::get(ProvenanceTy, kTLSSize));
}

bool BorrowSanitizer::instrumentFunction(Function &F, FunctionAnalysisManager &FAM, const StackSafetyGlobalInfo *const SSGI) {
    if (F.empty())
        return false;
    if (F.getLinkage() == GlobalValue::AvailableExternallyLinkage)
        return false;
    if (F.getName().starts_with(kBsanPrefix))
        return false;
    if (F.isPresplitCoroutine())
        return false;
    if (F.hasFnAttribute(Attribute::DisableSanitizerInstrumentation))
        return false;

    AliasAnalysis &AA = FAM.getResult<AAManager>(F);
    MemorySSA &MSSA = FAM.getResult<MemorySSAAnalysis>(F).getMSSA();
    const TargetLibraryInfo &TLI = FAM.getResult<TargetLibraryAnalysis>(F);

    initializeCallbacks(*F.getParent(), TLI);

    BorrowSanitizerVisitor Visitor(F, *this, SSGI, AA, MSSA, TLI);
    return Visitor.runOnFunction();
}

llvm::PassPluginLibraryInfo getBorrowSanitizerPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "BorrowSanitizer", LLVM_VERSION_STRING,
            [](PassBuilder &PB)
            {
                PB.registerPipelineParsingCallback(
                    [](StringRef Name, ModulePassManager &MPM,
                       ArrayRef<PassBuilder::PipelineElement>)
                    {
                        if (Name == "bsan")
                        {
                            MPM.addPass(BorrowSanitizerPass(BorrowSanitizerOptions()));
                            return true;
                        }
                        return false;
                    });
            }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return getBorrowSanitizerPluginInfo();
}