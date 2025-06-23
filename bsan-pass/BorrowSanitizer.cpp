//===- BorrowSanitizer.cpp - Instrumentation for BorrowSanitizer
//------------===//
#include "BorrowSanitizer.h"

#include "llvm/Transforms/Utils/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/EscapeEnumerator.h"

#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/TargetLibraryInfo.h"

#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/Module.h"

#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/PostOrderIterator.h"

#include "llvm/Analysis/MemoryBuiltins.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/DebugCounter.h"

#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

#include <optional>

using namespace llvm;

#define DEBUG_TYPE "bsan"

// Constants:
const char kBsanPrefix[] = "__bsan_";
const char kBsanModuleCtorName[] = "bsan.module_ctor";
const char kBsanModuleDtorName[] = "bsan.module_dtor";
const char kBsanFuncInitName[] = "__bsan_init";
const char kBsanFuncDeinitName[] = "__bsan_deinit";

const char kBsanFuncStackTopName[] = "__bsan_stack_top";
const char kBsanFuncExtendFrameName[] = "__bsan_extend_frame";
const char kBsanFuncContractFrameName[] = "__bsan_contract_frame";

const char kBsanFuncPushFrameName[] = "__bsan_push_frame";
const char kBsanFuncPopFrameName[] = "__bsan_pop_frame";
const char kBsanFuncCopyShadowName[] = "__bsan_copy_shadow";
const char kBsanFuncClearShadowName[] = "__bsan_clear_shadow";
const char kBsanFuncRetagName[] = "__bsan_retag";
const char kBsanFuncStoreProvName[] = "__bsan_store_prov";
const char kBsanFuncLoadProvName[] = "__bsan_load_prov";
const char kBsanFuncAllocName[] = "__bsan_alloc";
const char kBsanFuncDeallocName[] = "__bsan_dealloc";
const char kBsanFuncExposeTagName[] = "__bsan_expose_tag";
const char kBsanFuncReadName[] = "__bsan_read";
const char kBsanFuncWriteName[] = "__bsan_write";

const char kBsanWildcardProvenance[] = "__WILDCARD_PROVENANCE";
const char kBsanNullProvenance[] = "__NULL_PROVENANCE";
const char kVScale[] = "__VSCALE";

// Provenance is three words
static const unsigned kProvenanceSize = 24;

// Command-line flags:
static cl::opt<bool>
    ClEnableKbsan("bsan-kernel",
                  cl::desc("Enable KernelBorrowSanitizer instrumentation"),
                  cl::Hidden, cl::init(false));

static cl::opt<bool>
    ClWithComdat("bsan-with-comdat",
                 cl::desc("Place BSan constructors in comdat sections"),
                 cl::Hidden, cl::init(true));

static cl::opt<bool> ClSingleStack(
    "bsan-single-stack-alloc",
    cl::desc("Treat all static stack allocations as a single allocation."),
    cl::Hidden, cl::init(false));

static cl::opt<bool> ClHandleCxxExceptions(
    "bsan-handle-cxx-exceptions", cl::init(true),
    cl::desc("Handle C++ exceptions (insert cleanup blocks for unwinding)"),
    cl::Hidden);

namespace
{

    struct BorrowSanitizer
    {
        BorrowSanitizer(Module &M)
            : CompileKernel(ClEnableKbsan.getNumOccurrences() > 0 ? ClEnableKbsan
                                                                  : false),
              UseCtorComdat(ClWithComdat && !this->CompileKernel),
              SingleStack(ClSingleStack)
        {
            C = &(M.getContext());
            DL = &M.getDataLayout();
            LongSize = M.getDataLayout().getPointerSizeInBits();
            TargetTriple = Triple(M.getTargetTriple());
            Int8Ty = Type::getInt8Ty(*C);
            Int64Ty = Type::getInt64Ty(*C);
            PtrTy = PointerType::getUnqual(*C);
            IntptrTy = Type::getIntNTy(*C, LongSize);
            ProvenanceTy = StructType::get(IntptrTy, IntptrTy, PtrTy);
        }
        bool instrumentModule(Module &);
        bool instrumentFunction(Function &F, const TargetLibraryInfo &TLI);
        void createUserspaceApi(Module &M, const TargetLibraryInfo &TLI);
        void createKernelApi(Module &M, const TargetLibraryInfo &TLI);

        TypeSize getAllocaSizeInBytes(const AllocaInst &AI) const
        {
            return *AI.getAllocationSize(AI.getDataLayout());
        }

    private:
        friend struct BorrowSanitizerVisitor;

        void initializeCallbacks(Module &M, const TargetLibraryInfo &TLI);
        void instrumentGlobals(IRBuilder<> &IRB, Module &M, bool *CtorComdat);
        Instruction *CreateBsanModuleDtor(Module &M);

        bool CompileKernel;
        bool UseCtorComdat;
        bool SingleStack;
        LLVMContext *C;
        const DataLayout *DL;
        int LongSize;
        Triple TargetTriple;
        Type *Int8Ty;
        Type *Int64Ty;
        PointerType *PtrTy;
        Type *IntptrTy;
        StructType *ProvenanceTy;
        bool CallbacksInitialized = false;

        Function *BsanCtorFunction = nullptr;
        Function *BsanDtorFunction = nullptr;
        FunctionCallee BsanFuncRetag;
        FunctionCallee BsanFuncPushFrame;
        FunctionCallee BsanFuncPopFrame;
        FunctionCallee BsanFuncCopyShadow;
        FunctionCallee BsanFuncClearShadow;
        FunctionCallee BsanFuncStoreProv;
        FunctionCallee BsanFuncLoadProv;
        FunctionCallee BsanFuncAlloc;
        FunctionCallee BsanFuncDealloc;
        FunctionCallee BsanFuncExposeTag;
        FunctionCallee BsanFuncRead;
        FunctionCallee BsanFuncWrite;
        FunctionCallee BsanFuncContractFrame;
        FunctionCallee BsanFuncExtendFrame;
        FunctionCallee BsanFuncStackTop;

        Value *WildcardProvenance;
        Value *NullProvenance;
        Value *VScale;
    };

    struct BorrowSanitizerVisitor : public InstVisitor<BorrowSanitizerVisitor>
    {
        Function &F;
        BorrowSanitizer &BS;
        DIBuilder DIB;
        LLVMContext *C;
        const TargetLibraryInfo *TLI;

        uint64_t StackOffset = 0;

        SmallVector<Instruction *, 16> Instructions;
        SmallVector<AllocaInst *, 16> StaticAllocaVec;
        SmallVector<AllocaInst *, 1> DynamicAllocaVec;

        SmallVector<StoreInst *, 16> StoreVec;
        SmallVector<LoadInst *, 16> LoadVec;


        SmallVector<std::tuple<Value*, Instruction *>, 16> FreeVec;
        SmallVector<PHINode *, 16> ShadowPHINodes;



        Value *PrevShadowFrameTop = nullptr;
        Value *ShadowStackBase = nullptr;
        ValueMap<Value *, SmallVector<Value *>> ProvenanceMap;

        BorrowSanitizerVisitor(Function &F, BorrowSanitizer &BS,
                               const TargetLibraryInfo &TLI)
            : F(F), BS(BS), DIB(*F.getParent(), /*AllowUnresolved*/ false), C(BS.C),
              TLI(&TLI)
        {
            removeUnreachableBlocks(F);
        }

        /// Set Provenance to be the provenance value for V.
        void appendProvenance(Value *Key, Value *Val)
        {
            ProvenanceMap[Key].push_back(Val);
        }

        /// Gets the Provenance value for V
        Value *getProvenance(Value *V)
        {
            return getProvenanceAtIndex(V, 0);
        }

        Value *getProvenanceAtIndex(Value *V, int i) {
            SmallVector<Value*> ProvenanceValues = ProvenanceMap[V];
            if(ProvenanceMap.count(V)) {
                assert(ProvenanceValues.size() > i);
                return ProvenanceValues[i];
            }else {
                return BS.WildcardProvenance;
            }
        }

        /// Get the Provenance for i-th argument of the instruction I.
        Value *getProvenance(Instruction *I, int i)
        {
            return getProvenance(I->getOperand(i));
        }

        void instrumentLoad(LoadInst &I) {}

        void instrumentVectorLoad(LoadInst &I) {}

        void instrumentAggregateLoad(LoadInst &I) {}

        void instrumentStore(StoreInst &I) {}

        void instrumentVectorStore(StoreInst &I) {}

        void instrumentAggregateStore(StoreInst &I) {}

        void instrumentRetag(IntrinsicInst &I) {
            CallInst *CIRetag = CallInst::Create(
                BS.BsanFuncRetag, {I.getOperand(0), I.getOperand(1), I.getOperand(2), I.getOperand(3)});
            ReplaceInstWithInst(&I, CIRetag);
        }

        bool runOnFunction() {
            for (BasicBlock *BB :
                 ReversePostOrderTraversal<BasicBlock *>(&F.getEntryBlock()))
            {
                visit(*BB);
            }

            if (Instructions.empty())
                return false;

            initStack();

            for (Instruction *I : Instructions)
            {
                InstVisitor<BorrowSanitizerVisitor>::visit(*I);
            }

            // Finalize PHI nodes.
            for (PHINode *PN : ShadowPHINodes) {
                size_t NumValues = PN->getNumIncomingValues();
                size_t NumPointersInType = numPointersInType(PN->getType());
                for(unsigned ProvIdx = 0; ProvIdx < NumPointersInType; ProvIdx++){
                    PHINode *ShadowPN = cast<PHINode>(getProvenanceAtIndex(PN, ProvIdx));
                    for(unsigned ValIdx = 0; ValIdx < NumValues; ++ValIdx) {
                        Value *IncomingValue = PN->getIncomingValue(ValIdx);
                        Value *IncomingProvenance = getProvenanceAtIndex(IncomingValue, ProvIdx);
                        ShadowPN->addIncoming(IncomingProvenance, PN->getIncomingBlock(ValIdx));
                    }
                }
            }
            handleStores();
            insertDereferenceChecks();
            deinitStack();
            return true;
        }

        void handleStores() {

        }

        void insertDereferenceChecks() {

        }

        void initStack() {
            processArguments();
            processStaticAllocas();
            processDynamicAllocas();
        }

        void processArguments() {
            InstrumentationIRBuilder IRB(&F.getEntryBlock(),
                F.getEntryBlock().getFirstNonPHIIt());
            uint64_t Offset = 1;
            
            for (auto &FArg : F.args()) {
                uint64_t NumPointersInType = numPointersInType(FArg.getType());
                if(NumPointersInType > 0) {
                    for(unsigned i = 0; i < NumPointersInType; ++i) {
                        Offset += i;
                        
                        if(PrevShadowFrameTop == nullptr) {
                            PrevShadowFrameTop = IRB.CreateCall(BS.BsanFuncStackTop, {});
                        }

                        Value *Base = IRB.CreatePointerCast(PrevShadowFrameTop, BS.IntptrTy);
                        int64_t OffsetNegative = -((int64_t) Offset * kProvenanceSize);
                        Value *Offset = ConstantInt::get(BS.IntptrTy, OffsetNegative);
                        Value *Provenance = IRB.CreateIntToPtr(IRB.CreateAdd(Base, Offset), BS.PtrTy);
                        appendProvenance(&FArg, Provenance);
                    }
                }   
            }   
        }

        void processStaticAllocas() {
            Instruction* Position;
            if(PrevShadowFrameTop == nullptr) {
                Position = &*F.getEntryBlock().getFirstNonPHIIt();
            }else{
                Position = ((CallInst *)PrevShadowFrameTop)->getNextNode();
            }

            InstrumentationIRBuilder IRB(Position);

            // Create separate provenance slots for each stack variable.
            ShadowStackBase = IRB.CreateCall(BS.BsanFuncPushFrame, {
                ConstantInt::get(BS.IntptrTy, StaticAllocaVec.size())
            });
            initStackWithSeparateAllocs();
        }
        
        void initStackWithSeparateAllocs() {
            InstrumentationIRBuilder IRB(&F.getEntryBlock(),
                                        F.getEntryBlock().getFirstNonPHIIt());
            // Create separate provenance slots for each stack variable.
            size_t NumStackAllocations = StaticAllocaVec.size() + DynamicAllocaVec.size();
            ShadowStackBase = IRB.CreateCall(BS.BsanFuncPushFrame, {
                ConstantInt::get(BS.IntptrTy, NumStackAllocations)
            });
    
            // After each alloca, insert a call to __bsan_alloc, which will
            // initialize the provenance for the corresponding slot. 
            for (AllocaInst *AI : StaticAllocaVec) {
                InstrumentationIRBuilder IRB(AI->getNextNode());
                
                Value *Base = IRB.CreatePointerCast(ShadowStackBase, BS.IntptrTy);
                Value *Offset = ConstantInt::get(BS.IntptrTy, StackOffset * kProvenanceSize);
                Value *Provenance = IRB.CreateIntToPtr(IRB.CreateAdd(Base, Offset), BS.PtrTy);
                initializeProvenanceForAlloca(IRB, AI, Provenance);
                StackOffset += 1;
            }
        }

        void processDynamicAllocas() {
            for (AllocaInst *AI : DynamicAllocaVec) {
                InstrumentationIRBuilder IRB(AI->getNextNode());
                CallInst* Provenance = IRB.CreateCall(BS.BsanFuncExtendFrame, {
                    ConstantInt::get(BS.IntptrTy, 1)
                });
                initializeProvenanceForAlloca(IRB, AI, Provenance);
            }
        }

        void initializeProvenanceForAlloca(IRBuilder<> &IRB, AllocaInst *AI, Value *Provenance) {
            TypeSize TS = BS.getAllocaSizeInBytes(*AI);
            Value *Size = IRB.CreateTypeSize(BS.IntptrTy, TS);
            Value *ObjectAddress = AI;
            IRB.CreateCall(BS.BsanFuncAlloc, {
                Provenance, ObjectAddress, Size
            });
            appendProvenance(ObjectAddress, Provenance);
        }

        void deinitStack() {
            // We only need to pop a stack frame if one has already been pushed.
            if(ShadowStackBase != nullptr) {
                EscapeEnumerator EE(F, "bsan_cleanup", ClHandleCxxExceptions);
                while (IRBuilder<> *AtExit = EE.Next())
                {
                    InstrumentationIRBuilder::ensureDebugInfo(*AtExit, F);
                    AtExit->CreateCall(BS.BsanFuncPopFrame);
                }
            }
        }

        bool shouldInstrumentAlloca(AllocaInst &AI)
        {
            bool ShouldInstrument =
                // alloca() may be called with 0 size, ignore it.
                (AI.getAllocatedType()->isSized() &&
                 !BS.getAllocaSizeInBytes(AI).isZero());
            return ShouldInstrument;
        }

        using InstVisitor<BorrowSanitizerVisitor>::visit;

        // We use this function to visit all instructions in depth-first order.
        void visit(Instruction &I)
        {
            if (I.getMetadata(LLVMContext::MD_nosanitize))
                return;
            if (I.getOpcode() == Instruction::Alloca) {
                AllocaInst &AI = static_cast<AllocaInst &>(I);
                if (shouldInstrumentAlloca(AI)) {
                    if (AI.isStaticAlloca())
                        StaticAllocaVec.push_back(&AI);
                    else
                        DynamicAllocaVec.push_back(&AI);
                }
            } else {
                Instructions.push_back(&I);
            }
        }

        void processDynamicAllocation(CallBase *CB, std::optional<APInt> &AllocSize) {
            if(AllocSize.has_value()) {
                InstrumentationIRBuilder IRBAfter = getInsertionPointAfterCall(CB);
                Value *Size = ConstantInt::get(BS.IntptrTy, AllocSize->getZExtValue());

                CallInst* Provenance = IRBAfter.CreateCall(BS.BsanFuncExtendFrame, {
                    ConstantInt::get(BS.IntptrTy, 1)
                });
                CallInst *Call = IRBAfter.CreateCall(BS.BsanFuncAlloc, {Provenance, CB, Size});
                appendProvenance(CB, Provenance);
            }
        }

        void visitCallBase(CallBase &I) {
            LibFunc TLIFn;
            Function *Callee = I.getCalledFunction();
            std::optional<APInt> AllocSize = getAllocSize(&I, TLI);
            if (isAllocLikeFn(&I, TLI)){
                processDynamicAllocation(&I, AllocSize);
            }else if(Callee && isReallocLikeFn(Callee)) {
                processDynamicAllocation(&I, AllocSize);
                Value *Operand = getReallocatedOperand(&I);
                FreeVec.push_back(std::make_tuple(Operand, &I));
            }else if(Callee && TLI->getLibFunc(*Callee, TLIFn) && TLI->has(TLIFn) &&
                isLibFreeFunction(Callee, TLIFn)) {
                Value* Operand = getFreedOperand(&I, TLI);
                FreeVec.push_back(std::make_tuple(Operand, &I));
            }else{
                
            }
        }

        void visitIntrinsicInst(IntrinsicInst &I) {
            switch (I.getIntrinsicID()) {
                case Intrinsic::retag: {
                    instrumentRetag(I);
                } break;
                default:
                    break;
            }
        }

        void visitLoadInst(LoadInst &I) {
            LoadVec.push_back(&I);
            InstrumentationIRBuilder IRB(I.getNextNode());
        }

        void visitStoreInst(StoreInst &I) {
            StoreVec.push_back(&I);
            InstrumentationIRBuilder IRB(I.getNextNode());
        }

        void visitPHINode(PHINode &I) {
            IRBuilder<> IRB(&I);
            uint64_t NumPointers = numPointersInType(I.getType());
            if(NumPointers > 0) {
                ShadowPHINodes.push_back(&I);
                for(unsigned i = 0; i < NumPointers; ++i) {
                    appendProvenance(&I, IRB.CreatePHI(BS.PtrTy, I.getNumIncomingValues(),
                            "_bsphi"));
                } 
            }
        }
    };
} // end anonymous namespace

PreservedAnalyses BorrowSanitizerPass::run(Module &M,
                                           ModuleAnalysisManager &MAM)
{
    BorrowSanitizer ModuleSanitizer(M);
    bool Modified = false;

    auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();

    for (Function &F : M)
    {
        const TargetLibraryInfo &TLI = FAM.getResult<TargetLibraryAnalysis>(F);
        Modified |= ModuleSanitizer.instrumentFunction(F, TLI);
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

Instruction *BorrowSanitizer::CreateBsanModuleDtor(Module &M)
{
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

bool BorrowSanitizer::instrumentModule(Module &M)
{
    if (CompileKernel)
    {
        // The kernel always builds with its own runtime, and therefore does not
        // need the init and version check calls.
        BsanCtorFunction = createSanitizerCtor(M, kBsanModuleCtorName);
    }
    else
    {
        // TODO: add version check.
        std::tie(BsanCtorFunction, std::ignore) =
            createSanitizerCtorAndInitFunctions(
                M, kBsanModuleCtorName, kBsanFuncInitName, /*InitArgTypes=*/{},
                /*InitArgs=*/{}, "");
    }

    bool CtorComdat = true;

    IRBuilder<> IRB(BsanCtorFunction->getEntryBlock().getTerminator());
    instrumentGlobals(IRB, M, &CtorComdat);

    assert(BsanCtorFunction && BsanDtorFunction);
    uint64_t Priority = 1;

    // Put the constructor and destructor in comdat if both
    // (1) global instrumentation is not TU-specific
    // (2) target is ELF.
    if (UseCtorComdat && TargetTriple.isOSBinFormatELF() && CtorComdat)
    {
        BsanCtorFunction->setComdat(M.getOrInsertComdat(kBsanModuleCtorName));
        appendToGlobalCtors(M, BsanCtorFunction, Priority, BsanCtorFunction);

        BsanDtorFunction->setComdat(M.getOrInsertComdat(kBsanModuleDtorName));
        appendToGlobalDtors(M, BsanDtorFunction, Priority, BsanDtorFunction);
    }
    else
    {
        appendToGlobalCtors(M, BsanCtorFunction, Priority);
        appendToGlobalDtors(M, BsanDtorFunction, Priority);
    }
    return true;
}

static Constant *getOrInsertGlobal(Module &M, StringRef Name, Type *Ty)
{
    return M.getOrInsertGlobal(Name, Ty, [&]
                               { return new GlobalVariable(M, Ty, false, GlobalVariable::ExternalLinkage,
                                                           nullptr, Name, nullptr,
                                                           GlobalVariable::InitialExecTLSModel); });
}

void BorrowSanitizer::instrumentGlobals(IRBuilder<> &IRB, Module &M,
                                        bool *CtorComdat)
{
    CreateBsanModuleDtor(M);
    WildcardProvenance = getOrInsertGlobal(M, kBsanWildcardProvenance, ProvenanceTy);
    NullProvenance = getOrInsertGlobal(M, kBsanWildcardProvenance, ProvenanceTy);
}

void BorrowSanitizer::initializeCallbacks(Module &M,
                                          const TargetLibraryInfo &TLI)
{
    // Only do this once.
    if (CallbacksInitialized)
        return;

    IRBuilder<> IRB(*C);

    BsanFuncRetag = M.getOrInsertFunction(kBsanFuncRetagName, IRB.getVoidTy(),
                                          PtrTy, IntptrTy, Int8Ty, Int8Ty);

    BsanFuncPushFrame = M.getOrInsertFunction(
        kBsanFuncPushFrameName, PtrTy, IntptrTy);

    BsanFuncPopFrame = M.getOrInsertFunction(
        kBsanFuncPopFrameName,
        FunctionType::get(IRB.getVoidTy(), /*isVarArg=*/false));

    BsanFuncCopyShadow = M.getOrInsertFunction(
        kBsanFuncCopyShadowName, IRB.getVoidTy(), IntptrTy, IntptrTy, IntptrTy);

    BsanFuncClearShadow = M.getOrInsertFunction(
        kBsanFuncClearShadowName, IRB.getVoidTy(), IntptrTy, IntptrTy);

    BsanFuncStoreProv = M.getOrInsertFunction(kBsanFuncStoreProvName,
                                              IRB.getVoidTy(), PtrTy, IntptrTy);

    BsanFuncLoadProv = M.getOrInsertFunction(kBsanFuncLoadProvName,
                                             IRB.getVoidTy(), PtrTy, IntptrTy);

    BsanFuncAlloc = M.getOrInsertFunction(kBsanFuncAllocName, IRB.getVoidTy(),
                                          PtrTy, PtrTy, IntptrTy);

    BsanFuncDealloc =
        M.getOrInsertFunction(kBsanFuncDeallocName, IRB.getVoidTy(), PtrTy);

    BsanFuncExposeTag =
        M.getOrInsertFunction(kBsanFuncExposeTagName, IRB.getVoidTy(), PtrTy);

    BsanFuncRead = M.getOrInsertFunction(kBsanFuncReadName, IRB.getVoidTy(),
                                         PtrTy, IntptrTy, IntptrTy);

    BsanFuncWrite = M.getOrInsertFunction(kBsanFuncWriteName, IRB.getVoidTy(),
                                          PtrTy, IntptrTy, IntptrTy);

    BsanFuncContractFrame = M.getOrInsertFunction(kBsanFuncContractFrameName, IRB.getVoidTy(), IntptrTy);

    BsanFuncExtendFrame = M.getOrInsertFunction(kBsanFuncExtendFrameName, PtrTy, IntptrTy);

    BsanFuncStackTop = M.getOrInsertFunction(kBsanFuncStackTopName, FunctionType::get(PtrTy, /*isVarArg=*/false));
    
    if (CompileKernel)
    {
        createKernelApi(M, TLI);
    }
    else
    {
        createUserspaceApi(M, TLI);
    }

    CallbacksInitialized = true;
}

void BorrowSanitizer::createKernelApi(Module &M, const TargetLibraryInfo &TLI)
{
    IRBuilder<> IRB(*C);
}

void BorrowSanitizer::createUserspaceApi(Module &M,
                                         const TargetLibraryInfo &TLI)
{
    IRBuilder<> IRB(*C);
}

bool BorrowSanitizer::instrumentFunction(Function &F,
                                         const TargetLibraryInfo &TLI)
{
    if (F.empty())
        return false;
    if (F.getLinkage() == GlobalValue::AvailableExternallyLinkage)
        return false;
    if (F.getName().starts_with(kBsanPrefix))
        return false;
    if (F.isPresplitCoroutine())
        return false;

    initializeCallbacks(*F.getParent(), TLI);

    BorrowSanitizerVisitor Visitor(F, *this, TLI);
    return Visitor.runOnFunction();
}

llvm::PassPluginLibraryInfo getBorrowSanitizerPluginInfo()
{
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

// This is the core interface for pass plugins. It guarantees that 'opt' will
// be able to recognize BorrowSanitizer when added to the pass pipeline on the
// command line, i.e. via '-passes=bsan'
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo()
{
    return getBorrowSanitizerPluginInfo();
}