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

using namespace llvm;

#define DEBUG_TYPE "bsan"

// Constants:
const char kBsanPrefix[] = "__bsan_";
const char kBsanModuleCtorName[] = "bsan.module_ctor";
const char kBsanModuleDtorName[] = "bsan.module_dtor";
const char kBsanFuncInitName[] = "__bsan_init";
const char kBsanFuncDeinitName[] = "__bsan_deinit";

const char kBsanFuncPushFrameName[] = "__bsan_push_frame";
const char kBsanFuncPopFrameName[] = "__bsan_pop_frame";
const char kBsanFuncCopyShadowName[] = "__bsan_copy_shadow";
const char kBsanFuncClearShadowName[] = "__bsan_clear_shadow";
const char kBsanFuncRetagName[] = "__bsan_retag";
const char kBsanFuncStoreProvName[] = "__bsan_store_prov";
const char kBsanFuncLoadProvName[] = "__bsan_load_prov";
const char kBsanFuncAllocName[] = "__bsan_alloc";
const char kBsanFuncAllocStackName[] = "__bsan_alloc_stack";
const char kBsanFuncDeallocName[] = "__bsan_dealloc";
const char kBsanFuncExposeTagName[] = "__bsan_expose_tag";
const char kBsanFuncReadName[] = "__bsan_read";
const char kBsanFuncWriteName[] = "__bsan_write";

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
        FunctionCallee BsanFuncAllocStack;
        FunctionCallee BsanFuncDealloc;
        FunctionCallee BsanFuncExposeTag;
        FunctionCallee BsanFuncRead;
        FunctionCallee BsanFuncWrite;
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

        ValueMap<Value *, Value *> ProvenanceMap;
        ValueMap<Value *, ArrayRef<Value *>> AggregateProvenanceMap;
        Value *CurrentShadowStackPointer;

        BorrowSanitizerVisitor(Function &F, BorrowSanitizer &BS,
                               const TargetLibraryInfo &TLI)
            : F(F), BS(BS), DIB(*F.getParent(), /*AllowUnresolved*/ false), C(BS.C),
              TLI(&TLI)
        {
            removeUnreachableBlocks(F);
        }

        /// Set Provenance to be the provenance value for V.
        void setProvenance(Value *V, Value *Provenance)
        {
            assert(!ProvenanceMap.count(V) &&
                   "Values may only have one provenance value");
            ProvenanceMap[V] = Provenance;
        }

        /// Gets the Provenance value for V
        Value *getProvenance(Value *V)
        {
            Value *Provenance = ProvenanceMap[V];
            assert(Provenance && "Missing provenance");
            return Provenance;
        }

        /// Get the Provenance for i-th argument of the instruction I.
        Value *getProvenance(Instruction *I, int i)
        {
            return getProvenance(I->getOperand(i));
        }

        CallInst *createAllocationMetadata(Value *AllocAddr, APInt &AllocSize)
        {
            /* Value *AllocSizeValue =
                ConstantInt::get(BS.IntptrTy, AllocSize.getZExtValue());
            return CallInst::Create(BS.BsanFuncAlloc, {AllocAddr, AllocSizeValue}); */
        }

        void instrumentLoad(LoadInst &I) {}

        void instrumentVectorLoad(LoadInst &I) {}

        void instrumentAggregateLoad(LoadInst &I) {}

        void instrumentStore(StoreInst &I) {}

        void instrumentVectorStore(StoreInst &I) {}

        void instrumentAggregateStore(StoreInst &I) {}

        bool runOnFunction()
        {
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

            deinitStack();

            return true;
        }

        void initStack()
        {
            BasicBlock *EntryBlock = &F.getEntryBlock();
            InstrumentationIRBuilder IRB(EntryBlock, EntryBlock->getFirstNonPHIIt());
            CurrentShadowStackPointer = IRB.CreateCall(BS.BsanFuncPushFrame);
        }

        void deinitStack()
        {
            EscapeEnumerator EE(F, "bsan_cleanup", ClHandleCxxExceptions);
            while (IRBuilder<> *AtExit = EE.Next())
            {
                InstrumentationIRBuilder::ensureDebugInfo(*AtExit, F);
                AtExit->CreateCall(BS.BsanFuncPopFrame);
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
            if (I.getOpcode() == Instruction::Alloca)
            {
                AllocaInst &AI = static_cast<AllocaInst &>(I);
                if (shouldInstrumentAlloca(AI))
                {
                    if (AI.isStaticAlloca())
                        StaticAllocaVec.push_back(&AI);
                    else
                        DynamicAllocaVec.push_back(&AI);
                }
            }
            else
            {
                Instructions.push_back(&I);
            }
        }

        void visitCallInst(CallInst &I)
        {
            LibFunc TLIFn;
            Function *Callee = I.getCalledFunction();
            // TODO: Handle CallBr and Invoke
            if (isAllocLikeFn(&I, TLI))
            {
                /*
                APInt AllocSize = getAllocSize(&I, TLI).value_or(
                    APInt::getZero(BS.IntptrTy->getIntegerBitWidth()));
                CallInst *AllocCall = createAllocationMetadata(&I, AllocSize);
                setProvenance(&I, AllocCall);
                AllocCall->insertAfter(&I); */
            }
            else if (Callee && TLI->getLibFunc(*Callee, TLIFn) && TLI->has(TLIFn) &&
                     isLibFreeFunction(Callee, TLIFn))
            {
            }
            else
            {
                // TODO: handle passing provenance through the shadow stack or TLS.
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
}

void BorrowSanitizer::initializeCallbacks(Module &M,
                                          const TargetLibraryInfo &TLI)
{
    // Only do this once.
    if (CallbacksInitialized)
        return;

    IRBuilder<> IRB(*C);

    BsanFuncRetag = M.getOrInsertFunction(kBsanFuncRetagName, IRB.getVoidTy(),
                                          PtrTy, Int8Ty, Int8Ty);

    BsanFuncPushFrame = M.getOrInsertFunction(
        kBsanFuncPushFrameName, FunctionType::get(PtrTy, /*isVarArg=*/false));

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
                                          PtrTy, IntptrTy);

    BsanFuncAllocStack = M.getOrInsertFunction(kBsanFuncAllocStackName,
                                               IRB.getVoidTy(), PtrTy, IntptrTy);

    BsanFuncDealloc =
        M.getOrInsertFunction(kBsanFuncDeallocName, IRB.getVoidTy(), PtrTy);

    BsanFuncExposeTag =
        M.getOrInsertFunction(kBsanFuncExposeTagName, IRB.getVoidTy(), PtrTy);

    BsanFuncRead = M.getOrInsertFunction(kBsanFuncReadName, IRB.getVoidTy(),
                                         PtrTy, IntptrTy, IntptrTy);

    BsanFuncWrite = M.getOrInsertFunction(kBsanFuncWriteName, IRB.getVoidTy(),
                                          PtrTy, IntptrTy, IntptrTy);

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