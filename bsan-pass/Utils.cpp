    void resolveAllocationInfo(CallBase *CB) {
        LibFunc TLIFn;
        if(Callee) {
            AllocFnKind Kind = getAllocFnKind(CB)
            if(TLI->getLibFunc(*Callee, TLIFn) && TLI->has(TLIFn)) {
                std::optional<APInt> AllocSize = getAllocSize(&CB, TLI);
                if (isAllocLikeFn(&CB, TLI)) {
                    
                } else if (isReallocLikeFn(Callee)) {
                    
                } else if (isLibFreeFunction(Callee, TLIFn)) {

                }
            // Rust's allocation functions are not considered "library functions",
            // but they have an `AllocKind` attribute. 
            } else if (Callee->hasFnAttribute(Attribute::AllocKind)) {  
                
            }   
        }
        return std::nullopt;
    }