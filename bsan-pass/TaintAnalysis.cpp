// This file implements an interprocedural taint analysis to support
// soundly removing runtime checks from safe components.
//
// Our fork of rustc can be configured to emit function calls that mark when
// pointers have been exposed to unsafety. This happens when a reference is
// cast into a raw pointer, or vice versa, and when any kind of transmutation
// happens. If a pointer is tainted, we need to instrument it from the point it
// gained ownership to tthe end of the lifetime of its underlying object. If a
// place is tainted, then any pointers that are loaded from it become tainted.
// We use two forms of intrinsic functions (`__rust_taint_reg` and
// `__rust_taint_mem`) to distinguish between each case.
//
// Using this analysis, we can remove runtime checks for components that are
// exclusively accessed via safe or unsafe operations, respectively. Only
// components that cross the "safe/unsafe boundary" are capable of having
// aliasing-related undefined behavior.
//
// We need to pessimistically assume that any external inputs to the current
// module are tainted. This means that the "power" of the analysis to remove
// runtime checks will increase if LTO is enabled. However, we still expect to
// be able to eliminate a significant portion of runtime overhead in any case,
// even if we can only reason about components that are isolated within the
// current module.

#include "TaintAnalysis.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Value.h"

using namespace llvm;

#define DEBUG_TYPE "borsan-taint"

#define TAINT_FN(name) "__rust_taint_"

FunctionTaintAnalysis::FunctionTaintAnalysis(Function &F) : F(F) {}

void FunctionTaintAnalysis::run() {}