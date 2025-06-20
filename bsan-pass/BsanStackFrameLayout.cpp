#include "BsanStackFrameLayout.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/ScopedPrinter.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>

namespace llvm {

// We sort the stack variables by alignment (largest first) to minimize
// unnecessary large gaps due to alignment.
// It is tempting to also sort variables by size so that larger variables
// have larger redzones at both ends. But reordering will make report analysis
// harder, especially when temporary unnamed variables are present.
// So, until we can provide more information (type, line number, etc)
// for the stack variables we avoid reordering them too much.
static inline bool CompareVars(const BSanStackVariableDescription &a,
                               const BSanStackVariableDescription &b) {
  return a.Alignment > b.Alignment;
}

// We also force minimal alignment for all vars to kMinAlignment so that vars
// with e.g. alignment 1 and alignment 16 do not get reordered by CompareVars.
static const uint64_t kMinAlignment = 16;

BSanStackFrameLayout
ComputeBSanStackFrameLayout(SmallVectorImpl<BSanStackVariableDescription> &Vars) {
  const size_t NumVars = Vars.size();
  assert(NumVars > 0);

  for (size_t i = 0; i < NumVars; i++)
    Vars[i].Alignment = std::max(Vars[i].Alignment, kMinAlignment);

  llvm::stable_sort(Vars, CompareVars);

  BSanStackFrameLayout Layout;
  uint64_t Offset = Vars[0].Alignment;
  for (size_t i = 0; i < NumVars; i++) {

    uint64_t Alignment = Vars[i].Alignment;
    (void)Alignment;  // Used only in asserts.

    uint64_t Size = Vars[i].Size;

    assert((Alignment & (Alignment - 1)) == 0);
    assert((Offset % Alignment) == 0);
    assert(Size > 0);

    Size = alignTo(Size, Alignment);
    Offset += Size;
    Vars[i].Offset = Offset;
  }
  Layout.FrameSize = Offset;
  return Layout;
}

SmallString<64> ComputeBSanStackFrameDescription(
    const SmallVectorImpl<BSanStackVariableDescription> &Vars) {
  SmallString<2048> StackDescriptionStorage;
  raw_svector_ostream StackDescription(StackDescriptionStorage);
  StackDescription << Vars.size();

  for (const auto &Var : Vars) {
    std::string Name = Var.Name;
    if (Var.Line) {
      Name += ":";
      Name += to_string(Var.Line);
    }
    StackDescription << " " << Var.Offset << " " << Var.Size << " "
                     << Name.size() << " " << Name;
  }
  return StackDescription.str();
}

} // llvm namespace
