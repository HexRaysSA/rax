// Function pointers that LLVM holds as data pointers.
//
// A function's address is a pointer in the program address space, and the
// format gives it a code pointer type. Clang nevertheless keeps the entries
// of a C++ virtual table as pointers in the data address space: it stores
// `addrspacecast (ptr addrspace(1) @f to ptr)` in the table, loads a plain
// `ptr` from it and calls through that. A data pointer cannot designate a
// function in the format, so the values involved are found here and given
// the code pointer type instead.
#include "emitter.h"

namespace smir {

namespace {

bool isDataPointer(const Value *V) {
  return V->getType()->isPointerTy() && V->getType()->getPointerAddressSpace() == 0;
}

// A constant expression that converts a function's address to a data
// pointer; returns the function.
const Function *castFunction(const Value *V) {
  auto *Expression = dyn_cast<ConstantExpr>(V);
  if (!Expression || Expression->getOpcode() != Instruction::AddrSpaceCast)
    return nullptr;
  return dyn_cast<Function>(Expression->getOperand(0));
}

} // namespace

// Find the data-pointer values of F that hold function pointers: what a
// call goes through, what an address-space cast converts to or from a
// function pointer, and whatever flows into or out of those through phis,
// selects and freezes.
void Emitter::findCodeValues(const Function &F) {
  CodeValues.clear();
  SmallVector<const Value *, 16> Work;
  auto Mark = [&](const Value *V) {
    if (isDataPointer(V) && !isa<Constant>(V) && CodeValues.insert(V).second)
      Work.push_back(V);
  };
  for (const Instruction &I : instructions(F)) {
    if (auto *Call = dyn_cast<CallBase>(&I); Call && !Call->getCalledFunction() && !Call->isInlineAsm())
      Mark(Call->getCalledOperand());
    if (auto *Cast = dyn_cast<AddrSpaceCastInst>(&I)) {
      Mark(Cast);
      Mark(Cast->getOperand(0));
    }
  }
  auto Forwards = [](const Value *V) { return isa<PHINode>(V) || isa<SelectInst>(V) || isa<FreezeInst>(V); };
  while (!Work.empty()) {
    const Value *V = Work.pop_back_val();
    // What a forwarding instruction yields is what it was given.
    if (Forwards(V))
      for (const Use &Operand : cast<Instruction>(V)->operands())
        if (!isa<SelectInst>(V) || Operand.getOperandNo() != 0)
          Mark(Operand);
    for (const User *U : V->users())
      if (Forwards(U) && (!isa<SelectInst>(U) || cast<SelectInst>(U)->getCondition() != V))
        Mark(U);
  }
  // Every such value must come from, and go to, a place that can hold a
  // function pointer.
  for (const Value *V : CodeValues) {
    if (!isa<LoadInst>(V) && !Forwards(V) && !isa<AddrSpaceCastInst>(V))
      diagnose("E-UNSUPPORTED-INSTRUCTION", "function pointer from a data pointer that was not loaded");
    for (const Use &Use : V->uses()) {
      const User *U = Use.getUser();
      auto *Call = dyn_cast<CallBase>(U);
      auto *Store = dyn_cast<StoreInst>(U);
      auto *Compare = dyn_cast<ICmpInst>(U);
      bool Fits = (Call && Call->isCallee(&Use)) || (Store && Store->getValueOperand() == V) ||
                  (Compare && Compare->isEquality()) || Forwards(U) || isa<AddrSpaceCastInst>(U);
      if (!Fits)
        diagnose("E-UNSUPPORTED-INSTRUCTION", "function pointer used as a data pointer");
    }
  }
}

// The type a value has in the emitted code: a function pointer for the
// values found above, and its own type otherwise.
Type *Emitter::carriedType(const Value *V) {
  return CodeValues.count(V) ? PointerType::get(M.getContext(), 1) : V->getType();
}

// An operand where a function pointer is expected. A null data pointer is
// the null function pointer there, and a function's address converted to a
// data pointer is the function's address.
unsigned Emitter::codeOperand(const Value *V) {
  if (isa<ConstantPointerNull>(V))
    return constant(ConstantPointerNull::get(PointerType::get(M.getContext(), 1)));
  if (const Function *F = castFunction(V))
    return codeAddress(F);
  return operand(V);
}

// An operand of an instruction whose other operand, or whose result, is
// `Peer`: a function pointer if that is one.
unsigned Emitter::operandLike(const Value *V, const Value *Peer) {
  return CodeValues.count(Peer) ? codeOperand(V) : operand(V);
}

} // namespace smir
