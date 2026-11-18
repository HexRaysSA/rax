// Function pointers that LLVM holds as data pointers.
//
// A function's address is a pointer in the program address space, and the
// format gives it a code pointer type. Clang nevertheless keeps the entries
// of a C++ virtual table as pointers in the data address space: it stores
// `addrspacecast (ptr addrspace(1) @f to ptr)` in the table, loads a plain
// `ptr` from it and calls through that. A data pointer cannot designate a
// function in the format, so the values involved are found here and given
// the code pointer type instead.
//
// That works where the function pointer stays among loads, stores, calls
// and comparisons. A program may also convert a function pointer to
// `void *`, pass it on as that, and convert it back where it is called.
// Such a value stays a data pointer: the conversion to it goes through the
// function's address as an integer, which exposes the function, and the
// conversion back finds the function that integer names.
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

// Find the data-pointer values of F that are given the code pointer type:
// what a call goes through, what an address-space cast converts to or from
// a function pointer, and whatever flows into or out of those through phis,
// selects and freezes, provided that every one of the values so connected
// comes from, and goes to, a place that can hold a function pointer. The
// values of a group where one does not stay data pointers.
void Emitter::findCodeValues(const Function &F) {
  CodeValues.clear();
  SmallVector<const Value *, 16> Seeds;
  for (const Instruction &I : instructions(F)) {
    if (auto *Call = dyn_cast<CallBase>(&I); Call && !Call->getCalledFunction() && !Call->isInlineAsm())
      Seeds.push_back(Call->getCalledOperand());
    if (auto *Cast = dyn_cast<AddrSpaceCastInst>(&I)) {
      Seeds.push_back(Cast);
      Seeds.push_back(Cast->getOperand(0));
    }
  }
  auto Forwards = [](const Value *V) { return isa<PHINode>(V) || isa<SelectInst>(V) || isa<FreezeInst>(V); };
  // Whether every use of V can take a function pointer.
  auto Fits = [&](const Value *V) {
    if (!isa<LoadInst>(V) && !Forwards(V) && !isa<AddrSpaceCastInst>(V))
      return false;
    return all_of(V->uses(), [&](const Use &Use) {
      const User *U = Use.getUser();
      auto *Call = dyn_cast<CallBase>(U);
      auto *Store = dyn_cast<StoreInst>(U);
      auto *Compare = dyn_cast<ICmpInst>(U);
      return (Call && Call->isCallee(&Use)) || (Store && Store->getValueOperand() == V) ||
             (Compare && Compare->isEquality()) || Forwards(U) || isa<AddrSpaceCastInst>(U);
    });
  };
  DenseSet<const Value *> Visited;
  for (const Value *Seed : Seeds) {
    // One group: the seed and everything that forwards to or from it.
    SmallVector<const Value *, 16> Group, Work;
    auto Mark = [&](const Value *V) {
      if (isDataPointer(V) && !isa<Constant>(V) && Visited.insert(V).second) {
        Group.push_back(V);
        Work.push_back(V);
      }
    };
    Mark(Seed);
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
    if (all_of(Group, Fits))
      CodeValues.insert(Group.begin(), Group.end());
  }
}

// A function pointer as the data pointer that stands for it: the function's
// address, which this exposes, as a pointer to no object.
unsigned Emitter::dataFromCode(unsigned Code, Array &Ops) {
  unsigned Bits = fresh(), Data = fresh();
  Ops.push_back(operation("ptrtoint", Bits, IntegerType::get(M.getContext(), 64), Array{Code}));
  Ops.push_back(operation("inttoptr", Data, PointerType::get(M.getContext(), 0), Array{Bits}));
  return Data;
}

// The function pointer that a data pointer stands for: the function whose
// exposed address the pointer holds.
unsigned Emitter::codeFromData(unsigned Data, Array &Ops) {
  unsigned Bits = fresh(), Code = fresh();
  Ops.push_back(operation("ptrtoint", Bits, IntegerType::get(M.getContext(), 64), Array{Data}));
  Ops.push_back(operation("inttoptr", Code, PointerType::get(M.getContext(), 1), Array{Bits}));
  return Code;
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

// The function whose address, converted to a data pointer, the constant
// `C` is; null if it is not that.
const Function *Emitter::functionAsData(const Constant *C) { return castFunction(C); }

// An operand of an instruction whose other operand, or whose result, is
// `Peer`: a function pointer if that is one.
unsigned Emitter::operandLike(const Value *V, const Value *Peer) {
  return CodeValues.count(Peer) ? codeOperand(V) : operand(V);
}

} // namespace smir
