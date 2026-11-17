// Lowering of atomic memory access: ordered loads and stores, read-modify-
// write, compare-and-exchange, and fences.
#include "emitter.h"

namespace smir {

namespace {

const char *orderName(AtomicOrdering Order) {
  switch (Order) {
  case AtomicOrdering::NotAtomic: return "none";
  case AtomicOrdering::Unordered: return "unordered";
  case AtomicOrdering::Monotonic: return "relaxed";
  case AtomicOrdering::Acquire: return "acquire";
  case AtomicOrdering::Release: return "release";
  case AtomicOrdering::AcquireRelease: return "acq_rel";
  case AtomicOrdering::SequentiallyConsistent: return "seq_cst";
  }
  return "none";
}

// The format's name for what a read-modify-write stores, or null for an
// action on floats or one the format does not have.
const char *actionName(AtomicRMWInst::BinOp Action) {
  switch (Action) {
  case AtomicRMWInst::Xchg: return "exchange";
  case AtomicRMWInst::Add: return "add";
  case AtomicRMWInst::Sub: return "sub";
  case AtomicRMWInst::And: return "and";
  case AtomicRMWInst::Nand: return "nand";
  case AtomicRMWInst::Or: return "or";
  case AtomicRMWInst::Xor: return "xor";
  case AtomicRMWInst::Min: return "min";
  case AtomicRMWInst::Max: return "max";
  case AtomicRMWInst::UMin: return "umin";
  case AtomicRMWInst::UMax: return "umax";
  default: return nullptr;
  }
}

} // namespace

// The mode fields of an ordered or volatile access; `access` has set the
// plain ones.
void Emitter::ordered(Object &Op, bool Volatile, AtomicOrdering Order, AtomicOrdering Failure) {
  Object &Mode = *Op["mode"].getAsObject();
  Mode["volatile"] = Volatile;
  Mode["order"] = orderName(Order);
  Mode["failure_order"] = orderName(Failure);
}

// Lower I if it is an atomic instruction; otherwise return false. An atomic
// load or store is lowered with the plain ones.
bool Emitter::lowerAtomic(const Instruction &I, Array &Ops) {
  if (auto *Fence = dyn_cast<FenceInst>(&I)) {
    Ops.push_back(Object{{"op", "fence"},
                         {"results", Array{}},
                         {"operands", Array{}},
                         {"order", orderName(Fence->getOrdering())},
                         {"scope", "process"}});
    return true;
  }
  if (auto *Update = dyn_cast<AtomicRMWInst>(&I)) {
    const char *Action = actionName(Update->getOperation());
    Type *Ty = Update->getValOperand()->getType();
    // Arithmetic is on integers; an exchange moves any scalar.
    if (!Action || (Update->getOperation() != AtomicRMWInst::Xchg && !Ty->isIntegerTy())) {
      diagnose("E-UNSUPPORTED-INSTRUCTION",
               "atomicrmw " + AtomicRMWInst::getOperationName(Update->getOperation()));
      return true;
    }
    Object Op = operation("atomic_rmw", Values.lookup(&I), Ty,
                          Array{operand(Update->getPointerOperand()), operand(Update->getValOperand())});
    access(Op, Ty, Update->getAlign());
    ordered(Op, Update->isVolatile(), Update->getOrdering(), AtomicOrdering::NotAtomic);
    Op["action"] = Action;
    Ops.push_back(std::move(Op));
    return true;
  }
  if (auto *Exchange = dyn_cast<AtomicCmpXchgInst>(&I)) {
    // The instruction's pair is its two results; see `Pairs`.
    auto [Old, Success] = Pairs.lookup(&I);
    Type *Ty = Exchange->getCompareOperand()->getType();
    Object Op{{"op", "cmpxchg"},
              {"results", Array{decl(Old, Ty), decl(Success, IntegerType::get(M.getContext(), 1))}},
              {"operands", Array{operand(Exchange->getPointerOperand()), operand(Exchange->getCompareOperand()),
                                 operand(Exchange->getNewValOperand())}}};
    access(Op, Ty, Exchange->getAlign());
    ordered(Op, Exchange->isVolatile(), Exchange->getSuccessOrdering(), Exchange->getFailureOrdering());
    Op["weak"] = Exchange->isWeak();
    Ops.push_back(std::move(Op));
    return true;
  }
  return false;
}

} // namespace smir
