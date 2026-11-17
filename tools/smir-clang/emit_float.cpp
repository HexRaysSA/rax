// Lowering of floating point: binary32 and binary64 arithmetic, comparison
// and conversion, in the default environment.
//
// Fast-math flags have no SMIR field and are dropped. Those that make a
// result poison (nnan, ninf) are refined to the defined IEEE result; the
// others only permit transformations that the emitter does not make.
#include "emitter.h"

namespace smir {

// An operation in the default environment: round to nearest with ties to
// even, no observable exception.
Object Emitter::floatOperation(StringRef Name, unsigned Result, Type *Ty, Array Operands) {
  Object Op = operation(Name, Result, Ty, std::move(Operands));
  Op["mode"] = Object{{"environment", "default"}, {"rounding", "nearest_even"}, {"exceptions", "ignore"}};
  return Op;
}

// Lower I if it is a floating-point instruction; otherwise return false.
bool Emitter::lowerFloat(const Instruction &I, Array &Ops) {
  auto Emit = [&](StringRef Name, Array Operands) {
    Ops.push_back(floatOperation(Name, Values.lookup(&I), I.getType(), std::move(Operands)));
    return true;
  };
  auto Binary = [&](StringRef Name) { return Emit(Name, Array{operand(I.getOperand(0)), operand(I.getOperand(1))}); };
  auto Unary = [&](StringRef Name) { return Emit(Name, Array{operand(I.getOperand(0))}); };
  switch (I.getOpcode()) {
  case Instruction::FAdd: return Binary("fp_add");
  case Instruction::FSub: return Binary("fp_sub");
  case Instruction::FMul: return Binary("fp_mul");
  case Instruction::FDiv: return Binary("fp_div");
  case Instruction::FRem: return Binary("fp_frem");
  case Instruction::FNeg: return Unary("fp_neg");
  case Instruction::SIToFP: return Unary("sitofp");
  case Instruction::UIToFP: return Unary("uitofp");
  case Instruction::FPToSI: return Unary("fptosi");
  case Instruction::FPToUI: return Unary("fptoui");
  case Instruction::FPExt:
  case Instruction::FPTrunc: return Unary("fpconvert");
  case Instruction::FCmp: {
    const auto &Compare = cast<FCmpInst>(I);
    Object Op = floatOperation("fcmp", Values.lookup(&I), I.getType(),
                               Array{operand(I.getOperand(0)), operand(I.getOperand(1))});
    // LLVM's predicate names are the format's: oeq, ult, ord, uno, ...
    Op["predicate"] = CmpInst::getPredicateName(Compare.getPredicate());
    Op["signaling"] = false;
    Ops.push_back(std::move(Op));
    return true;
  }
  case Instruction::BitCast: {
    // The bits of a float as an integer of the same width, or the reverse.
    Type *From = I.getOperand(0)->getType(), *To = I.getType();
    if (!(From->isFloatingPointTy() && To->isIntegerTy()) && !(From->isIntegerTy() && To->isFloatingPointTy()))
      return false;
    Ops.push_back(operation("bitcast", Values.lookup(&I), To, Array{operand(I.getOperand(0))}));
    return true;
  }
  default:
    return false;
  }
}

// Lower I if it is a floating-point intrinsic; otherwise return false.
bool Emitter::lowerFloatIntrinsic(const IntrinsicInst &I, Array &Ops) {
  unsigned Result = Values.lookup(&I);
  auto Emit = [&](StringRef Name, unsigned Count) {
    Array Operands;
    for (unsigned Index = 0; Index < Count; ++Index)
      Operands.push_back(operand(I.getArgOperand(Index)));
    Ops.push_back(floatOperation(Name, Result, I.getType(), std::move(Operands)));
    return true;
  };
  switch (I.getIntrinsicID()) {
  case Intrinsic::fabs: return Emit("fp_abs", 1);
  case Intrinsic::sqrt: return Emit("fp_sqrt", 1);
  case Intrinsic::copysign: return Emit("fp_copysign", 2);
  case Intrinsic::fma: return Emit("fp_fma", 3);
  case Intrinsic::minnum: return Emit("fp_minnum", 2);
  case Intrinsic::maxnum: return Emit("fp_maxnum", 2);
  case Intrinsic::minimum: return Emit("fp_minimum", 2);
  case Intrinsic::maximum: return Emit("fp_maximum", 2);
  case Intrinsic::minimumnum: return Emit("fp_minimumnum", 2);
  case Intrinsic::maximumnum: return Emit("fp_maximumnum", 2);
  case Intrinsic::fptosi_sat: return Emit("fptosi_sat", 1);
  case Intrinsic::fptoui_sat: return Emit("fptoui_sat", 1);
  case Intrinsic::fmuladd: {
    // The product may be fused with the sum or rounded first. It is rounded
    // first, which is what the separate operations would do.
    unsigned Product = fresh();
    Ops.push_back(floatOperation("fp_mul", Product, I.getType(),
                                 Array{operand(I.getArgOperand(0)), operand(I.getArgOperand(1))}));
    Ops.push_back(floatOperation("fp_add", Result, I.getType(), Array{Product, operand(I.getArgOperand(2))}));
    return true;
  }
  case Intrinsic::is_fpclass:
    lowerClassTest(I, Ops);
    return true;
  default:
    return false;
  }
}

// llvm.is.fpclass: whether a float is in any of the classes a constant mask
// names. The classes are decided from the bits of the encoding, so the test
// neither quiets nor signals a NaN.
void Emitter::lowerClassTest(const IntrinsicInst &I, Array &Ops) {
  Type *Float = I.getArgOperand(0)->getType();
  if (!Float->isFloatTy() && !Float->isDoubleTy())
    return diagnose("E-UNSUPPORTED-INTRINSIC", "llvm.is.fpclass on a type other than float and double");
  unsigned Mask = cast<ConstantInt>(I.getArgOperand(1))->getZExtValue();
  unsigned Bits = Float->getPrimitiveSizeInBits().getFixedValue();
  unsigned Fraction = Float->isFloatTy() ? 23 : 52;
  IntegerType *Int = IntegerType::get(M.getContext(), Bits);
  Type *Bool = IntegerType::get(M.getContext(), 1);
  auto Constant = [&](const APInt &Value) { return constant(ConstantInt::get(Int, Value)); };
  auto Binary = [&](const char *Name, Type *Ty, unsigned Left, unsigned Right) {
    unsigned Id = fresh();
    Object Op = operation(Name, Id, Ty, Array{Left, Right});
    Op["flags"] = Array{};
    Ops.push_back(std::move(Op));
    return Id;
  };
  auto Compare = [&](const char *Predicate, unsigned Left, unsigned Right) {
    unsigned Id = fresh();
    Object Op = operation("icmp", Id, Bool, Array{Left, Right});
    Op["predicate"] = Predicate;
    Ops.push_back(std::move(Op));
    return Id;
  };
  APInt Sign = APInt::getSignMask(Bits);
  APInt Infinity = APInt::getBitsSet(Bits, Fraction, Bits - 1);
  APInt Quiet = Infinity | APInt::getOneBitSet(Bits, Fraction - 1);
  APInt MinNormal = APInt::getOneBitSet(Bits, Fraction);
  unsigned Encoding = fresh();
  Ops.push_back(operation("bitcast", Encoding, Int, Array{operand(I.getArgOperand(0))}));
  unsigned Magnitude = Binary("i_and", Int, Encoding, Constant(~Sign));
  unsigned Negative = Compare("slt", Encoding, Constant(APInt::getZero(Bits)));
  unsigned Positive = Compare("sge", Encoding, Constant(APInt::getZero(Bits)));
  // Each class, as a test of the magnitude.
  auto Signaling = [&] {
    return Binary("i_and", Bool, Compare("ugt", Magnitude, Constant(Infinity)),
                  Compare("ult", Magnitude, Constant(Quiet)));
  };
  auto IsQuiet = [&] { return Compare("uge", Magnitude, Constant(Quiet)); };
  auto IsInfinite = [&] { return Compare("eq", Magnitude, Constant(Infinity)); };
  auto IsZero = [&] { return Compare("eq", Magnitude, Constant(APInt::getZero(Bits))); };
  // Between zero and the smallest normal number, exclusive.
  auto IsSubnormal = [&] {
    unsigned Below = Binary("i_sub", Int, Magnitude, Constant(APInt(Bits, 1)));
    return Compare("ult", Below, Constant(MinNormal - 1));
  };
  auto IsNormal = [&] {
    unsigned Above = Binary("i_sub", Int, Magnitude, Constant(MinNormal));
    return Compare("ult", Above, Constant(Infinity - MinNormal));
  };
  std::optional<unsigned> Any;
  auto Include = [&](unsigned Condition) { Any = Any ? Binary("i_or", Bool, *Any, Condition) : Condition; };
  // A class of either sign is the magnitude test alone; of one sign, the
  // test and the sign.
  auto Signed = [&](unsigned NegativeBit, unsigned PositiveBit, function_ref<unsigned()> Test) {
    bool WantNegative = Mask & NegativeBit, WantPositive = Mask & PositiveBit;
    if (WantNegative && WantPositive)
      Include(Test());
    else if (WantNegative || WantPositive)
      Include(Binary("i_and", Bool, Test(), WantNegative ? Negative : Positive));
  };
  if (Mask & fcSNan)
    Include(Signaling());
  if (Mask & fcQNan)
    Include(IsQuiet());
  Signed(fcNegInf, fcPosInf, IsInfinite);
  Signed(fcNegNormal, fcPosNormal, IsNormal);
  Signed(fcNegSubnormal, fcPosSubnormal, IsSubnormal);
  Signed(fcNegZero, fcPosZero, IsZero);
  unsigned Outcome = Any ? *Any : constant(ConstantInt::getFalse(M.getContext()));
  Ops.push_back(operation("copy", Values.lookup(&I), I.getType(), Array{Outcome}));
}

} // namespace smir
