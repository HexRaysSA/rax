// Lowering of calls: intrinsics, direct and indirect calls, and the runtime
// services that declared functions are bound to.
#include "emitter.h"

namespace smir {

void Emitter::lowerIntrinsic(const IntrinsicInst &I, Array &Ops) {
  if (lowerFloatIntrinsic(I, Ops) || lowerVariadicIntrinsic(I, Ops) || lowerOverflow(I, Ops))
    return;
  unsigned Result = Values.lookup(&I);
  auto Unary = [&](const char *Name, bool ZeroIsPoison) {
    Object Op = operation(Name, Result, I.getType(), Array{operand(I.getArgOperand(0))});
    Op["zero_is_poison"] = ZeroIsPoison;
    Ops.push_back(std::move(Op));
  };
  auto Flag = [&](unsigned Index) { return cast<ConstantInt>(I.getArgOperand(Index))->isOne(); };
  // min and max become a comparison and a select on the same operands.
  auto MinMax = [&](const char *Predicate) {
    unsigned Left = operand(I.getArgOperand(0)), Right = operand(I.getArgOperand(1));
    unsigned Condition = fresh();
    Object Compare = Object{{"op", "icmp"},
                            {"results", Array{Object{{"id", Condition}, {"type", ref(intType(1))}}}},
                            {"operands", Array{Left, Right}},
                            {"predicate", Predicate}};
    Ops.push_back(std::move(Compare));
    Ops.push_back(operation("select", Result, I.getType(), Array{Condition, Left, Right}));
  };
  // Unsigned saturation: compute the wrapping result, detect the wrap with one
  // comparison, and select the bound when it happened.
  auto Saturate = [&](const char *Name, const char *Predicate, bool WrapComparesResult, Constant *Bound) {
    unsigned Left = operand(I.getArgOperand(0)), Right = operand(I.getArgOperand(1));
    unsigned Wrapped = fresh(), Overflowed = fresh();
    Object Arithmetic = operation(Name, Wrapped, I.getType(), Array{Left, Right});
    Arithmetic["flags"] = Array{};
    Ops.push_back(std::move(Arithmetic));
    // Addition wrapped if the sum is below an operand; subtraction wrapped if
    // the minuend is below the subtrahend.
    Ops.push_back(Object{{"op", "icmp"},
                         {"results", Array{Object{{"id", Overflowed}, {"type", ref(intType(1))}}}},
                         {"operands", WrapComparesResult ? Array{Wrapped, Left} : Array{Left, Right}},
                         {"predicate", Predicate}});
    Ops.push_back(operation("select", Result, I.getType(), Array{Overflowed, constant(Bound), Wrapped}));
  };
  // A three-way comparison is the difference of two comparisons: one when
  // the left operand is greater, minus one when it is less.
  auto ThreeWay = [&](const char *Greater, const char *Less) {
    unsigned Left = operand(I.getArgOperand(0)), Right = operand(I.getArgOperand(1));
    unsigned Wide[2];
    for (unsigned Side = 0; Side < 2; ++Side) {
      unsigned Condition = fresh();
      Wide[Side] = fresh();
      Ops.push_back(Object{{"op", "icmp"},
                           {"results", Array{Object{{"id", Condition}, {"type", ref(intType(1))}}}},
                           {"operands", Array{Left, Right}},
                           {"predicate", Side == 0 ? Greater : Less}});
      Ops.push_back(operation("zext", Wide[Side], I.getType(), Array{Condition}));
    }
    Object Difference = operation("i_sub", Result, I.getType(), Array{Wide[0], Wide[1]});
    Difference["flags"] = Array{};
    Ops.push_back(std::move(Difference));
  };
  switch (I.getIntrinsicID()) {
  case Intrinsic::ucmp: return ThreeWay("ugt", "ult");
  case Intrinsic::scmp: return ThreeWay("sgt", "slt");
  case Intrinsic::uadd_sat: return Saturate("i_add", "ult", true, Constant::getAllOnesValue(I.getType()));
  case Intrinsic::usub_sat: return Saturate("i_sub", "ult", false, Constant::getNullValue(I.getType()));
  case Intrinsic::ctlz: return Unary("i_clz", Flag(1));
  case Intrinsic::cttz: return Unary("i_ctz", Flag(1));
  case Intrinsic::ctpop: return Unary("i_popcount", false);
  case Intrinsic::abs: return Unary("i_abs", Flag(1));
  case Intrinsic::bswap: return Unary("i_bswap", false);
  case Intrinsic::bitreverse: return Unary("i_bitreverse", false);
  case Intrinsic::smax: return MinMax("sgt");
  case Intrinsic::smin: return MinMax("slt");
  case Intrinsic::umax: return MinMax("ugt");
  case Intrinsic::umin: return MinMax("ult");
  case Intrinsic::sadd_sat:
  case Intrinsic::ssub_sat: {
    // Signed saturation: on overflow the result is the bound on the side of
    // the first operand's sign.
    bool Add = I.getIntrinsicID() == Intrinsic::sadd_sat;
    Type *Ty = I.getType();
    unsigned Bits = Ty->getIntegerBitWidth();
    unsigned Left = operand(I.getArgOperand(0)), Right = operand(I.getArgOperand(1));
    auto Binary = [&](const char *Name, unsigned A, unsigned B) {
      unsigned Id = fresh();
      Object Op = operation(Name, Id, Ty, Array{A, B});
      Op["flags"] = Array{};
      Ops.push_back(std::move(Op));
      return Id;
    };
    auto Negative = [&](unsigned Value) {
      unsigned Id = fresh();
      Object Op = operation("icmp", Id, IntegerType::get(M.getContext(), 1),
                            Array{Value, constant(ConstantInt::get(Ty, 0))});
      Op["predicate"] = "slt";
      Ops.push_back(std::move(Op));
      return Id;
    };
    unsigned Wrapped = Binary(Add ? "i_add" : "i_sub", Left, Right);
    // A sum overflows when both operands differ in sign from it; a
    // difference, when the operands differ and so do the first and it.
    unsigned Overflowed = Negative(Binary("i_and", Binary("i_xor", Left, Add ? Wrapped : Right),
                                          Binary("i_xor", Add ? Right : Left, Wrapped)));
    unsigned Bound = fresh();
    Ops.push_back(operation("select", Bound, Ty,
                            Array{Negative(Left), constant(ConstantInt::get(Ty, APInt::getSignedMinValue(Bits))),
                                  constant(ConstantInt::get(Ty, APInt::getSignedMaxValue(Bits)))}));
    return Ops.push_back(operation("select", Result, Ty, Array{Overflowed, Bound, Wrapped}));
  }
  case Intrinsic::fshl:
  case Intrinsic::fshr: {
    bool Left = I.getIntrinsicID() == Intrinsic::fshl;
    // A funnel shift of a value with itself is a rotate.
    if (I.getArgOperand(0) == I.getArgOperand(1)) {
      Object Op = operation(Left ? "i_rotl" : "i_rotr", Result, I.getType(),
                            Array{operand(I.getArgOperand(0)), operand(I.getArgOperand(2))});
      Op["flags"] = Array{};
      Ops.push_back(std::move(Op));
      return;
    }
    // Otherwise it shifts the two values as one double-width value and
    // keeps the high half (left) or the low half (right). The amount is
    // taken modulo the width, and an amount of zero keeps the first (left)
    // or the second (right) value unchanged, which the two shifts alone
    // would not: one of them would shift by the whole width.
    Type *Ty = I.getType();
    unsigned Bits = Ty->getIntegerBitWidth();
    if (!isPowerOf2_32(Bits))
      break;
    auto Binary = [&](const char *Name, unsigned A, unsigned B) {
      unsigned Id = fresh();
      Object Op = operation(Name, Id, Ty, Array{A, B});
      Op["flags"] = Array{};
      Ops.push_back(std::move(Op));
      return Id;
    };
    unsigned High = operand(I.getArgOperand(0)), Low = operand(I.getArgOperand(1));
    unsigned Mask = constant(ConstantInt::get(Ty, Bits - 1));
    unsigned Amount = Binary("i_and", operand(I.getArgOperand(2)), Mask);
    unsigned Inverse = Binary("i_and", Binary("i_sub", constant(ConstantInt::get(Ty, 0)), Amount), Mask);
    unsigned Combined = Left ? Binary("i_or", Binary("i_shl", High, Amount), Binary("i_lshr", Low, Inverse))
                             : Binary("i_or", Binary("i_lshr", Low, Amount), Binary("i_shl", High, Inverse));
    unsigned Zero = fresh();
    Object Compare = operation("icmp", Zero, IntegerType::get(M.getContext(), 1),
                               Array{Amount, constant(ConstantInt::get(Ty, 0))});
    Compare["predicate"] = "eq";
    Ops.push_back(std::move(Compare));
    return Ops.push_back(operation("select", Result, Ty, Array{Zero, Left ? High : Low, Combined}));
  }
  case Intrinsic::memcpy:
  case Intrinsic::memcpy_inline:
  case Intrinsic::memmove:
  case Intrinsic::memset:
  case Intrinsic::memset_inline:
    return lowerBulk(cast<MemIntrinsic>(I), Ops);
  case Intrinsic::lifetime_start: return lowerLifetime(I, Ops, true);
  case Intrinsic::lifetime_end: return lowerLifetime(I, Ops, false);
  // The stack is not unwound within a function: a stack object lives until
  // its function returns, so the mark that llvm.stacksave takes is no
  // value at all and restoring it does nothing. A variable-length array
  // declared in a loop is therefore a new object each time around.
  case Intrinsic::stacksave:
    return Ops.push_back(operation("copy", Result, I.getType(), Array{constant(Constant::getNullValue(I.getType()))}));
  case Intrinsic::stackrestore:
    return;
  // The address of a thread-local variable in the calling thread: a call of
  // the helper import for that variable's segment, which the fragment names
  // by the segment's position.
  case Intrinsic::threadlocal_address: {
    auto Found = ThreadLocals.find(dyn_cast<GlobalVariable>(I.getArgOperand(0)));
    if (Found == ThreadLocals.end())
      return diagnose("E-UNSUPPORTED-INTRINSIC", "address of a thread-local variable that is not defined here");
    Type *Offset = IntegerType::get(M.getContext(), 64);
    unsigned Signature = functionType({valueType(Offset, "thread-local offset")},
                                      {valueType(I.getType(), "thread-local address")});
    ThreadLocalSignature = Signature;
    return Ops.push_back(Object{
        {"op", "call"},
        {"results", Array{decl(Result, I.getType())}},
        {"operands", Array{constant(ConstantInt::get(Offset, 0))}},
        {"target", Object{{"kind", "import"},
                          {"import", ("tls:" + Twine(Found->second.first)).str()},
                          {"signature", ref(Signature)}}},
        {"unwind", "propagate"},
        {"source_plan", nullptr}});
  }
  // A hint about the likely value: the value itself.
  case Intrinsic::expect:
  case Intrinsic::expect_with_probability:
    return Ops.push_back(operation("copy", Result, I.getType(), Array{operand(I.getArgOperand(0))}));
  // Whether the argument is a compile-time constant. Answering no is always
  // allowed, and by now nothing would fold on a yes.
  case Intrinsic::is_constant:
    return Ops.push_back(
        operation("copy", Result, I.getType(), Array{constant(ConstantInt::getFalse(M.getContext()))}));
  // The size of the object a pointer points into, when the compiler cannot
  // tell: all ones, or zero if the caller asked for a lower bound.
  case Intrinsic::objectsize: {
    Constant *Unknown = Flag(1) ? Constant::getNullValue(I.getType()) : Constant::getAllOnesValue(I.getType());
    return Ops.push_back(operation("copy", Result, I.getType(), Array{constant(Unknown)}));
  }
  // These have no effect on the values computed.
  case Intrinsic::assume:
  case Intrinsic::donothing:
  case Intrinsic::experimental_noalias_scope_decl:
  case Intrinsic::prefetch:
    return;
  default:
    break;
  }
  diagnose("E-UNSUPPORTED-INTRINSIC", I.getCalledFunction()->getName());
}

void Emitter::lowerCall(const CallInst &I, Array &Ops) {
  if (auto *Assembly = dyn_cast<InlineAsm>(I.getCalledOperand())) {
    // Assembly with no instructions, operands or results only tells the
    // optimizer that memory may have changed. It has done that by now.
    if (Assembly->getAsmString().empty() && I.arg_empty() && I.getType()->isVoidTy())
      return;
    return diagnose("E-INLINE-ASSEMBLY", "inline assembly");
  }
  if (I.hasOperandBundles())
    return diagnose("E-OPERAND-BUNDLE", "call with operand bundles");
  const Function *Callee = I.getCalledFunction();
  Object Target;
  if (Callee && Callee->getName().starts_with(ServicePrefix)) {
    if (const smir::Service *Service = boundService(*Callee))
      lowerServiceCall(I, *Service, Ops);
    return;
  }
  if (Callee) {
    auto Defined = FunctionIds.find(Callee);
    if (Defined == FunctionIds.end())
      return diagnose("E-UNSUPPORTED-CALL", "call to undefined function " + Callee->getName());
    if (I.getFunctionType() != Callee->getFunctionType())
      return diagnose("E-UNSUPPORTED-CALL", "call through a different function type to " + Callee->getName());
    // LLVM makes a call whose convention differs from its callee's undefined.
    if (I.getCallingConv() != Callee->getCallingConv())
      return diagnose("E-UNSUPPORTED-CALL", "calling convention mismatch calling " + Callee->getName());
    Target = Object{{"kind", "direct"},
                    {"function", ref(Defined->second)},
                    {"signature", ref(SignatureIds.lookup(Callee))}};
  } else {
    // A call through a pointer. The pointer is retyped to the signature the
    // call uses; the engine then checks that the function it designates has
    // exactly that signature.
    // The pointer is in the program address space, or is a data pointer
    // that holds a function pointer.
    const Value *Pointer = I.getCalledOperand();
    if (!portableConvention(I.getCallingConv()))
      return diagnose("E-UNSUPPORTED-CALL", "indirect call with a non-default calling convention");
    // A data pointer that was not given the code pointer type holds the
    // function's address; see emit_code.cpp.
    bool Held = Pointer->getType()->getPointerAddressSpace() != 1 && !CodeValues.count(Pointer) &&
                !isa<ConstantPointerNull>(Pointer);
    unsigned Callee = Held ? codeFromData(operand(Pointer), Ops) : codeOperand(Pointer);
    unsigned Signature = signatureType(I.getFunctionType());
    unsigned Typed = fresh();
    Ops.push_back(Object{{"op", "bitcast"},
                         {"results", Array{Object{{"id", Typed}, {"type", ref(codePointerType(Signature))}}}},
                         {"operands", Array{Callee}}});
    Target = Object{{"kind", "indirect"}, {"value", Typed}, {"signature", ref(Signature)}};
  }
  Array Operands, Results;
  unsigned Fixed = I.getFunctionType()->getNumParams();
  for (unsigned Index = 0; Index < Fixed; ++Index)
    Operands.push_back(operand(I.getArgOperand(Index)));
  if (I.getFunctionType()->isVarArg())
    Operands.push_back(variadicArea(I, Ops));
  if (!I.getType()->isVoidTy())
    Results.push_back(decl(Values.lookup(&I), I.getType()));
  Ops.push_back(Object{{"op", "call"},
                       {"results", std::move(Results)},
                       {"operands", std::move(Operands)},
                       {"target", std::move(Target)},
                       {"unwind", "propagate"},
                       {"source_plan", nullptr}});
}

// The LLVM type a C declaration uses for a type of the service catalog, or
// null for a type no C declaration can carry yet.
Type *Emitter::serviceType(StringRef Name) {
  LLVMContext &Context = M.getContext();
  if (Name == "u64" || Name == "i64")
    return Type::getInt64Ty(Context);
  if (Name == "u32" || Name == "i32")
    return Type::getInt32Ty(Context);
  if (Name == "u8")
    return Type::getInt8Ty(Context);
  if (Name == "data_ptr")
    return PointerType::get(Context, 0);
  // A pointer to a function, of whatever type the declaration gives it.
  if (Name == "code_ptr")
    return PointerType::get(Context, DL.getProgramAddressSpace());
  return nullptr;
}

// The service a declaration is bound to by its link name. The declaration
// must have the service's shape in C: the service's parameters, then one
// pointer for each result after the first, and the first result as the
// return type. It may leave out those pointers, all of them, when it has no
// use for the results. A declaration that does not bind is diagnosed once.
const smir::Service *Emitter::boundService(const Function &F) {
  auto [Slot, Inserted] = Bindings.try_emplace(&F, nullptr);
  if (!Inserted)
    return Slot->second;
  StringRef Name = F.getName().substr(ServicePrefix.size());
  auto Found = find_if(Options.Services, [&](const smir::Service &Service) { return Service.Name == Name; });
  if (Found == Options.Services.end()) {
    diagnose("E-SERVICE-BINDING", "no runtime service is named " + Name);
    return nullptr;
  }
  SmallVector<Type *, 8> Params;
  Type *Returned = Type::getVoidTy(M.getContext());
  bool Expressible = true;
  for (const std::string &Param : Found->Params)
    Expressible &= Params.emplace_back(serviceType(Param)) != nullptr;
  const size_t Taken = Params.size();
  for (size_t Index = 0; Index < Found->Results.size(); ++Index) {
    Type *Result = serviceType(Found->Results[Index]);
    Expressible &= Result != nullptr;
    if (Index == 0)
      Returned = Result;
    else
      Params.push_back(PointerType::get(M.getContext(), 0));
  }
  if (!Expressible) {
    diagnose("E-SERVICE-BINDING", "service " + Name + " uses a type that C declarations cannot carry yet");
    return nullptr;
  }
  const FunctionType *Declared = F.getFunctionType();
  const ArrayRef<Type *> Full(Params);
  if (Declared->isVarArg() || Declared->getReturnType() != Returned ||
      (Declared->params() != Full && Declared->params() != Full.take_front(Taken))) {
    diagnose("E-SERVICE-BINDING", "the declaration bound to " + Name + " does not have the service's parameters and results");
    return nullptr;
  }
  return Slot->second = &*Found;
}

// A call of a runtime service: one call operation with all the service's
// results, then a store of each result after the first through the pointer
// the C declaration passes for it.
void Emitter::lowerServiceCall(const CallInst &I, const smir::Service &Service, Array &Ops) {
  SmallVector<unsigned, 8> Params, Results;
  SmallVector<Type *, 2> ResultTypes;
  for (const std::string &Param : Service.Params)
    Params.push_back(valueType(serviceType(Param), "service parameter"));
  for (const std::string &Result : Service.Results) {
    ResultTypes.push_back(serviceType(Result));
    Results.push_back(valueType(ResultTypes.back(), "service result"));
  }
  unsigned Signature = functionType(Params, Results);
  Services.try_emplace(Service.Name, Signature);
  Array Operands, Declared;
  for (size_t Index = 0; Index < Params.size(); ++Index)
    Operands.push_back(operand(I.getArgOperand(Index)));
  SmallVector<unsigned, 2> Ids;
  for (size_t Index = 0; Index < Results.size(); ++Index) {
    Ids.push_back(Index == 0 ? Values.lookup(&I) : fresh());
    Declared.push_back(Object{{"id", Ids.back()}, {"type", ref(Results[Index])}});
  }
  // The import identifier is assigned when the fragment is merged; the
  // service is named here.
  Ops.push_back(Object{{"op", "call"},
                       {"results", std::move(Declared)},
                       {"operands", std::move(Operands)},
                       {"target", Object{{"kind", "import"}, {"import", Service.Name}, {"signature", ref(Signature)}}},
                       {"unwind", "propagate"},
                       {"source_plan", nullptr}});
  // A declaration without the result pointers drops those results.
  for (size_t Index = 1; Index < Results.size() && I.arg_size() > Params.size(); ++Index) {
    Object Store{{"op", "store"},
                 {"results", Array{}},
                 {"operands", Array{operand(I.getArgOperand(Params.size() + Index - 1)), Ids[Index]}}};
    access(Store, ResultTypes[Index], DL.getABITypeAlign(ResultTypes[Index]));
    Ops.push_back(std::move(Store));
  }
}

} // namespace smir
