// How C calls that LLVM leaves to the target are carried: aggregates passed
// by value, variadic arguments, and arithmetic that reports overflow.
//
// These are choices of this compiler, made with ordinary memory operations.
// They are not the source ABI records of the ABI chapter, which need a
// compiler that produces them.
#include "emitter.h"

namespace smir {

// A stack object that lives as long as the function's activation, created at
// the start of the entry block.
unsigned Emitter::stackObject(uint64_t Bytes, uint64_t Alignment) {
  unsigned Size = constantInt(Bytes);
  unsigned Id = fresh();
  Object Op = operation("alloca", Id, PointerType::get(M.getContext(), 0), Array{Size});
  Op["helper"] = helper("stack_alloc", {intType(64), intType(64)}, {pointerType()});
  Op["binding"] = nullptr;
  Op["alignment"] = (int64_t)Alignment;
  EntryConstants.push_back(std::move(Op));
  return Id;
}

// Base plus a constant number of bytes, with no promise about the result.
unsigned Emitter::offsetPointer(unsigned Base, uint64_t Bytes, Array &Ops) {
  if (Bytes == 0)
    return Base;
  unsigned Delta = constantInt(Bytes);
  unsigned Result = fresh();
  Object Op = operation("ptr_offset", Result, PointerType::get(M.getContext(), 0), Array{Base, Delta});
  Op["inbounds"] = false;
  Op["check_base"] = false;
  Op["nuw"] = false;
  Op["nusw"] = false;
  Op["inrange"] = nullptr;
  Ops.push_back(std::move(Op));
  return Result;
}

// A parameter passed by value arrives as a pointer to the caller's object.
// The function copies it into an object of its own before anything else
// runs, and its body uses the copy: the caller's object is never modified
// through the parameter, and later changes to it are not seen.
void Emitter::copyByValue(const Argument &Arg) {
  Type *Pointee = Arg.getParamByValType();
  uint64_t Bytes = DL.getTypeAllocSize(Pointee).getFixedValue();
  uint64_t Alignment = Arg.getParamAlign().valueOrOne().value();
  unsigned Passed = Values.lookup(&Arg);
  unsigned Copy = stackObject(Bytes, Alignment);
  if (Bytes)
    EntryConstants.push_back(Object{{"op", "memcpy"},
                                    {"results", Array{}},
                                    {"operands", Array{Copy, Passed, constantInt(Bytes)}},
                                    {"alignment", 1},
                                    {"volatile", false}});
  Values[&Arg] = Copy;
}

// Whether a value of this type can be a variadic argument: one that fits a
// slot of eight bytes.
bool Emitter::variadicSlotType(Type *Ty) {
  if (Ty->isIntegerTy())
    return Ty->getIntegerBitWidth() <= 64;
  return Ty->isFloatTy() || Ty->isDoubleTy() || Ty->isPointerTy();
}

// The variadic arguments of a call are stored in consecutive eight-byte
// slots of one stack object, and the object's address is passed as an extra
// last argument. The object belongs to the call site and is reused each time
// the call runs. A call with no variadic arguments passes a null pointer.
unsigned Emitter::variadicArea(const CallBase &I, Array &Ops) {
  unsigned Fixed = I.getFunctionType()->getNumParams();
  unsigned Count = I.arg_size() - Fixed;
  if (Count == 0)
    return constant(ConstantPointerNull::get(PointerType::get(M.getContext(), 0)));
  unsigned Area = stackObject(8 * (uint64_t)Count, 8);
  for (unsigned Index = 0; Index < Count; ++Index) {
    const Value *Argument = I.getArgOperand(Fixed + Index);
    Type *Ty = Argument->getType();
    if (I.paramHasAttr(Fixed + Index, Attribute::ByVal) || !variadicSlotType(Ty)) {
      std::string Name;
      raw_string_ostream(Name) << *Ty;
      diagnose("E-UNSUPPORTED-CALL", "variadic argument that does not fit eight bytes: " + Name);
      continue;
    }
    Object Store{{"op", "store"},
                 {"results", Array{}},
                 {"operands", Array{offsetPointer(Area, 8 * (uint64_t)Index, Ops), operand(Argument)}}};
    access(Store, Ty, DL.getABITypeAlign(Ty));
    Ops.push_back(std::move(Store));
  }
  return Area;
}

// A va_list is one pointer: the address of the next variadic slot.
//
// va_start stores the function's hidden last parameter in it, va_copy copies
// it, and va_end does nothing.
bool Emitter::lowerVariadicIntrinsic(const IntrinsicInst &I, Array &Ops) {
  Type *Pointer = PointerType::get(M.getContext(), 0);
  auto StoreCursor = [&](const Value *List, unsigned Cursor) {
    Object Store{{"op", "store"}, {"results", Array{}}, {"operands", Array{operand(List), Cursor}}};
    access(Store, Pointer, Align(8));
    Ops.push_back(std::move(Store));
  };
  switch (I.getIntrinsicID()) {
  case Intrinsic::vastart:
    if (!VariadicArguments)
      diagnose("E-UNSUPPORTED-INTRINSIC", "va_start outside a variadic function");
    else
      StoreCursor(I.getArgOperand(0), *VariadicArguments);
    return true;
  case Intrinsic::vacopy: {
    unsigned Cursor = fresh();
    Object Load = operation("load", Cursor, Pointer, Array{operand(I.getArgOperand(1))});
    access(Load, Pointer, Align(8));
    Ops.push_back(std::move(Load));
    StoreCursor(I.getArgOperand(0), Cursor);
    return true;
  }
  case Intrinsic::vaend:
    return true;
  default:
    return false;
  }
}

// va_arg reads the slot the list points at and advances the list by a slot.
void Emitter::lowerVariadicArgument(const VAArgInst &I, Array &Ops) {
  Type *Ty = I.getType();
  if (!variadicSlotType(Ty)) {
    std::string Name;
    raw_string_ostream(Name) << *Ty;
    return diagnose("E-UNSUPPORTED-INSTRUCTION", "va_arg of a type that does not fit eight bytes: " + Name);
  }
  Type *Pointer = PointerType::get(M.getContext(), 0);
  unsigned List = operand(I.getPointerOperand());
  unsigned Cursor = fresh();
  Object LoadCursor = operation("load", Cursor, Pointer, Array{List});
  access(LoadCursor, Pointer, Align(8));
  Ops.push_back(std::move(LoadCursor));
  Object LoadValue = operation("load", Values.lookup(&I), Ty, Array{Cursor});
  access(LoadValue, Ty, DL.getABITypeAlign(Ty));
  Ops.push_back(std::move(LoadValue));
  Object Store{{"op", "store"}, {"results", Array{}}, {"operands", Array{List, offsetPointer(Cursor, 8, Ops)}}};
  access(Store, Pointer, Align(8));
  Ops.push_back(std::move(Store));
}

// The intrinsics that return a result and whether it overflowed. Their two
// results are the values that extractvalue selects; see `Pairs`.
bool Emitter::lowerOverflow(const IntrinsicInst &I, Array &Ops) {
  auto Found = Pairs.find(&I);
  if (Found == Pairs.end())
    return false;
  auto [Result, Overflowed] = Found->second;
  Type *Ty = I.getArgOperand(0)->getType();
  Type *Bool = IntegerType::get(M.getContext(), 1);
  unsigned Bits = Ty->getIntegerBitWidth();
  unsigned Left = operand(I.getArgOperand(0)), Right = operand(I.getArgOperand(1));
  auto Binary = [&](const char *Name, unsigned Id, Type *Type, unsigned A, unsigned B) {
    Object Op = operation(Name, Id, Type, Array{A, B});
    Op["flags"] = Array{};
    Ops.push_back(std::move(Op));
    return Id;
  };
  auto Compare = [&](const char *Predicate, unsigned A, unsigned B) {
    Object Op = operation("icmp", Overflowed, Bool, Array{A, B});
    Op["predicate"] = Predicate;
    Ops.push_back(std::move(Op));
  };
  unsigned Zero = constant(ConstantInt::get(Ty, 0));
  switch (I.getIntrinsicID()) {
  case Intrinsic::uadd_with_overflow:
    // The sum wrapped if it is below an operand.
    Binary("i_add", Result, Ty, Left, Right);
    Compare("ult", Result, Left);
    return true;
  case Intrinsic::usub_with_overflow:
    Binary("i_sub", Result, Ty, Left, Right);
    Compare("ult", Left, Right);
    return true;
  case Intrinsic::sadd_with_overflow: {
    // Overflow: both operands differ in sign from the sum.
    Binary("i_add", Result, Ty, Left, Right);
    unsigned A = Binary("i_xor", fresh(), Ty, Left, Result), B = Binary("i_xor", fresh(), Ty, Right, Result);
    Compare("slt", Binary("i_and", fresh(), Ty, A, B), Zero);
    return true;
  }
  case Intrinsic::ssub_with_overflow: {
    // Overflow: the operands differ in sign, and so do the minuend and the
    // difference.
    Binary("i_sub", Result, Ty, Left, Right);
    unsigned A = Binary("i_xor", fresh(), Ty, Left, Right), B = Binary("i_xor", fresh(), Ty, Left, Result);
    Compare("slt", Binary("i_and", fresh(), Ty, A, B), Zero);
    return true;
  }
  case Intrinsic::umul_with_overflow:
  case Intrinsic::smul_with_overflow: {
    // The exact product in twice the width, compared with the product that
    // fits.
    if (2 * Bits > MaxIntBits) {
      diagnose("E-UNSUPPORTED-INTRINSIC", "overflow-checked multiplication wider than half the widest integer");
      return true;
    }
    bool IsSigned = I.getIntrinsicID() == Intrinsic::smul_with_overflow;
    Type *Wide = IntegerType::get(M.getContext(), 2 * Bits);
    const char *Extend = IsSigned ? "sext" : "zext";
    unsigned A = fresh(), B = fresh(), Back = fresh();
    Ops.push_back(operation(Extend, A, Wide, Array{Left}));
    Ops.push_back(operation(Extend, B, Wide, Array{Right}));
    unsigned Product = Binary("i_mul", fresh(), Wide, A, B);
    Ops.push_back(operation("trunc", Result, Ty, Array{Product}));
    Ops.push_back(operation(Extend, Back, Wide, Array{Result}));
    Compare("ne", Product, Back);
    return true;
  }
  default:
    return false;
  }
}

} // namespace smir
