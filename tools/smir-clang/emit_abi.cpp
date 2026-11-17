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

// How many eight-byte slots a variadic argument of this type takes: one, or
// two for the sixteen-byte scalars, which are also aligned to sixteen bytes.
// Zero for a type that cannot be a variadic argument. A structure is passed
// as a pointer to a copy, so it takes one.
unsigned Emitter::variadicSlots(Type *Ty) {
  if (Ty->isIntegerTy())
    return Ty->getIntegerBitWidth() <= 64 ? 1 : Ty->getIntegerBitWidth() <= 128 ? 2 : 0;
  if (Ty->isFP128Ty())
    return 2;
  return Ty->isFloatTy() || Ty->isDoubleTy() || Ty->isPointerTy() ? 1 : 0;
}

// The variadic arguments of a call are stored in consecutive eight-byte
// slots of one stack object, and the object's address is passed as an extra
// last argument. A sixteen-byte argument starts at a multiple of sixteen
// bytes; the object is aligned to sixteen so that the callee can find that
// place from the address alone. The object belongs to the call site and is
// reused each time the call runs. A call with no variadic arguments passes a
// null pointer.
unsigned Emitter::variadicArea(const CallBase &I, Array &Ops) {
  unsigned Fixed = I.getFunctionType()->getNumParams();
  if (I.arg_size() == Fixed)
    return constant(ConstantPointerNull::get(PointerType::get(M.getContext(), 0)));
  // Lay the arguments out first; the object's size is where the last ends.
  SmallVector<uint64_t, 8> Offsets;
  uint64_t Bytes = 0;
  for (unsigned Index = Fixed; Index < I.arg_size(); ++Index) {
    Type *Ty = I.getArgOperand(Index)->getType();
    unsigned Slots = variadicSlots(Ty);
    if (Slots == 0) {
      std::string Name;
      raw_string_ostream(Name) << *Ty;
      diagnose("E-UNSUPPORTED-CALL", "variadic argument that is no scalar of at most sixteen bytes: " + Name);
      return 0;
    }
    Bytes = alignTo(Bytes, 8 * Slots);
    Offsets.push_back(Bytes);
    Bytes += 8 * Slots;
  }
  unsigned Area = stackObject(Bytes, 16);
  for (unsigned Index = Fixed; Index < I.arg_size(); ++Index) {
    const Value *Argument = I.getArgOperand(Index);
    unsigned Passed = operand(Argument);
    if (I.paramHasAttr(Index, Attribute::ByVal)) {
      // A structure by value: the callee's va_arg reads a pointer and
      // copies from it. What it must find there is the structure as it is
      // now, so the call makes its own copy and passes that.
      Type *Pointee = I.getParamByValType(Index);
      uint64_t Size = DL.getTypeAllocSize(Pointee).getFixedValue();
      unsigned Copy = stackObject(Size, I.getParamAlign(Index).valueOrOne().value());
      if (Size)
        Ops.push_back(Object{{"op", "memcpy"},
                             {"results", Array{}},
                             {"operands", Array{Copy, Passed, constantInt(Size)}},
                             {"alignment", 1},
                             {"volatile", false}});
      Passed = Copy;
    }
    Object Store{{"op", "store"},
                 {"results", Array{}},
                 {"operands", Array{offsetPointer(Area, Offsets[Index - Fixed], Ops), Passed}}};
    access(Store, Argument->getType(), DL.getABITypeAlign(Argument->getType()));
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

// va_arg reads the slots the list points at and advances the list past
// them. For a sixteen-byte argument the list is first moved up to the next
// address that is a multiple of sixteen.
void Emitter::lowerVariadicArgument(const VAArgInst &I, Array &Ops) {
  Type *Ty = I.getType();
  unsigned Slots = variadicSlots(Ty);
  if (Slots == 0) {
    std::string Name;
    raw_string_ostream(Name) << *Ty;
    return diagnose("E-UNSUPPORTED-INSTRUCTION", "va_arg of a type that is no scalar of at most sixteen bytes: " + Name);
  }
  Type *Pointer = PointerType::get(M.getContext(), 0);
  Type *Address = IntegerType::get(M.getContext(), 64);
  unsigned List = operand(I.getPointerOperand());
  unsigned Cursor = fresh();
  Object LoadCursor = operation("load", Cursor, Pointer, Array{List});
  access(LoadCursor, Pointer, Align(8));
  Ops.push_back(std::move(LoadCursor));
  if (Slots == 2) {
    // The distance to the next multiple of sixteen is the low four bits of
    // the negated address.
    unsigned Bits = fresh(), Negated = fresh(), Padding = fresh(), Aligned = fresh();
    Ops.push_back(operation("ptrtoaddr", Bits, Address, Array{Cursor}));
    Object Negate = operation("i_sub", Negated, Address, Array{constantInt(0), Bits});
    Negate["flags"] = Array{};
    Ops.push_back(std::move(Negate));
    Object Mask = operation("i_and", Padding, Address, Array{Negated, constantInt(15)});
    Mask["flags"] = Array{};
    Ops.push_back(std::move(Mask));
    Object Advance = operation("ptr_offset", Aligned, Pointer, Array{Cursor, Padding});
    Advance["inbounds"] = false;
    Advance["check_base"] = false;
    Advance["nuw"] = false;
    Advance["nusw"] = false;
    Advance["inrange"] = nullptr;
    Ops.push_back(std::move(Advance));
    Cursor = Aligned;
  }
  Object LoadValue = operation("load", Values.lookup(&I), Ty, Array{Cursor});
  access(LoadValue, Ty, DL.getABITypeAlign(Ty));
  Ops.push_back(std::move(LoadValue));
  Object Store{{"op", "store"},
               {"results", Array{}},
               {"operands", Array{List, offsetPointer(Cursor, 8 * (uint64_t)Slots, Ops)}}};
  access(Store, Pointer, Align(8));
  Ops.push_back(std::move(Store));
}

// The intrinsics that return a result and whether it overflowed. Their two
// results are the values that extractvalue selects; see `Pairs`.
bool Emitter::lowerOverflow(const IntrinsicInst &I, Array &Ops) {
  auto Found = Pairs.find(&I);
  if (Found == Pairs.end())
    return false;
  unsigned Result = Found->second.first, Overflowed = Found->second.second;
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
    bool IsSigned = I.getIntrinsicID() == Intrinsic::smul_with_overflow;
    if (2 * Bits > MaxIntBits) {
      // Too wide to hold the exact product. An unsigned product overflowed
      // if dividing it by one factor does not give back the other; a zero
      // factor cannot overflow, and is replaced by one for the division.
      if (IsSigned) {
        diagnose("E-UNSUPPORTED-INTRINSIC", "signed overflow-checked multiplication wider than half the widest integer");
        return true;
      }
      Binary("i_mul", Result, Ty, Left, Right);
      unsigned IsZero = fresh(), Divisor = fresh(), Differs = fresh(), NonZero = fresh();
      Object Zeroed = operation("icmp", IsZero, Bool, Array{Right, Zero});
      Zeroed["predicate"] = "eq";
      Ops.push_back(std::move(Zeroed));
      Ops.push_back(operation("select", Divisor, Ty, Array{IsZero, constant(ConstantInt::get(Ty, 1)), Right}));
      unsigned Quotient = Binary("i_udiv", fresh(), Ty, Result, Divisor);
      Object Changed = operation("icmp", Differs, Bool, Array{Quotient, Left});
      Changed["predicate"] = "ne";
      Ops.push_back(std::move(Changed));
      Object Present = operation("icmp", NonZero, Bool, Array{Right, Zero});
      Present["predicate"] = "ne";
      Ops.push_back(std::move(Present));
      Binary("i_and", Overflowed, Bool, Differs, NonZero);
      return true;
    }
    // The exact product in twice the width, compared with the product that
    // fits.
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
