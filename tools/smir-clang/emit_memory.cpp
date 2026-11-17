// Lowering of memory: stack objects, address arithmetic, lifetime markers,
// bulk copies and fills, and global variables with their initializers.
#include "emitter.h"

namespace smir {

// memcpy, memmove and memset. A copy moves bytes with their shadow, so
// pointers and poison survive it.
void Emitter::lowerBulk(const MemIntrinsic &I, Array &Ops) {
  unsigned LengthBits = I.getLength()->getType()->getIntegerBitWidth();
  if (LengthBits > 64)
    return diagnose("E-UNSUPPORTED-INTRINSIC", "bulk memory length wider than 64 bits");
  unsigned Length = operand(I.getLength());
  if (LengthBits < 64) {
    unsigned Widened = fresh();
    Ops.push_back(operation("zext", Widened, IntegerType::get(M.getContext(), 64), Array{Length}));
    Length = Widened;
  }
  // One alignment covers both ends, so it is the weaker of the two.
  uint64_t Alignment = I.getDestAlign().valueOrOne().value();
  unsigned Second;
  const char *Name;
  if (auto *Fill = dyn_cast<MemSetInst>(&I)) {
    Name = "memset";
    Second = operand(Fill->getValue());
  } else {
    auto *Transfer = cast<MemTransferInst>(&I);
    Name = isa<MemMoveInst>(I) ? "memmove" : "memcpy";
    Second = operand(Transfer->getRawSource());
    Alignment = std::min(Alignment, Transfer->getSourceAlign().valueOrOne().value());
  }
  Ops.push_back(Object{{"op", Name},
                       {"results", Array{}},
                       {"operands", Array{operand(I.getRawDest()), Second, Length}},
                       {"alignment", (int64_t)Alignment},
                       {"volatile", I.isVolatile()}});
}

// llvm.global_ctors and llvm.global_dtors: an array of a priority, a function
// that takes and returns nothing, and an optional global the entry belongs
// to. The whole program is here, so every entry is kept.
void Emitter::lowerStructors(const GlobalVariable &List, Array &Out) {
  auto *Entries = dyn_cast<ConstantArray>(List.getInitializer());
  if (!Entries)
    return; // An empty list is a zero initializer.
  for (const Use &Entry : Entries->operands()) {
    auto *Fields = cast<ConstantStruct>(Entry);
    auto *F = dyn_cast<Function>(Fields->getOperand(1)->stripPointerCasts());
    auto Defined = F ? FunctionIds.find(F) : FunctionIds.end();
    if (Defined == FunctionIds.end() || !F->arg_empty() || !F->getReturnType()->isVoidTy()) {
      diagnose("E-UNSUPPORTED-GLOBAL", "entry of " + List.getName() + " that is not a defined function of no arguments");
      continue;
    }
    Out.push_back(Object{{"function", Defined->second},
                         {"priority", (int64_t)cast<ConstantInt>(Fields->getOperand(0))->getZExtValue()}});
  }
}

// The initial bytes of a global: value bits, a poison mask and an undef mask,
// plus the places where the address of another global is to be written.
struct Emitter::Image {
  std::vector<uint8_t> Bits, Poison, Undef;
  Array Relocations;
  unsigned Segment;

  // Mark bytes as holding defined values.
  void define(uint64_t Offset, uint64_t Count) {
    std::fill_n(Undef.begin() + Offset, Count, 0);
  }
};

void Emitter::writeConstant(const Constant *C, uint64_t Offset, Image &Out) {
  Type *Ty = C->getType();
  uint64_t Stored = DL.getTypeStoreSize(Ty).getFixedValue();
  if (isa<PoisonValue>(C)) {
    std::fill_n(Out.Poison.begin() + Offset, Stored, 0xff);
    return Out.define(Offset, Stored);
  }
  // Undef bytes, and the padding of aggregates, keep their undef mask.
  if (isa<UndefValue>(C))
    return;
  // A zero initializer defines every byte of the object, padding included.
  if (isa<ConstantAggregateZero>(C) || isa<ConstantPointerNull>(C))
    return Out.define(Offset, DL.getTypeAllocSize(Ty).getFixedValue());
  if (isa<ConstantInt>(C) || isa<ConstantFP>(C)) {
    // A float is stored as the bits of its encoding.
    auto *Float = dyn_cast<ConstantFP>(C);
    APInt Value = Float ? Float->getValueAPF().bitcastToAPInt() : cast<ConstantInt>(C)->getValue();
    APInt Wide = Value.zext(Stored * 8);
    for (uint64_t Index = 0; Index < Stored; ++Index)
      Out.Bits[Offset + Index] = Wide.extractBitsAsZExtValue(8, Index * 8);
    return Out.define(Offset, Stored);
  }
  if (auto *Sequence = dyn_cast<ConstantDataSequential>(C)) {
    uint64_t Stride = DL.getTypeAllocSize(Sequence->getElementType()).getFixedValue();
    for (uint64_t Index = 0; Index < Sequence->getNumElements(); ++Index)
      writeConstant(Sequence->getElementAsConstant(Index), Offset + Index * Stride, Out);
    return;
  }
  if (auto *Aggregate = dyn_cast<ConstantArray>(C)) {
    uint64_t Stride = DL.getTypeAllocSize(Aggregate->getType()->getElementType()).getFixedValue();
    for (unsigned Index = 0; Index < Aggregate->getNumOperands(); ++Index)
      writeConstant(Aggregate->getOperand(Index), Offset + Index * Stride, Out);
    return;
  }
  if (auto *Aggregate = dyn_cast<ConstantStruct>(C)) {
    const StructLayout *Layout = DL.getStructLayout(Aggregate->getType());
    for (unsigned Index = 0; Index < Aggregate->getNumOperands(); ++Index)
      writeConstant(Aggregate->getOperand(Index), Offset + Layout->getElementOffset(Index).getFixedValue(), Out);
    return;
  }
  // An integer written as a pointer: its bits, which designate no object.
  if (auto *Expression = dyn_cast<ConstantExpr>(C);
      Expression && Expression->getOpcode() == Instruction::IntToPtr && isa<ConstantInt>(Expression->getOperand(0))) {
    APInt Wide = cast<ConstantInt>(Expression->getOperand(0))->getValue().zextOrTrunc(Stored * 8);
    for (uint64_t Index = 0; Index < Stored; ++Index)
      Out.Bits[Offset + Index] = Wide.extractBitsAsZExtValue(8, Index * 8);
    return Out.define(Offset, Stored);
  }
  // The address of a function defined here, as a function pointer or as the
  // data pointer a virtual table holds it as.
  auto *F = dyn_cast<Function>(C);
  if (auto *Expression = dyn_cast<ConstantExpr>(C); Expression && Expression->getOpcode() == Instruction::AddrSpaceCast)
    F = dyn_cast<Function>(Expression->getOperand(0));
  if (F && FunctionIds.count(F)) {
    Out.Relocations.push_back(Object{{"segment", Out.Segment},
                                     {"offset", (int64_t)Offset},
                                     {"kind", "function_token"},
                                     {"target", FunctionIds.lookup(F)},
                                     {"addend", 0},
                                     {"integer_bits", 0}});
    return Out.define(Offset, Stored);
  }
  // The address of a global, as a pointer or converted to an integer.
  const Constant *Pointer = C;
  unsigned IntegerBits = 0;
  if (auto *Expression = dyn_cast<ConstantExpr>(C);
      Expression && Expression->getOpcode() == Instruction::PtrToInt && Ty->isIntegerTy()) {
    Pointer = Expression->getOperand(0);
    IntegerBits = Ty->getIntegerBitWidth();
  }
  int64_t Addend;
  if (const GlobalVariable *Target = globalAddress(Pointer, Addend); Target && IntegerBits <= 64) {
    Out.Relocations.push_back(Object{{"segment", Out.Segment},
                                     {"offset", (int64_t)Offset},
                                     {"kind", IntegerBits ? "data_integer" : "data_address"},
                                     {"target", DataSymbols.lookup(Target)},
                                     {"addend", Addend},
                                     {"integer_bits", IntegerBits}});
    return Out.define(Offset, Stored);
  }
  std::string Text;
  raw_string_ostream(Text) << *C;
  diagnose("E-UNSUPPORTED-INITIALIZER", Text);
}

void Emitter::lowerGlobals() {
  unsigned NextSymbol = FunctionIds.size();
  SmallVector<const GlobalVariable *, 16> Globals;
  for (const GlobalVariable &Global : M.globals()) {
    if (Global.isDeclaration())
      diagnose("E-UNSUPPORTED-GLOBAL", "global variable defined elsewhere: " + Global.getName());
    else if (Global.isThreadLocal())
      diagnose("E-UNSUPPORTED-GLOBAL", "thread-local variable " + Global.getName());
    else if (Global.getName() == "llvm.global_ctors")
      lowerStructors(Global, Initializers);
    else if (Global.getName() == "llvm.global_dtors")
      lowerStructors(Global, Finalizers);
    else if (Global.getAddressSpace() != 0 || Global.getName().starts_with("llvm.") || Global.hasSection())
      diagnose("E-UNSUPPORTED-GLOBAL", "special global " + Global.getName());
    else {
      DataSymbols[&Global] = NextSymbol++;
      Globals.push_back(&Global);
    }
  }
  auto Hex = [](const std::vector<uint8_t> &Bytes) {
    std::string Text;
    for (uint8_t Byte : Bytes) {
      Text += hexdigit(Byte >> 4, /*LowerCase=*/true);
      Text += hexdigit(Byte & 15, /*LowerCase=*/true);
    }
    return Text;
  };
  for (const GlobalVariable *Global : Globals) {
    uint64_t Size = DL.getTypeAllocSize(Global->getValueType()).getFixedValue();
    Image Out;
    Out.Segment = Segments.size();
    Out.Bits.assign(Size, 0);
    Out.Poison.assign(Size, 0);
    // Bytes no initializer element covers, such as padding, are undef.
    Out.Undef.assign(Size, 0xff);
    writeConstant(Global->getInitializer(), 0, Out);
    for (json::Value &Relocation : Out.Relocations)
      Relocations.push_back(std::move(Relocation));
    // A segment's storage is an array of raw bytes of its size.
    if (!RawByteType) {
      RawByteType = NextType++;
      Types.push_back(Object{{"kind", "raw"}, {"id", RawByteType}, {"bits", 8}});
    }
    unsigned Storage = NextType++;
    Types.push_back(Object{{"kind", "array"}, {"id", Storage}, {"element", ref(RawByteType)}, {"count", (int64_t)Size}});
    // An all-zero image is stored as a fill count instead of bytes.
    bool Zero = std::all_of(Out.Bits.begin(), Out.Bits.end(), [](uint8_t Byte) { return Byte == 0; }) &&
                std::all_of(Out.Poison.begin(), Out.Poison.end(), [](uint8_t Byte) { return Byte == 0; }) &&
                std::all_of(Out.Undef.begin(), Out.Undef.end(), [](uint8_t Byte) { return Byte == 0; });
    if (Zero)
      Out.Bits.clear(), Out.Poison.clear(), Out.Undef.clear();
    const char *Binding = Global->hasLocalLinkage() ? "local" : Global->isWeakForLinker() ? "weak" : "strong";
    const char *Visibility =
        Global->hasHiddenVisibility() ? "hidden" : Global->hasProtectedVisibility() ? "protected" : "default";
    Segments.push_back(Object{{"symbol", DataSymbols.lookup(Global)},
                              {"name", Global->getName()},
                              {"binding", Binding},
                              {"visibility", Visibility},
                              {"type", Storage},
                              {"size", (int64_t)Size},
                              {"alignment", (int64_t)DL.getValueOrABITypeAlignment(Global->getAlign(), Global->getValueType()).value()},
                              {"mutable", !Global->isConstant()},
                              {"initial", Hex(Out.Bits)},
                              {"poison", Hex(Out.Poison)},
                              {"undef", Hex(Out.Undef)},
                              {"zero_fill", (int64_t)(Zero ? Size : 0)}});
  }
}

// The byte size of a stack object with a constant element count.
bool Emitter::allocatedBytes(const AllocaInst &I, uint64_t &Bytes) {
  auto *Count = dyn_cast<ConstantInt>(I.getArraySize());
  TypeSize Element = DL.getTypeAllocSize(I.getAllocatedType());
  if (!Count || Element.isScalable() || Count->getValue().getActiveBits() > 32)
    return false;
  Bytes = Element.getFixedValue() * Count->getZExtValue();
  return true;
}

void Emitter::lowerAlloca(const AllocaInst &I, Array &Ops) {
  uint64_t Bytes;
  if (I.getAddressSpace() != 0 || I.isUsedWithInAlloca())
    return diagnose("E-UNSUPPORTED-INSTRUCTION", "alloca outside the data address space");
  unsigned Size;
  if (allocatedBytes(I, Bytes)) {
    Size = constantInt(Bytes);
  } else {
    // A variable-length object: the element count times the element size.
    // A product that wraps asks for a smaller object, and the accesses
    // beyond it are then out of bounds.
    TypeSize Element = DL.getTypeAllocSize(I.getAllocatedType());
    unsigned CountBits = I.getArraySize()->getType()->getIntegerBitWidth();
    if (Element.isScalable() || CountBits > 64)
      return diagnose("E-UNSUPPORTED-INSTRUCTION", "alloca of a scalable type or with a count wider than 64 bits");
    Type *Wide = IntegerType::get(M.getContext(), 64);
    unsigned Count = operand(I.getArraySize());
    if (CountBits < 64) {
      unsigned Widened = fresh();
      Ops.push_back(operation("zext", Widened, Wide, Array{Count}));
      Count = Widened;
    }
    Size = fresh();
    Object Product = operation("i_mul", Size, Wide, Array{Count, constantInt(Element.getFixedValue())});
    Product["flags"] = Array{};
    Ops.push_back(std::move(Product));
  }
  Object Op = operation("alloca", Values.lookup(&I), I.getType(), Array{Size});
  Op["helper"] = helper("stack_alloc", {intType(64), intType(64)}, {pointerType()});
  Op["binding"] = nullptr;
  Op["alignment"] = (int64_t)I.getAlign().value();
  Ops.push_back(std::move(Op));
}

void Emitter::lowerLifetime(const IntrinsicInst &I, Array &Ops, bool Start) {
  // The marker names a whole stack object; its extent is the object's size.
  auto *Alloca = dyn_cast<AllocaInst>(I.getArgOperand(0)->stripPointerCasts());
  uint64_t Bytes;
  if (!Alloca || !allocatedBytes(*Alloca, Bytes))
    return diagnose("E-UNSUPPORTED-INTRINSIC", "lifetime marker on something other than a fixed stack object");
  unsigned Size = constantInt(Bytes);
  const char *Name = Start ? "lifetime_start" : "lifetime_end";
  Ops.push_back(Object{{"op", Name},
                       {"results", Array{}},
                       {"operands", Array{operand(I.getArgOperand(0)), Size}},
                       {"helper", helper(Name, {pointerType(), intType(64)}, {})},
                       {"binding", nullptr},
                       {"alignment", 0}});
}

// Address arithmetic. Each index is one checked step, in index order: the
// format's promises (in bounds, no signed or unsigned wrap) are per step, and
// one final displacement could not prove the intermediate ones.
void Emitter::lowerAddress(const GetElementPtrInst &I, Array &Ops) {
  if (!I.getType()->isPointerTy() || I.getAddressSpace() != 0)
    return diagnose("E-UNSUPPORTED-INSTRUCTION", "getelementptr on vectors or outside the data address space");
  unsigned Result = Values.lookup(&I);
  bool Inbounds = I.isInBounds();
  bool NoUnsignedWrap = I.hasNoUnsignedWrap();
  bool NoSignedWrap = I.hasNoUnsignedSignedWrap();
  unsigned Base = operand(I.getPointerOperand());
  unsigned Current = Base;
  // Zero tests of the variable indices, for the all-zero rule below.
  SmallVector<unsigned, 4> ZeroTests;
  bool AnyStep = false;
  auto Step = [&](unsigned Delta) {
    unsigned Next = fresh();
    Object Op = operation("ptr_offset", Next, I.getType(), Array{Current, Delta});
    Op["inbounds"] = Inbounds;
    // A step taken for a nonzero index checks its base even when the byte
    // displacement happens to be zero.
    Op["check_base"] = Inbounds;
    Op["nuw"] = NoUnsignedWrap;
    Op["nusw"] = NoSignedWrap;
    Op["inrange"] = nullptr;
    Ops.push_back(std::move(Op));
    Current = Next;
    AnyStep = true;
  };
  for (gep_type_iterator Index = gep_type_begin(I), End = gep_type_end(I); Index != End; ++Index) {
    const Value *Operand = Index.getOperand();
    if (StructType *Struct = Index.getStructTypeOrNull()) {
      uint64_t Field = cast<ConstantInt>(Operand)->getZExtValue();
      uint64_t Offset = DL.getStructLayout(Struct)->getElementOffset(Field).getFixedValue();
      if (Offset)
        Step(constantInt(Offset));
      continue;
    }
    TypeSize Stride = Index.getSequentialElementStride(DL);
    if (Stride.isScalable() || !Operand->getType()->isIntegerTy() ||
        Operand->getType()->getIntegerBitWidth() > 64)
      return diagnose("E-UNSUPPORTED-INSTRUCTION", "getelementptr with a scalable stride or an index wider than 64 bits");
    if (auto *Constant = dyn_cast<ConstantInt>(Operand)) {
      // Constant indices fold; a zero one is no step at all.
      int64_t Offset = Constant->getSExtValue() * (int64_t)Stride.getFixedValue();
      if (!Constant->isZero())
        Step(constantInt((uint64_t)Offset));
      continue;
    }
    // A variable index is sign-extended to the pointer width and scaled. The
    // multiplication carries the same no-wrap promises as the step.
    unsigned Extended = operand(Operand);
    unsigned Bits = Operand->getType()->getIntegerBitWidth();
    Type *Wide = IntegerType::get(M.getContext(), 64);
    if (Bits < 64) {
      unsigned Widened = fresh();
      Ops.push_back(operation("sext", Widened, Wide, Array{Extended}));
      Extended = Widened;
    }
    unsigned IsZero = fresh();
    Ops.push_back(Object{{"op", "icmp"},
                         {"results", Array{Object{{"id", IsZero}, {"type", ref(intType(1))}}}},
                         {"operands", Array{Extended, constantInt(0)}},
                         {"predicate", "eq"}});
    ZeroTests.push_back(IsZero);
    unsigned Scaled = fresh();
    Object Multiply = operation("i_mul", Scaled, Wide, Array{Extended, constantInt(Stride.getFixedValue())});
    Array Flags;
    if (NoSignedWrap)
      Flags.push_back("nsw");
    if (NoUnsignedWrap)
      Flags.push_back("nuw");
    Multiply["flags"] = std::move(Flags);
    Ops.push_back(std::move(Multiply));
    Step(Scaled);
  }
  if (!AnyStep)
    return Ops.push_back(operation("copy", Result, I.getType(), Array{Base}));
  // With every index zero the result is the base pointer, whatever it is:
  // the in-bounds promise is then trivially kept. If all the steps came from
  // variable indices, that case is decided at run time.
  bool OnlyVariable = Inbounds && !ZeroTests.empty();
  for (gep_type_iterator Index = gep_type_begin(I), End = gep_type_end(I); OnlyVariable && Index != End; ++Index)
    if (auto *Constant = dyn_cast<ConstantInt>(Index.getOperand()); Constant && !Constant->isZero())
      OnlyVariable = false;
  if (!OnlyVariable)
    return Ops.push_back(operation("copy", Result, I.getType(), Array{Current}));
  unsigned AllZero = ZeroTests[0];
  for (unsigned Position = 1; Position < ZeroTests.size(); ++Position) {
    unsigned Both = fresh();
    Object Conjunction = operation("i_and", Both, IntegerType::get(M.getContext(), 1), Array{AllZero, ZeroTests[Position]});
    Conjunction["flags"] = Array{};
    Ops.push_back(std::move(Conjunction));
    AllZero = Both;
  }
  Ops.push_back(operation("select", Result, I.getType(), Array{AllZero, Base, Current}));
}

} // namespace smir
