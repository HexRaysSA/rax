// Lowering from an LLVM module to portable SMIR records.
//
// Scope: functions over integers and data pointers. Integer arithmetic,
// comparisons, select, integer casts, freeze, phis, direct calls between
// functions of the module, a set of integer intrinsics, stack allocation,
// scalar loads and stores, address arithmetic, pointer/integer conversions,
// lifetime markers, and the return, branch, switch and unreachable
// terminators. Everything else is diagnosed and nothing is emitted.
//
// Poison-generating flags that SMIR has no field for (`disjoint` on `or`,
// `samesign` on `icmp`, `nneg` on `zext`, `nuw`/`nsw` on `trunc`) and value
// range attributes are dropped. Dropping them is a refinement: the SMIR
// operation yields a defined value where LLVM would yield poison.
#include "emit.h"

#include "llvm/ADT/APInt.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include <map>

using namespace llvm;
using json::Array;
using json::Object;

namespace {

// Widest integer the interpreter evaluates.
constexpr unsigned MaxIntBits = 128;

Object ref(unsigned Id) { return Object{{"module", Object{{"kind", "self"}}}, {"id", Id}}; }

// The optimizer moves internal functions to the fast and cold conventions.
// They differ from the C convention only in how a native backend would pass
// arguments; a portable call is logical, so all three are the same call.
bool portableConvention(CallingConv::ID Convention) {
  return Convention == CallingConv::C || Convention == CallingConv::Fast || Convention == CallingConv::Cold;
}

// Little-endian hex of exactly the value's byte size.
std::string littleEndianHex(const APInt &Value) {
  unsigned Bytes = (Value.getBitWidth() + 7) / 8;
  APInt Wide = Value.zext(Bytes * 8);
  std::string Text;
  for (unsigned Index = 0; Index < Bytes; ++Index) {
    unsigned Byte = Wide.extractBitsAsZExtValue(8, Index * 8);
    Text += hexdigit(Byte >> 4, /*LowerCase=*/true);
    Text += hexdigit(Byte & 15, /*LowerCase=*/true);
  }
  return Text;
}

class Emitter {
public:
  Emitter(const Module &M, const smir::EmitOptions &Options, std::vector<smir::Diagnostic> &Diags)
      : M(M), DL(M.getDataLayout()), NextType(Options.TypeBase), NextLayout(Options.TypeBase), Diags(Diags) {}

  bool run(Object &Fragment);

private:
  const Module &M;
  const DataLayout &DL;
  unsigned NextType;
  unsigned NextLayout;
  std::vector<smir::Diagnostic> &Diags;
  const Function *Current = nullptr;

  Array Types;
  Array Layouts;
  std::map<unsigned, unsigned> IntTypes;
  unsigned PointerType = 0;
  // Memory layout identifier by execution type identifier.
  std::map<unsigned, unsigned> LayoutIds;
  // Runtime helpers used, with the function type each is called through.
  std::map<std::string, unsigned> Helpers;
  std::map<std::string, unsigned> FunctionTypes;
  DenseMap<const Function *, unsigned> FunctionIds;
  DenseMap<const Function *, unsigned> SignatureIds;

  // State of the function being lowered.
  DenseMap<const Value *, unsigned> Values;
  DenseMap<const BasicBlock *, unsigned> Blocks;
  std::map<std::pair<unsigned, std::string>, unsigned> Constants;
  Array EntryConstants;
  unsigned NextValue = 0;

  void diagnose(StringRef Code, const Twine &Detail) {
    Diags.push_back({Code.str(), Current ? Current->getName().str() : std::string(), Detail.str()});
  }

  // Identifier of the integer type of this width, or 0 after a diagnostic.
  unsigned intType(unsigned Bits) {
    auto [Slot, Inserted] = IntTypes.try_emplace(Bits, 0);
    if (Inserted) {
      Slot->second = NextType++;
      Types.push_back(Object{{"kind", "int"}, {"id", Slot->second}, {"bits", Bits}});
    }
    return Slot->second;
  }

  // The data pointer type. Pointers in other address spaces, which includes
  // every function pointer, are not lowered yet.
  unsigned pointerType() {
    if (!PointerType) {
      PointerType = NextType++;
      Types.push_back(Object{{"kind", "data_ptr"}, {"id", PointerType}, {"space", "guest_data"}});
    }
    return PointerType;
  }

  unsigned valueType(Type *Ty, const Twine &What) {
    if (auto *Int = dyn_cast<IntegerType>(Ty)) {
      if (Int->getBitWidth() <= MaxIntBits)
        return intType(Int->getBitWidth());
      diagnose("E-UNSUPPORTED-TYPE", What + ": integer wider than " + Twine(MaxIntBits) + " bits");
      return 0;
    }
    if (Ty->isPointerTy() && Ty->getPointerAddressSpace() == 0)
      return pointerType();
    std::string Name;
    raw_string_ostream(Name) << *Ty;
    diagnose("E-UNSUPPORTED-TYPE", What + ": " + Name);
    return 0;
  }

  // The execution function type of F, shared by structurally equal signatures.
  unsigned signatureType(const Function &F) {
    Array Params, Results, ParamNoundef, ResultNoundef;
    std::string Key;
    for (const Argument &Arg : F.args()) {
      unsigned Type = valueType(Arg.getType(), "parameter");
      bool Noundef = Arg.hasAttribute(Attribute::NoUndef);
      Params.push_back(ref(Type));
      ParamNoundef.push_back(Noundef);
      Key += (Twine(Type) + (Noundef ? "n," : ",")).str();
    }
    Key += "->";
    if (!F.getReturnType()->isVoidTy()) {
      unsigned Type = valueType(F.getReturnType(), "result");
      bool Noundef = F.hasRetAttribute(Attribute::NoUndef);
      Results.push_back(ref(Type));
      ResultNoundef.push_back(Noundef);
      Key += (Twine(Type) + (Noundef ? "n" : "")).str();
    }
    auto [Slot, Inserted] = FunctionTypes.try_emplace(Key, 0);
    if (Inserted) {
      Slot->second = NextType++;
      Types.push_back(Object{{"kind", "function"},
                             {"id", Slot->second},
                             {"params", std::move(Params)},
                             {"results", std::move(Results)},
                             {"variadic", false},
                             {"param_noundef", std::move(ParamNoundef)},
                             {"result_noundef", std::move(ResultNoundef)},
                             {"cc", "portable"}});
    }
    return Slot->second;
  }

  unsigned fresh() { return NextValue++; }

  // The memory layout of a scalar type: how many bytes an access touches and
  // how much room and alignment an object of the type takes.
  unsigned layout(Type *Ty) {
    unsigned TypeId = valueType(Ty, "memory access");
    auto [Slot, Inserted] = LayoutIds.try_emplace(TypeId, 0);
    if (Inserted) {
      Slot->second = NextLayout++;
      Layouts.push_back(Object{{"id", Slot->second},
                               {"type", ref(TypeId)},
                               {"size", (int64_t)DL.getTypeAllocSize(Ty).getFixedValue()},
                               {"alignment", (int64_t)DL.getABITypeAlign(Ty).value()},
                               {"access_bytes", (int64_t)DL.getTypeStoreSize(Ty).getFixedValue()},
                               {"fields", Array{}},
                               {"element", nullptr},
                               {"stride", 0}});
    }
    return Slot->second;
  }

  // The storage and mode fields of a plain scalar load or store.
  void access(Object &Op, Type *Ty, Align Alignment) {
    Op["storage"] = Object{{"type", ref(valueType(Ty, "memory access"))},
                           {"layout", ref(layout(Ty))},
                           {"nominal", nullptr},
                           {"abi_binding", nullptr},
                           {"bytes", (int64_t)DL.getTypeStoreSize(Ty).getFixedValue()}};
    Op["mode"] = Object{{"alignment", (int64_t)Alignment.value()},
                        {"volatile", false},
                        {"order", "none"},
                        {"failure_order", "none"},
                        {"scope", "process"},
                        {"elementwise", false}};
  }

  // The call target of an internal runtime helper, declaring it on first use.
  Object helper(StringRef Name, std::initializer_list<unsigned> Params, std::initializer_list<unsigned> Results) {
    auto [Slot, Inserted] = Helpers.try_emplace(Name.str(), 0);
    if (Inserted) {
      Array ParamRefs, ResultRefs, ParamNoundef, ResultNoundef;
      for (unsigned Type : Params) {
        ParamRefs.push_back(ref(Type));
        ParamNoundef.push_back(false);
      }
      for (unsigned Type : Results) {
        ResultRefs.push_back(ref(Type));
        ResultNoundef.push_back(false);
      }
      Slot->second = NextType++;
      Types.push_back(Object{{"kind", "function"},
                             {"id", Slot->second},
                             {"params", std::move(ParamRefs)},
                             {"results", std::move(ResultRefs)},
                             {"variadic", false},
                             {"param_noundef", std::move(ParamNoundef)},
                             {"result_noundef", std::move(ResultNoundef)},
                             {"cc", "portable"}});
    }
    // The import identifier is assigned when the fragment is merged; the
    // helper is named here.
    return Object{{"kind", "import"}, {"import", Name}, {"signature", ref(Slot->second)}};
  }

  unsigned constantInt(uint64_t Value, unsigned Bits = 64) {
    return constant(ConstantInt::get(IntegerType::get(M.getContext(), Bits), Value));
  }

  Object decl(unsigned Id, Type *Ty) { return Object{{"id", Id}, {"type", ref(valueType(Ty, "value"))}}; }

  // A constant is materialized once per function, in the entry block, which
  // dominates every use and has no phis.
  unsigned constant(const Constant *C) {
    Object Literal;
    std::string Key;
    if (isa<PoisonValue>(C)) {
      Literal = Object{{"kind", "poison"}};
      Key = "poison";
    } else if (isa<UndefValue>(C)) {
      Literal = Object{{"kind", "undef"}};
      Key = "undef";
    } else if (auto *Int = dyn_cast<ConstantInt>(C)) {
      Key = littleEndianHex(Int->getValue());
      Literal = Object{{"kind", "bits"}, {"value", Key}};
    } else if (isa<ConstantPointerNull>(C)) {
      Literal = Object{{"kind", "zero"}};
      Key = "null";
    } else {
      std::string Text;
      raw_string_ostream(Text) << *C;
      diagnose("E-UNSUPPORTED-CONSTANT", Text);
      return 0;
    }
    unsigned Type = valueType(C->getType(), "constant");
    auto [Slot, Inserted] = Constants.try_emplace({Type, Key}, 0);
    if (Inserted) {
      Slot->second = fresh();
      EntryConstants.push_back(Object{{"op", "constant"},
                                      {"results", Array{Object{{"id", Slot->second}, {"type", ref(Type)}}}},
                                      {"operands", Array{}},
                                      {"literal", std::move(Literal)}});
    }
    return Slot->second;
  }

  unsigned operand(const Value *V) {
    if (auto Found = Values.find(V); Found != Values.end())
      return Found->second;
    if (auto *C = dyn_cast<Constant>(V); C && !isa<GlobalValue>(C) && !isa<ConstantExpr>(C))
      return constant(C);
    std::string Text;
    raw_string_ostream(Text) << *V;
    diagnose("E-UNSUPPORTED-OPERAND", Text);
    return 0;
  }

  Object operation(StringRef Name, unsigned Result, Type *Ty, Array Operands) {
    return Object{{"op", Name}, {"results", Array{decl(Result, Ty)}}, {"operands", std::move(Operands)}};
  }

  void unsupported(const Instruction &I) {
    diagnose("E-UNSUPPORTED-INSTRUCTION", I.getOpcodeName());
  }

  void lowerBinary(const BinaryOperator &I, Array &Ops);
  void lowerAlloca(const AllocaInst &I, Array &Ops);
  void lowerAddress(const GetElementPtrInst &I, Array &Ops);
  void lowerLifetime(const IntrinsicInst &I, Array &Ops, bool Start);
  bool allocatedBytes(const AllocaInst &I, uint64_t &Bytes);
  void lowerIntrinsic(const IntrinsicInst &I, Array &Ops);
  void lowerCall(const CallInst &I, Array &Ops);
  void lowerInstruction(const Instruction &I, Array &Ops);
  Object lowerTerminator(const Instruction &I);
  Object lowerFunction(const Function &F);
  bool supportedSignature(const Function &F);
};

void Emitter::lowerBinary(const BinaryOperator &I, Array &Ops) {
  const char *Name = nullptr;
  switch (I.getOpcode()) {
  case Instruction::Add: Name = "i_add"; break;
  case Instruction::Sub: Name = "i_sub"; break;
  case Instruction::Mul: Name = "i_mul"; break;
  case Instruction::UDiv: Name = "i_udiv"; break;
  case Instruction::SDiv: Name = "i_sdiv"; break;
  case Instruction::URem: Name = "i_urem"; break;
  case Instruction::SRem: Name = "i_srem"; break;
  case Instruction::Shl: Name = "i_shl"; break;
  case Instruction::LShr: Name = "i_lshr"; break;
  case Instruction::AShr: Name = "i_ashr"; break;
  case Instruction::And: Name = "i_and"; break;
  case Instruction::Or: Name = "i_or"; break;
  case Instruction::Xor: Name = "i_xor"; break;
  default:
    return unsupported(I);
  }
  // The format requires flags in sorted order.
  Array Flags;
  if (auto *Exact = dyn_cast<PossiblyExactOperator>(&I); Exact && Exact->isExact())
    Flags.push_back("exact");
  if (auto *Wrap = dyn_cast<OverflowingBinaryOperator>(&I)) {
    if (Wrap->hasNoSignedWrap())
      Flags.push_back("nsw");
    if (Wrap->hasNoUnsignedWrap())
      Flags.push_back("nuw");
  }
  Object Op = operation(Name, Values.lookup(&I), I.getType(), Array{operand(I.getOperand(0)), operand(I.getOperand(1))});
  Op["flags"] = std::move(Flags);
  Ops.push_back(std::move(Op));
}

void Emitter::lowerIntrinsic(const IntrinsicInst &I, Array &Ops) {
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
  switch (I.getIntrinsicID()) {
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
  case Intrinsic::fshl:
  case Intrinsic::fshr: {
    // A funnel shift of a value with itself is a rotate.
    if (I.getArgOperand(0) != I.getArgOperand(1))
      break;
    Object Op = operation(I.getIntrinsicID() == Intrinsic::fshl ? "i_rotl" : "i_rotr", Result, I.getType(),
                          Array{operand(I.getArgOperand(0)), operand(I.getArgOperand(2))});
    Op["flags"] = Array{};
    Ops.push_back(std::move(Op));
    return;
  }
  case Intrinsic::lifetime_start: return lowerLifetime(I, Ops, true);
  case Intrinsic::lifetime_end: return lowerLifetime(I, Ops, false);
  // These have no effect on the values computed.
  case Intrinsic::assume:
  case Intrinsic::donothing:
  case Intrinsic::experimental_noalias_scope_decl:
    return;
  default:
    break;
  }
  diagnose("E-UNSUPPORTED-INTRINSIC", I.getCalledFunction()->getName());
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
  if (!allocatedBytes(I, Bytes))
    return diagnose("E-UNSUPPORTED-INSTRUCTION", "alloca with a variable element count");
  unsigned Size = constantInt(Bytes);
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

void Emitter::lowerCall(const CallInst &I, Array &Ops) {
  if (I.isInlineAsm())
    return diagnose("E-INLINE-ASSEMBLY", "inline assembly");
  const Function *Callee = I.getCalledFunction();
  if (!Callee)
    return diagnose("E-UNSUPPORTED-CALL", "indirect call");
  if (I.hasOperandBundles())
    return diagnose("E-OPERAND-BUNDLE", "call with operand bundles");
  auto Target = FunctionIds.find(Callee);
  if (Target == FunctionIds.end())
    return diagnose("E-UNSUPPORTED-CALL", "call to undefined function " + Callee->getName());
  if (I.getFunctionType() != Callee->getFunctionType())
    return diagnose("E-UNSUPPORTED-CALL", "call through a different function type to " + Callee->getName());
  // LLVM makes a call whose convention differs from its callee's undefined.
  if (I.getCallingConv() != Callee->getCallingConv())
    return diagnose("E-UNSUPPORTED-CALL", "calling convention mismatch calling " + Callee->getName());
  Array Operands, Results;
  for (const Use &Argument : I.args())
    Operands.push_back(operand(Argument));
  if (!I.getType()->isVoidTy())
    Results.push_back(decl(Values.lookup(&I), I.getType()));
  Ops.push_back(Object{{"op", "call"},
                       {"results", std::move(Results)},
                       {"operands", std::move(Operands)},
                       {"target", Object{{"kind", "direct"},
                                         {"function", ref(Target->second)},
                                         {"signature", ref(SignatureIds.lookup(Callee))}}},
                       {"unwind", "propagate"},
                       {"source_plan", nullptr}});
}

void Emitter::lowerInstruction(const Instruction &I, Array &Ops) {
  if (auto *Binary = dyn_cast<BinaryOperator>(&I))
    return lowerBinary(*Binary, Ops);
  if (auto *Compare = dyn_cast<ICmpInst>(&I)) {
    Type *Compared = Compare->getOperand(0)->getType();
    if (!Compared->isIntegerTy() && !(Compared->isPointerTy() && Compared->getPointerAddressSpace() == 0))
      return diagnose("E-UNSUPPORTED-INSTRUCTION", "icmp on operands that are neither integers nor data pointers");
    const char *Predicate = nullptr;
    switch (Compare->getPredicate()) {
    case CmpInst::ICMP_EQ: Predicate = "eq"; break;
    case CmpInst::ICMP_NE: Predicate = "ne"; break;
    case CmpInst::ICMP_ULT: Predicate = "ult"; break;
    case CmpInst::ICMP_ULE: Predicate = "ule"; break;
    case CmpInst::ICMP_UGT: Predicate = "ugt"; break;
    case CmpInst::ICMP_UGE: Predicate = "uge"; break;
    case CmpInst::ICMP_SLT: Predicate = "slt"; break;
    case CmpInst::ICMP_SLE: Predicate = "sle"; break;
    case CmpInst::ICMP_SGT: Predicate = "sgt"; break;
    case CmpInst::ICMP_SGE: Predicate = "sge"; break;
    default: return unsupported(I);
    }
    Object Op = operation("icmp", Values.lookup(&I), I.getType(),
                          Array{operand(I.getOperand(0)), operand(I.getOperand(1))});
    Op["predicate"] = Predicate;
    return Ops.push_back(std::move(Op));
  }
  if (auto *Select = dyn_cast<SelectInst>(&I)) {
    if (!Select->getCondition()->getType()->isIntegerTy(1))
      return diagnose("E-UNSUPPORTED-INSTRUCTION", "vector select");
    return Ops.push_back(operation("select", Values.lookup(&I), I.getType(),
                                   Array{operand(Select->getCondition()), operand(Select->getTrueValue()),
                                         operand(Select->getFalseValue())}));
  }
  if (isa<TruncInst>(I) || isa<ZExtInst>(I) || isa<SExtInst>(I)) {
    if (!I.getOperand(0)->getType()->isIntegerTy())
      return diagnose("E-UNSUPPORTED-INSTRUCTION", Twine(I.getOpcodeName()) + " on non-integer operand");
    return Ops.push_back(operation(I.getOpcodeName(), Values.lookup(&I), I.getType(), Array{operand(I.getOperand(0))}));
  }
  if (isa<FreezeInst>(I))
    return Ops.push_back(operation("freeze", Values.lookup(&I), I.getType(), Array{operand(I.getOperand(0))}));
  if (auto *Alloca = dyn_cast<AllocaInst>(&I))
    return lowerAlloca(*Alloca, Ops);
  if (auto *Address = dyn_cast<GetElementPtrInst>(&I))
    return lowerAddress(*Address, Ops);
  if (auto *Load = dyn_cast<LoadInst>(&I)) {
    if (Load->isVolatile() || Load->isAtomic())
      return diagnose("E-UNSUPPORTED-INSTRUCTION", "volatile or atomic load");
    Object Op = operation("load", Values.lookup(&I), I.getType(), Array{operand(Load->getPointerOperand())});
    access(Op, I.getType(), Load->getAlign());
    return Ops.push_back(std::move(Op));
  }
  if (auto *Store = dyn_cast<StoreInst>(&I)) {
    if (Store->isVolatile() || Store->isAtomic())
      return diagnose("E-UNSUPPORTED-INSTRUCTION", "volatile or atomic store");
    Object Op{{"op", "store"},
              {"results", Array{}},
              {"operands", Array{operand(Store->getPointerOperand()), operand(Store->getValueOperand())}}};
    access(Op, Store->getValueOperand()->getType(), Store->getAlign());
    return Ops.push_back(std::move(Op));
  }
  // ptrtoint exposes the pointer's object to later inttoptr; ptrtoaddr only
  // reads the address.
  if (isa<PtrToIntInst>(I) || isa<PtrToAddrInst>(I) || isa<IntToPtrInst>(I)) {
    const char *Name = isa<PtrToIntInst>(I) ? "ptrtoint" : isa<PtrToAddrInst>(I) ? "ptrtoaddr" : "inttoptr";
    return Ops.push_back(operation(Name, Values.lookup(&I), I.getType(), Array{operand(I.getOperand(0))}));
  }
  if (auto *Intrinsic = dyn_cast<IntrinsicInst>(&I))
    return lowerIntrinsic(*Intrinsic, Ops);
  if (auto *Call = dyn_cast<CallInst>(&I))
    return lowerCall(*Call, Ops);
  unsupported(I);
}

Object Emitter::lowerTerminator(const Instruction &I) {
  if (auto *Return = dyn_cast<ReturnInst>(&I)) {
    Array Returned;
    if (const Value *V = Return->getReturnValue())
      Returned.push_back(operand(V));
    return Object{{"op", "return"}, {"values", std::move(Returned)}};
  }
  // This LLVM revision has separate unconditional and conditional branch
  // instructions. A conditional branch's successor 0 is the true target.
  if (auto *Jump = dyn_cast<UncondBrInst>(&I))
    return Object{{"op", "jump"}, {"target", Blocks.lookup(Jump->getSuccessor())}};
  if (auto *Branch = dyn_cast<CondBrInst>(&I))
    return Object{{"op", "cbranch"},
                  {"condition", operand(Branch->getCondition())},
                  {"true", Blocks.lookup(Branch->getSuccessor(0))},
                  {"false", Blocks.lookup(Branch->getSuccessor(1))}};
  if (auto *Switch = dyn_cast<SwitchInst>(&I)) {
    Array Cases;
    for (const auto &Case : Switch->cases())
      Cases.push_back(Object{{"value", littleEndianHex(Case.getCaseValue()->getValue())},
                             {"target", Blocks.lookup(Case.getCaseSuccessor())}});
    return Object{{"op", "switch"},
                  {"index", operand(Switch->getCondition())},
                  {"cases", std::move(Cases)},
                  {"default", Blocks.lookup(Switch->getDefaultDest())}};
  }
  if (isa<UnreachableInst>(I))
    return Object{{"op", "unreachable"}};
  unsupported(I);
  return Object{{"op", "unreachable"}};
}

bool Emitter::supportedSignature(const Function &F) {
  size_t Before = Diags.size();
  if (F.isVarArg())
    diagnose("E-UNSUPPORTED-FUNCTION", "variadic function");
  if (!portableConvention(F.getCallingConv()))
    diagnose("E-UNSUPPORTED-FUNCTION", "calling convention " + Twine(F.getCallingConv()));
  if (F.hasPersonalityFn())
    diagnose("E-UNSUPPORTED-FUNCTION", "exception personality");
  return Diags.size() == Before;
}

Object Emitter::lowerFunction(const Function &F) {
  Values.clear();
  Blocks.clear();
  Constants.clear();
  EntryConstants = Array{};
  NextValue = 0;

  Array Params;
  for (const Argument &Arg : F.args()) {
    unsigned Id = fresh();
    Values[&Arg] = Id;
    Params.push_back(decl(Id, Arg.getType()));
  }
  // Only blocks reachable from the entry are emitted; the format requires
  // every block to be reachable. Identifiers follow the function's own order.
  df_iterator_default_set<const BasicBlock *> Reachable;
  for (const BasicBlock *Block : depth_first_ext(&F.getEntryBlock(), Reachable))
    (void)Block;
  for (const BasicBlock &Block : F) {
    if (!Reachable.count(&Block))
      continue;
    unsigned BlockId = Blocks.size();
    Blocks[&Block] = BlockId;
    for (const Instruction &I : Block)
      if (!I.getType()->isVoidTy()) {
        unsigned Id = fresh();
        Values[&I] = Id;
      }
  }

  Array Lowered;
  for (const BasicBlock &Block : F) {
    if (!Reachable.count(&Block))
      continue;
    Array Phis, Ops;
    for (const PHINode &Phi : Block.phis()) {
      // A predecessor that reaches this block along several edges appears
      // once per edge with the same value; the format wants it once.
      Array Incoming;
      DenseSet<const BasicBlock *> Seen;
      for (unsigned Index = 0; Index < Phi.getNumIncomingValues(); ++Index) {
        const BasicBlock *Predecessor = Phi.getIncomingBlock(Index);
        if (!Reachable.count(Predecessor) || !Seen.insert(Predecessor).second)
          continue;
        Incoming.push_back(Object{{"predecessor", Blocks.lookup(Predecessor)},
                                  {"value", operand(Phi.getIncomingValue(Index))}});
      }
      Phis.push_back(Object{{"result", decl(Values.lookup(&Phi), Phi.getType())}, {"incoming", std::move(Incoming)}});
    }
    for (const Instruction &I : Block) {
      if (isa<PHINode>(I) || I.isTerminator())
        continue;
      lowerInstruction(I, Ops);
    }
    Object Term = lowerTerminator(*Block.getTerminator());
    Lowered.push_back(Object{{"id", Blocks.lookup(&Block)},
                             {"phis", std::move(Phis)},
                             {"ops", std::move(Ops)},
                             {"term", std::move(Term)}});
  }
  // Constants were collected while lowering; they open the entry block.
  if (Object *Entry = Lowered[0].getAsObject()) {
    Array Ops = std::move(EntryConstants);
    for (json::Value &Op : *Entry->getArray("ops"))
      Ops.push_back(std::move(Op));
    (*Entry)["ops"] = std::move(Ops);
  }
  return Object{{"id", FunctionIds.lookup(&F)},
                {"signature", ref(SignatureIds.lookup(&F))},
                {"abi_signature", nullptr},
                {"params", std::move(Params)},
                {"entry", 0},
                {"escape", "propagate"},
                {"no_return", F.doesNotReturn()},
                {"blocks", std::move(Lowered)}};
}

bool Emitter::run(Object &Fragment) {
  if (!M.getModuleInlineAsm().empty())
    diagnose("E-INLINE-ASSEMBLY", "module-level assembly");
  for (const GlobalVariable &Global : M.globals())
    diagnose("E-UNSUPPORTED-GLOBAL", "global variable " + Global.getName());
  for (const GlobalAlias &Alias : M.aliases())
    diagnose("E-UNSUPPORTED-GLOBAL", "alias " + Alias.getName());
  for (const GlobalIFunc &IFunc : M.ifuncs())
    diagnose("E-UNSUPPORTED-GLOBAL", "ifunc " + IFunc.getName());

  // Identify every defined function first so that calls can refer forward.
  for (const Function &F : M) {
    if (F.isDeclaration())
      continue;
    Current = &F;
    if (!supportedSignature(F))
      continue;
    unsigned Signature = signatureType(F);
    unsigned FunctionId = FunctionIds.size();
    SignatureIds[&F] = Signature;
    FunctionIds[&F] = FunctionId;
  }
  Array Functions, Symbols, Index;
  for (const Function &F : M) {
    Current = &F;
    if (F.isDeclaration() || !FunctionIds.count(&F))
      continue;
    Functions.push_back(lowerFunction(F));
    const char *Binding = F.hasLocalLinkage() ? "local" : F.isWeakForLinker() ? "weak" : "strong";
    const char *Visibility = F.hasHiddenVisibility() ? "hidden" : F.hasProtectedVisibility() ? "protected" : "default";
    Symbols.push_back(Object{{"function", FunctionIds.lookup(&F)},
                             {"name", F.getName()},
                             {"binding", Binding},
                             {"visibility", Visibility},
                             {"signature", SignatureIds.lookup(&F)}});
    Array ParamBits, ResultBits;
    // Widths of integer parameters and results; "ptr" marks a data pointer.
    auto Shape = [](Type *Ty) -> json::Value {
      return Ty->isIntegerTy() ? json::Value((int64_t)Ty->getIntegerBitWidth()) : json::Value("ptr");
    };
    for (const Argument &Arg : F.args())
      ParamBits.push_back(Shape(Arg.getType()));
    if (!F.getReturnType()->isVoidTy())
      ResultBits.push_back(Shape(F.getReturnType()));
    Index.push_back(Object{{"name", F.getName()},
                           {"function", FunctionIds.lookup(&F)},
                           {"params", std::move(ParamBits)},
                           {"results", std::move(ResultBits)},
                           {"local", F.hasLocalLinkage()}});
  }
  Current = nullptr;
  if (!Diags.empty())
    return false;
  Array HelperList;
  for (const auto &[Name, Signature] : Helpers)
    HelperList.push_back(Object{{"name", Name}, {"signature", Signature}});
  Fragment = Object{{"types", std::move(Types)},
                    {"layouts", std::move(Layouts)},
                    {"helpers", std::move(HelperList)},
                    {"functions", std::move(Functions)},
                    {"symbols", std::move(Symbols)},
                    {"index", std::move(Index)}};
  return true;
}

} // namespace

bool smir::emit(const Module &M, const EmitOptions &Options, Object &Fragment,
                std::vector<Diagnostic> &Diagnostics) {
  return Emitter(M, Options, Diagnostics).run(Fragment);
}
