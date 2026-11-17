// Lowering from an LLVM module to portable SMIR records.
//
// Scope: functions over integers, data pointers and function pointers, and
// global data. Integer arithmetic, comparisons, select, integer casts,
// freeze, phis, direct and indirect calls between functions of the module,
// a set of integer intrinsics, stack
// allocation, scalar loads and stores, bulk copies and fills, address
// arithmetic, pointer/integer conversions, lifetime markers, the return,
// branch, switch and unreachable terminators, and global variables whose
// initializers are integers, aggregates of them and addresses of other
// globals and of functions. Everything else is diagnosed and nothing is
// emitted.
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
#include <algorithm>
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
  std::map<unsigned, unsigned> CodePointerTypes;
  DenseMap<const Function *, unsigned> FunctionIds;
  DenseMap<const Function *, unsigned> SignatureIds;
  // Symbol identifier of each global variable; they follow the functions'.
  DenseMap<const GlobalVariable *, unsigned> DataSymbols;
  Array Segments, Relocations;
  unsigned RawByteType = 0;

  // State of the function being lowered.
  DenseMap<const Value *, unsigned> Values;
  DenseMap<const BasicBlock *, unsigned> Blocks;
  std::map<std::pair<unsigned, std::string>, unsigned> Constants;
  std::map<std::pair<const GlobalVariable *, int64_t>, unsigned> Addresses;
  DenseMap<const Function *, unsigned> CodeAddresses;
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

  // The type of pointers to data, which are in address space 0.
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
    // Address space 1 is the program address space: pointers to functions.
    if (Ty->isPointerTy() && Ty->getPointerAddressSpace() == 1)
      return genericCodePointer();
    std::string Name;
    raw_string_ostream(Name) << *Ty;
    diagnose("E-UNSUPPORTED-TYPE", What + ": " + Name);
    return 0;
  }

  // A function type over execution type identifiers, shared by structurally
  // equal signatures.
  //
  // No parameter or result is marked noundef. An indirect call must name
  // exactly its callee's signature, and the optimizer infers noundef on
  // definitions in ways no call site can see, so signatures leave it out.
  // That is a refinement: a poison argument or result flows on instead of
  // being undefined at the call boundary.
  unsigned functionType(ArrayRef<unsigned> Params, ArrayRef<unsigned> Results) {
    std::string Key;
    for (unsigned Type : Params)
      Key += (Twine(Type) + ",").str();
    Key += "->";
    for (unsigned Type : Results)
      Key += (Twine(Type) + ",").str();
    auto [Slot, Inserted] = FunctionTypes.try_emplace(Key, 0);
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
    return Slot->second;
  }

  // The execution function type of an LLVM function type.
  unsigned signatureType(const FunctionType *Ty) {
    SmallVector<unsigned, 8> Params, Results;
    for (Type *Param : Ty->params())
      Params.push_back(valueType(Param, "parameter"));
    if (!Ty->getReturnType()->isVoidTy())
      Results.push_back(valueType(Ty->getReturnType(), "result"));
    return functionType(Params, Results);
  }

  // The type of pointers to functions of one signature.
  unsigned codePointerType(unsigned Signature) {
    auto [Slot, Inserted] = CodePointerTypes.try_emplace(Signature, 0);
    if (Inserted) {
      Slot->second = NextType++;
      Types.push_back(Object{{"kind", "code_ptr"}, {"id", Slot->second}, {"signature", ref(Signature)}});
    }
    return Slot->second;
  }

  // LLVM function pointers are untyped, so every function pointer value has
  // this one type: a pointer to a function of no parameters and no results.
  // Taking a function's address and calling through a pointer convert from
  // and to the precise pointer type; the call then checks the signature.
  unsigned genericCodePointer() { return codePointerType(functionType({}, {})); }

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
    if (Inserted)
      Slot->second = functionType(Params, Results);
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

  // A constant data pointer as a global and a byte offset into it.
  const GlobalVariable *globalAddress(const Constant *C, int64_t &Offset) {
    if (!C->getType()->isPointerTy() || C->getType()->getPointerAddressSpace() != 0)
      return nullptr;
    APInt Accumulated(64, 0);
    auto *Global = dyn_cast<GlobalVariable>(
        C->stripAndAccumulateConstantOffsets(DL, Accumulated, /*AllowNonInbounds=*/true));
    Offset = Accumulated.getSExtValue();
    return Global && DataSymbols.count(Global) ? Global : nullptr;
  }

  // The address of a global, plus a constant offset, as a value. Like other
  // constants it is computed once per function at the start of the entry
  // block. The offset carries no in-bounds promise.
  unsigned address(const GlobalVariable *Global, int64_t Offset) {
    auto [Slot, Inserted] = Addresses.try_emplace({Global, Offset}, 0);
    if (!Inserted)
      return Slot->second;
    Type *Pointer = PointerType::get(M.getContext(), 0);
    if (Offset == 0) {
      Slot->second = fresh();
      Object Op = operation("address_of", Slot->second, Pointer, Array{});
      Op["symbol"] = ref(DataSymbols.lookup(Global));
      EntryConstants.push_back(std::move(Op));
      return Slot->second;
    }
    unsigned Base = address(Global, 0);
    unsigned Delta = constantInt((uint64_t)Offset);
    unsigned Result = fresh();
    Object Op = operation("ptr_offset", Result, Pointer, Array{Base, Delta});
    Op["inbounds"] = false;
    Op["check_base"] = false;
    Op["nuw"] = false;
    Op["nusw"] = false;
    Op["inrange"] = nullptr;
    EntryConstants.push_back(std::move(Op));
    // The recursive call may have rehashed the map.
    Addresses[{Global, Offset}] = Result;
    return Result;
  }

  // The address of a function, as a value of the generic function pointer
  // type. Computed once per function at the start of the entry block.
  unsigned codeAddress(const Function *F) {
    auto Defined = FunctionIds.find(F);
    if (Defined == FunctionIds.end()) {
      diagnose("E-UNSUPPORTED-OPERAND", "address of undefined function " + F->getName());
      return 0;
    }
    auto [Slot, Inserted] = CodeAddresses.try_emplace(F, 0);
    if (!Inserted)
      return Slot->second;
    unsigned Precise = fresh(), Generic = fresh();
    Slot->second = Generic;
    EntryConstants.push_back(Object{
        {"op", "address_of"},
        {"results", Array{Object{{"id", Precise}, {"type", ref(codePointerType(SignatureIds.lookup(F)))}}}},
        {"operands", Array{}},
        {"symbol", ref(Defined->second)}});
    EntryConstants.push_back(Object{
        {"op", "bitcast"},
        {"results", Array{Object{{"id", Generic}, {"type", ref(genericCodePointer())}}}},
        {"operands", Array{Precise}}});
    return Generic;
  }

  unsigned operand(const Value *V) {
    if (auto Found = Values.find(V); Found != Values.end())
      return Found->second;
    if (auto *C = dyn_cast<Constant>(V)) {
      int64_t Offset;
      if (const GlobalVariable *Global = globalAddress(C, Offset))
        return address(Global, Offset);
      if (auto *F = dyn_cast<Function>(C))
        return codeAddress(F);
      if (!isa<GlobalValue>(C) && !isa<ConstantExpr>(C))
        return constant(C);
    }
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
  void lowerBulk(const MemIntrinsic &I, Array &Ops);
  void lowerGlobals();
  struct Image;
  void writeConstant(const Constant *C, uint64_t Offset, Image &Out);
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
  case Intrinsic::memcpy:
  case Intrinsic::memcpy_inline:
  case Intrinsic::memmove:
  case Intrinsic::memset:
  case Intrinsic::memset_inline:
    return lowerBulk(cast<MemIntrinsic>(I), Ops);
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

// memcpy, memmove and memset. A copy moves bytes with their shadow, so
// pointers and poison survive it.
void Emitter::lowerBulk(const MemIntrinsic &I, Array &Ops) {
  if (I.isVolatile())
    return diagnose("E-UNSUPPORTED-INTRINSIC", "volatile bulk memory operation");
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
                       {"volatile", false}});
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
  if (auto *Int = dyn_cast<ConstantInt>(C)) {
    APInt Wide = Int->getValue().zext(Stored * 8);
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
  // The address of a function defined here.
  if (auto *F = dyn_cast<Function>(C); F && FunctionIds.count(F)) {
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
  if (I.hasOperandBundles())
    return diagnose("E-OPERAND-BUNDLE", "call with operand bundles");
  if (I.getFunctionType()->isVarArg())
    return diagnose("E-UNSUPPORTED-CALL", "call of a variadic function");
  const Function *Callee = I.getCalledFunction();
  Object Target;
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
    Type *Pointer = I.getCalledOperand()->getType();
    if (!Pointer->isPointerTy() || Pointer->getPointerAddressSpace() != 1)
      return diagnose("E-UNSUPPORTED-CALL", "call through a pointer outside the program address space");
    if (!portableConvention(I.getCallingConv()))
      return diagnose("E-UNSUPPORTED-CALL", "indirect call with a non-default calling convention");
    unsigned Signature = signatureType(I.getFunctionType());
    unsigned Typed = fresh();
    Ops.push_back(Object{{"op", "bitcast"},
                         {"results", Array{Object{{"id", Typed}, {"type", ref(codePointerType(Signature))}}}},
                         {"operands", Array{operand(I.getCalledOperand())}}});
    Target = Object{{"kind", "indirect"}, {"value", Typed}, {"signature", ref(Signature)}};
  }
  Array Operands, Results;
  for (const Use &Argument : I.args())
    Operands.push_back(operand(Argument));
  if (!I.getType()->isVoidTy())
    Results.push_back(decl(Values.lookup(&I), I.getType()));
  Ops.push_back(Object{{"op", "call"},
                       {"results", std::move(Results)},
                       {"operands", std::move(Operands)},
                       {"target", std::move(Target)},
                       {"unwind", "propagate"},
                       {"source_plan", nullptr}});
}

void Emitter::lowerInstruction(const Instruction &I, Array &Ops) {
  if (auto *Binary = dyn_cast<BinaryOperator>(&I))
    return lowerBinary(*Binary, Ops);
  if (auto *Compare = dyn_cast<ICmpInst>(&I)) {
    Type *Compared = Compare->getOperand(0)->getType();
    if (!Compared->isIntegerTy() && !Compared->isPointerTy())
      return diagnose("E-UNSUPPORTED-INSTRUCTION", "icmp on operands that are neither integers nor pointers");
    // Function pointers compare for equality only.
    if (Compared->isPointerTy() && Compared->getPointerAddressSpace() != 0 && !Compare->isEquality())
      return diagnose("E-UNSUPPORTED-INSTRUCTION", "ordered comparison of function pointers");
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
    Type *Pointer = isa<IntToPtrInst>(I) ? I.getType() : I.getOperand(0)->getType();
    if (Pointer->getPointerAddressSpace() != 0)
      return diagnose("E-UNSUPPORTED-INSTRUCTION", "conversion between a function pointer and an integer");
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
    // The format requires the cases in ascending unsigned order; LLVM keeps
    // them in whatever order they were written or transformed into.
    SmallVector<std::pair<APInt, unsigned>, 8> Sorted;
    for (const auto &Case : Switch->cases())
      Sorted.push_back({Case.getCaseValue()->getValue(), Blocks.lookup(Case.getCaseSuccessor())});
    llvm::sort(Sorted, [](const auto &Left, const auto &Right) { return Left.first.ult(Right.first); });
    Array Cases;
    for (const auto &[Value, Target] : Sorted)
      Cases.push_back(Object{{"value", littleEndianHex(Value)}, {"target", Target}});
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
  // These attributes make the call itself copy or allocate the argument's
  // object. A plain pointer argument would alias the caller's object instead.
  for (const Argument &Arg : F.args())
    if (Arg.hasByValAttr() || Arg.hasInAllocaAttr() || Arg.hasPreallocatedAttr())
      diagnose("E-UNSUPPORTED-FUNCTION", "aggregate parameter passed by value");
  return Diags.size() == Before;
}

Object Emitter::lowerFunction(const Function &F) {
  Values.clear();
  Blocks.clear();
  Constants.clear();
  Addresses.clear();
  CodeAddresses.clear();
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
    // A call to the trap intrinsic ends the block: what follows it never runs.
    bool Trapped = false;
    for (const Instruction &I : Block) {
      if (isa<PHINode>(I) || I.isTerminator())
        continue;
      if (auto *Call = dyn_cast<IntrinsicInst>(&I);
          Call && (Call->getIntrinsicID() == Intrinsic::trap || Call->getIntrinsicID() == Intrinsic::ubsantrap)) {
        Trapped = true;
        break;
      }
      lowerInstruction(I, Ops);
    }
    Object Term = Trapped ? Object{{"op", "trap"}, {"reason", "llvm_trap"}} : lowerTerminator(*Block.getTerminator());
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
    unsigned Signature = signatureType(F.getFunctionType());
    unsigned FunctionId = FunctionIds.size();
    SignatureIds[&F] = Signature;
    FunctionIds[&F] = FunctionId;
  }
  Current = nullptr;
  lowerGlobals();
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
    // Widths of integer parameters and results; "ptr" marks a pointer.
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
                    {"segments", std::move(Segments)},
                    {"relocations", std::move(Relocations)},
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
