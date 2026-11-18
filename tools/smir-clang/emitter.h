// The emitter's lowering state, shared by the files that implement it. This
// header is internal to smir-clang; emit.h is the interface.
#ifndef RAX_SMIR_CLANG_EMITTER_H
#define RAX_SMIR_CLANG_EMITTER_H

#include "emit.h"

#include "llvm/ADT/APInt.h"
#include "llvm/ADT/FloatingPointMode.h"
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
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include <algorithm>
#include <map>
#include <optional>

namespace smir {

using namespace llvm;
using json::Array;
using json::Object;


// Widest integer the interpreter evaluates.
constexpr unsigned MaxIntBits = 128;

// What the link name of a function of the host starts with.
constexpr StringLiteral HostPrefix = "host:";

inline Object ref(unsigned Id) { return Object{{"module", Object{{"kind", "self"}}}, {"id", Id}}; }

// The optimizer moves internal functions to the fast and cold conventions.
// They differ from the C convention only in how a native backend would pass
// arguments; a portable call is logical, so all three are the same call.
inline bool portableConvention(CallingConv::ID Convention) {
  return Convention == CallingConv::C || Convention == CallingConv::Fast || Convention == CallingConv::Cold;
}

// Little-endian hex of exactly the value's byte size.
inline std::string littleEndianHex(const APInt &Value) {
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
      : M(M), DL(M.getDataLayout()), Options(Options), ServicePrefix(Options.ServiceNamespace + ":"),
        NextType(Options.TypeBase), NextLayout(Options.TypeBase), Diags(Diags) {}

  bool run(Object &Fragment);

private:
  const Module &M;
  const DataLayout &DL;
  const smir::EmitOptions &Options;
  // What the link name of a function bound to a runtime service starts with.
  const std::string ServicePrefix;
  unsigned NextType;
  unsigned NextLayout;
  std::vector<smir::Diagnostic> &Diags;
  const Function *Current = nullptr;

  Array Types;
  Array Layouts;
  std::map<unsigned, unsigned> IntTypes;
  std::map<std::string, unsigned> FloatTypes;
  unsigned PointerType = 0;
  // Memory layout identifier by execution type identifier.
  std::map<unsigned, unsigned> LayoutIds;
  // Runtime helpers used, with the function type each is called through.
  std::map<std::string, unsigned> Helpers;
  // Likewise the runtime services, and the service each declaration with a
  // service's link name is bound to (null when the binding was refused).
  std::map<std::string, unsigned> Services;
  DenseMap<const Function *, const smir::Service *> Bindings;
  // The functions of the host that are called, by link name, with the
  // function type each is called through.
  std::map<std::string, unsigned> Hosts;
  std::map<std::string, unsigned> FunctionTypes;
  std::map<unsigned, unsigned> CodePointerTypes;
  DenseMap<const Function *, unsigned> FunctionIds;
  DenseMap<const Function *, unsigned> SignatureIds;
  // The functions of other modules that are called: for each dependency, by
  // its slot, their names in the order they were first called, each with
  // the signature it is called through; and the slot and the place in that
  // order of each declaration that is one.
  std::vector<std::vector<std::pair<std::string, unsigned>>> Outside;
  DenseMap<const Function *, std::pair<unsigned, unsigned>> OutsideIds;
  // Symbol identifier of each global variable; they follow the functions'.
  DenseMap<const GlobalVariable *, unsigned> DataSymbols;
  // Thread-local variables: the position of each one's segment among the
  // thread-local segments, and its symbol.
  DenseMap<const GlobalVariable *, std::pair<unsigned, unsigned>> ThreadLocals;
  Array ThreadLocalSegments;
  // The signature of the helper that yields a thread-local address, once a
  // function has used it.
  std::optional<unsigned> ThreadLocalSignature;
  Array Segments, Relocations;
  unsigned RawByteType = 0;

  // State of the function being lowered.
  DenseMap<const Value *, unsigned> Values;
  DenseMap<const BasicBlock *, unsigned> Blocks;
  std::map<std::pair<unsigned, std::string>, unsigned> Constants;
  std::map<std::pair<const GlobalVariable *, int64_t>, unsigned> Addresses;
  DenseMap<const Function *, unsigned> CodeAddresses;
  DenseMap<const ConstantExpr *, unsigned> Conversions;
  // The two results of each instruction that yields a pair: the result and
  // the overflow flag of overflow-checked arithmetic, the old value and the
  // success flag of a compare-and-exchange; and of each phi that merges
  // such pairs. An extractvalue of one is that value, not an operation.
  DenseMap<const Value *, std::pair<unsigned, unsigned>> Pairs;
  // In a variadic function, the parameter that holds the address of the
  // variadic arguments.
  std::optional<unsigned> VariadicArguments;
  // Values of data pointer type that hold function pointers; see
  // emit_code.cpp.
  DenseSet<const Value *> CodeValues;
  // Functions to run before and after the program, from llvm.global_ctors
  // and llvm.global_dtors.
  Array Initializers, Finalizers;
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

  // A float type by the name of its format.
  unsigned floatType(StringRef Format) {
    auto [Slot, Inserted] = FloatTypes.try_emplace(Format.str(), 0);
    if (Inserted) {
      Slot->second = NextType++;
      Types.push_back(Object{{"kind", "float"}, {"id", Slot->second}, {"format", Format}});
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
    if (Ty->isFloatTy())
      return floatType("binary32");
    if (Ty->isDoubleTy())
      return floatType("binary64");
    // long double. The engine carries its values; their arithmetic is the
    // engine's to refuse.
    if (Ty->isFP128Ty())
      return floatType("binary128");
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

  // The execution function type of an LLVM function type. A variadic
  // function takes one more parameter, the address of its variadic
  // arguments.
  unsigned signatureType(const FunctionType *Ty) {
    SmallVector<unsigned, 8> Params, Results;
    for (Type *Param : Ty->params())
      Params.push_back(valueType(Param, "parameter"));
    if (Ty->isVarArg())
      Params.push_back(pointerType());
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
    // An access through the null pointer is as aligned as LLVM can say, two
    // to the power of 32, which is more than the format can: the format's
    // alignment is 32 bits. Less is asked of the pointer here, never more.
    Op["mode"] = Object{{"alignment", (int64_t)std::min<uint64_t>(Alignment.value(), uint64_t(1) << 30)},
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
    } else if (auto *Float = dyn_cast<ConstantFP>(C)) {
      // A float literal is the bits of its encoding.
      Key = littleEndianHex(Float->getValueAPF().bitcastToAPInt());
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
      // An integer written as a data pointer. The format has no pointer
      // literal but null, so it is converted where the function begins.
      if (auto *Expression = dyn_cast<ConstantExpr>(C);
          Expression && Expression->getOpcode() == Instruction::IntToPtr &&
          isa<ConstantInt>(Expression->getOperand(0)) && C->getType()->getPointerAddressSpace() == 0) {
        auto [Slot, Inserted] = Conversions.try_emplace(Expression, 0);
        if (Inserted) {
          unsigned Address = constant(ConstantInt::get(
              IntegerType::get(M.getContext(), 64),
              cast<ConstantInt>(Expression->getOperand(0))->getValue().zextOrTrunc(64)));
          Slot->second = fresh();
          EntryConstants.push_back(operation("inttoptr", Slot->second, C->getType(), Array{Address}));
        }
        return Slot->second;
      }
      // A function's address written as a data pointer.
      if (const Function *F = functionAsData(C)) {
        auto [Slot, Inserted] = Conversions.try_emplace(cast<ConstantExpr>(C), 0);
        if (Inserted) {
          unsigned Code = codeAddress(F);
          unsigned Data = dataFromCode(Code, EntryConstants);
          // The calls above may have rehashed the map.
          Conversions[cast<ConstantExpr>(C)] = Data;
          return Data;
        }
        return Slot->second;
      }
      // The address of a global converted to an integer.
      if (auto *Expression = dyn_cast<ConstantExpr>(C);
          Expression && (Expression->getOpcode() == Instruction::PtrToInt ||
                         Expression->getOpcode() == Instruction::PtrToAddr)) {
        // A function's address as an integer.
        if (auto *F = dyn_cast<Function>(Expression->getOperand(0))) {
          auto [Slot, Inserted] = Conversions.try_emplace(Expression, 0);
          if (!Inserted)
            return Slot->second;
          unsigned Code = codeAddress(F), Bits = fresh();
          EntryConstants.push_back(
              operation(Expression->getOpcode() == Instruction::PtrToInt ? "ptrtoint" : "ptrtoaddr", Bits,
                        Expression->getType(), Array{Code}));
          // The call above may have rehashed the map.
          Conversions[Expression] = Bits;
          return Bits;
        }
        if (const GlobalVariable *Global = globalAddress(Expression->getOperand(0), Offset)) {
          auto [Slot, Inserted] = Conversions.try_emplace(Expression, 0);
          if (Inserted) {
            unsigned Pointer = address(Global, Offset);
            Slot->second = fresh();
            EntryConstants.push_back(operation(Expression->getOpcode() == Instruction::PtrToInt ? "ptrtoint" : "ptrtoaddr",
                                               Slot->second, Expression->getType(), Array{Pointer}));
          }
          return Slot->second;
        }
      }
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
  Object floatOperation(StringRef Name, unsigned Result, Type *Ty, Array Operands);
  bool lowerFloat(const Instruction &I, Array &Ops);
  bool lowerFloatIntrinsic(const IntrinsicInst &I, Array &Ops);
  void lowerClassTest(const IntrinsicInst &I, Array &Ops);
  unsigned stackObject(uint64_t Bytes, uint64_t Alignment);
  unsigned offsetPointer(unsigned Base, uint64_t Bytes, Array &Ops);
  void copyByValue(const Argument &Arg);
  unsigned variadicSlots(Type *Ty);
  unsigned variadicArea(const CallBase &I, Array &Ops);
  bool lowerVariadicIntrinsic(const IntrinsicInst &I, Array &Ops);
  void lowerVariadicArgument(const VAArgInst &I, Array &Ops);
  bool lowerOverflow(const IntrinsicInst &I, Array &Ops);
  void findCodeValues(const Function &F);
  Type *carriedType(const Value *V);
  unsigned dataFromCode(unsigned Code, Array &Ops);
  unsigned codeFromData(unsigned Data, Array &Ops);
  static const Function *functionAsData(const Constant *C);
  static bool isPairPhi(const Instruction &I);
  std::pair<unsigned, unsigned> pairOperands(const Value *V);
  unsigned codeOperand(const Value *V);
  unsigned operandLike(const Value *V, const Value *Peer);
  void lowerStructors(const GlobalVariable &List, Array &Out);
  void ordered(Object &Op, bool Volatile, AtomicOrdering Order, AtomicOrdering Failure);
  bool lowerAtomic(const Instruction &I, Array &Ops);
  Type *serviceType(StringRef Name);
  const smir::Service *boundService(const Function &F);
  void lowerServiceCall(const CallInst &I, const smir::Service &Service, Array &Ops);
  std::optional<std::pair<unsigned, unsigned>> outside(const Function &F);
  void lowerHostCall(const CallInst &I, const Function &F, Array &Ops);
  void lowerInstruction(const Instruction &I, Array &Ops);
  Object lowerTerminator(const Instruction &I);
  Object lowerFunction(const Function &F);
  bool supportedSignature(const Function &F);
};

} // namespace smir

#endif
