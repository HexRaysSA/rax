// Lowering from an LLVM module to portable SMIR records.
//
// Scope: functions over integers, binary32 and binary64 floats, data pointers
// and function pointers, and global data. Integer and floating-point
// arithmetic, comparisons, select, casts,
// freeze, phis, direct and indirect calls between functions of the module,
// calls of runtime services, a set of integer intrinsics, stack
// allocation, scalar loads and stores, bulk copies and fills, address
// arithmetic, pointer/integer conversions, lifetime markers, the return,
// branch, switch and unreachable terminators, and global variables whose
// initializers are integers, floats, aggregates of them and addresses of
// other globals and of functions. Everything else is diagnosed and nothing is
// emitted.
//
// Poison-generating flags that SMIR has no field for (`disjoint` on `or`,
// `samesign` on `icmp`, `nneg` on `zext`, `nuw`/`nsw` on `trunc`) and value
// range attributes are dropped. Dropping them is a refinement: the SMIR
// operation yields a defined value where LLVM would yield poison.
#include "emitter.h"

namespace smir {

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

void Emitter::lowerInstruction(const Instruction &I, Array &Ops) {
  if (lowerFloat(I, Ops))
    return;
  if (auto *Extract = dyn_cast<ExtractValueInst>(&I)) {
    // One of the two results of an overflow-checked operation is already a
    // value; nothing is computed here.
    if (Pairs.count(Extract->getAggregateOperand()) && Extract->getNumIndices() == 1)
      return;
    return diagnose("E-UNSUPPORTED-INSTRUCTION", "extractvalue of an aggregate value");
  }
  if (auto *Argument = dyn_cast<VAArgInst>(&I))
    return lowerVariadicArgument(*Argument, Ops);
  if (auto *Binary = dyn_cast<BinaryOperator>(&I))
    return lowerBinary(*Binary, Ops);
  if (auto *Compare = dyn_cast<ICmpInst>(&I)) {
    // A function pointer held as a data pointer compares as a function
    // pointer, and so does the constant it is compared with.
    const Value *Left = Compare->getOperand(0), *Right = Compare->getOperand(1);
    bool Code = CodeValues.count(Left) || CodeValues.count(Right);
    Type *Compared = Code ? PointerType::get(M.getContext(), 1) : Left->getType();
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
                          Code ? Array{codeOperand(Left), codeOperand(Right)} : Array{operand(Left), operand(Right)});
    Op["predicate"] = Predicate;
    return Ops.push_back(std::move(Op));
  }
  if (auto *Select = dyn_cast<SelectInst>(&I)) {
    if (!Select->getCondition()->getType()->isIntegerTy(1))
      return diagnose("E-UNSUPPORTED-INSTRUCTION", "vector select");
    return Ops.push_back(operation("select", Values.lookup(&I), carriedType(&I),
                                   Array{operand(Select->getCondition()), operandLike(Select->getTrueValue(), &I),
                                         operandLike(Select->getFalseValue(), &I)}));
  }
  if (isa<TruncInst>(I) || isa<ZExtInst>(I) || isa<SExtInst>(I)) {
    if (!I.getOperand(0)->getType()->isIntegerTy())
      return diagnose("E-UNSUPPORTED-INSTRUCTION", Twine(I.getOpcodeName()) + " on non-integer operand");
    return Ops.push_back(operation(I.getOpcodeName(), Values.lookup(&I), I.getType(), Array{operand(I.getOperand(0))}));
  }
  if (isa<FreezeInst>(I))
    return Ops.push_back(
        operation("freeze", Values.lookup(&I), carriedType(&I), Array{operandLike(I.getOperand(0), &I)}));
  if (isa<AddrSpaceCastInst>(I)) {
    // Between a function pointer and the data pointer that stands for it,
    // there is nothing to convert.
    if (!CodeValues.count(&I) && !CodeValues.count(I.getOperand(0)))
      return diagnose("E-UNSUPPORTED-INSTRUCTION", "address space cast of a data pointer");
    return Ops.push_back(operation("copy", Values.lookup(&I), PointerType::get(M.getContext(), 1),
                                   Array{codeOperand(I.getOperand(0))}));
  }
  if (auto *Alloca = dyn_cast<AllocaInst>(&I))
    return lowerAlloca(*Alloca, Ops);
  if (auto *Address = dyn_cast<GetElementPtrInst>(&I))
    return lowerAddress(*Address, Ops);
  if (auto *Load = dyn_cast<LoadInst>(&I)) {
    if (Load->isVolatile() || Load->isAtomic())
      return diagnose("E-UNSUPPORTED-INSTRUCTION", "volatile or atomic load");
    Object Op = operation("load", Values.lookup(&I), carriedType(&I), Array{operand(Load->getPointerOperand())});
    access(Op, carriedType(&I), Load->getAlign());
    return Ops.push_back(std::move(Op));
  }
  if (auto *Store = dyn_cast<StoreInst>(&I)) {
    if (Store->isVolatile() || Store->isAtomic())
      return diagnose("E-UNSUPPORTED-INSTRUCTION", "volatile or atomic store");
    Object Op{{"op", "store"},
              {"results", Array{}},
              {"operands", Array{operand(Store->getPointerOperand()),
                                 operandLike(Store->getValueOperand(), Store->getValueOperand())}}};
    access(Op, carriedType(Store->getValueOperand()), Store->getAlign());
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
  if (!portableConvention(F.getCallingConv()))
    diagnose("E-UNSUPPORTED-FUNCTION", "calling convention " + Twine(F.getCallingConv()));
  if (F.hasPersonalityFn())
    diagnose("E-UNSUPPORTED-FUNCTION", "exception personality");
  // These attributes make the call itself allocate the argument's object.
  for (const Argument &Arg : F.args())
    if (Arg.hasInAllocaAttr() || Arg.hasPreallocatedAttr())
      diagnose("E-UNSUPPORTED-FUNCTION", "parameter allocated by the call");
  return Diags.size() == Before;
}

Object Emitter::lowerFunction(const Function &F) {
  Values.clear();
  Blocks.clear();
  Constants.clear();
  Addresses.clear();
  CodeAddresses.clear();
  Conversions.clear();
  Pairs.clear();
  VariadicArguments.reset();
  findCodeValues(F);
  EntryConstants = Array{};
  NextValue = 0;

  Array Params;
  for (const Argument &Arg : F.args()) {
    unsigned Id = fresh();
    Values[&Arg] = Id;
    Params.push_back(decl(Id, Arg.getType()));
  }
  if (F.isVarArg()) {
    VariadicArguments = fresh();
    Params.push_back(Object{{"id", *VariadicArguments}, {"type", ref(pointerType())}});
  }
  for (const Argument &Arg : F.args())
    if (Arg.hasByValAttr())
      copyByValue(Arg);
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
      if (auto *Call = dyn_cast<WithOverflowInst>(&I)) {
        unsigned Result = fresh(), Overflowed = fresh();
        Pairs[Call] = {Result, Overflowed};
      } else if (!I.getType()->isVoidTy() && !isa<ExtractValueInst>(I)) {
        unsigned Id = fresh();
        Values[&I] = Id;
      }
  }
  // An extractvalue of an overflow-checked operation names one of its two
  // results. Any other is given a value, and refused when it is lowered.
  for (const BasicBlock &Block : F)
    for (const Instruction &I : Block)
      if (auto *Extract = dyn_cast<ExtractValueInst>(&I); Extract && Reachable.count(&Block)) {
        auto Pair = Pairs.find(Extract->getAggregateOperand());
        if (Pair != Pairs.end() && Extract->getNumIndices() == 1)
          Values[&I] = Extract->getIndices()[0] == 0 ? Pair->second.first : Pair->second.second;
        else
          Values[&I] = fresh();
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
                                  {"value", operandLike(Phi.getIncomingValue(Index), &Phi)}});
      }
      Phis.push_back(Object{{"result", decl(Values.lookup(&Phi), carriedType(&Phi))}, {"incoming", std::move(Incoming)}});
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
    // Widths of integer parameters and results; "f32" and "f64" mark floats
    // and "ptr" a pointer.
    auto Shape = [](Type *Ty) -> json::Value {
      if (Ty->isIntegerTy())
        return (int64_t)Ty->getIntegerBitWidth();
      return Ty->isFloatTy() ? "f32" : Ty->isDoubleTy() ? "f64" : Ty->isFP128Ty() ? "f128" : "ptr";
    };
    for (const Argument &Arg : F.args())
      ParamBits.push_back(Shape(Arg.getType()));
    // The address of the variadic arguments.
    if (F.isVarArg())
      ParamBits.push_back("ptr");
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
  Array HelperList, ServiceList;
  for (const auto &[Name, Signature] : Helpers)
    HelperList.push_back(Object{{"name", Name}, {"signature", Signature}});
  for (const auto &[Name, Signature] : Services)
    ServiceList.push_back(Object{{"name", Name}, {"signature", Signature}});
  Fragment = Object{{"types", std::move(Types)},
                    {"layouts", std::move(Layouts)},
                    {"helpers", std::move(HelperList)},
                    {"services", std::move(ServiceList)},
                    {"segments", std::move(Segments)},
                    {"relocations", std::move(Relocations)},
                    {"initializers", std::move(Initializers)},
                    {"finalizers", std::move(Finalizers)},
                    {"functions", std::move(Functions)},
                    {"symbols", std::move(Symbols)},
                    {"index", std::move(Index)}};
  return true;
}
bool emit(const Module &M, const EmitOptions &Options, Object &Fragment, std::vector<Diagnostic> &Diagnostics) {
  return Emitter(M, Options, Diagnostics).run(Fragment);
}

} // namespace smir
