// C++ exceptions as ordinary control flow; see lowerExceptions in program.h.
//
// LLVM expresses exceptions with `invoke`, `landingpad` and `resume`, which
// a native target hands to an unwinder that walks the stack. A portable
// module has no such stack to walk. Here a function that throws returns to
// its caller like any other, having said that an exception is on its way,
// and every call that may throw is followed by a test of that:
//
//   - `__smir_unwinding` is a thread-local flag, set while an exception
//     propagates. The runtime in sysroot/exceptions.cpp defines it; a
//     program that links none of that runtime cannot throw, and its invokes
//     become plain calls.
//   - A call that may throw, in a function that may let the exception out,
//     is followed by a test of the flag; if it is set the function returns,
//     with no value that means anything.
//   - An `invoke` is a call followed by the same test, which goes to the
//     landing pad instead.
//   - A landing pad first asks the runtime which of its clauses catches the
//     exception. If none does and it has no cleanup, the function returns
//     as above. Otherwise the runtime clears the flag and the pad's code
//     runs; `resume` sets the flag again and returns.
//   - The number that stands for a caught type, which the pad's code
//     compares with `llvm.eh.typeid.for`, is given out here, one for each
//     type a clause names.
#include "program.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/InstructionSimplify.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"

namespace smir {

namespace {

using namespace llvm;

class Lowering {
public:
  explicit Lowering(Module &M)
      : M(M), Context(M.getContext()), Int32(Type::getInt32Ty(Context)), Pointer(PointerType::get(Context, 0)),
        Unwinding(M.getGlobalVariable("__smir_unwinding")) {}

  std::string run() {
    for (Function &F : M)
      if (!F.isDeclaration())
        lower(F);
    // Nothing unwinds any more, so nothing has a personality.
    for (Function &F : M)
      if (F.hasPersonalityFn())
        F.setPersonalityFn(nullptr);
    if (Function *Personality = M.getFunction("__gxx_personality_v0"); Personality && Personality->use_empty())
      Personality->eraseFromParent();
    return Error;
  }

private:
  Module &M;
  LLVMContext &Context;
  Type *Int32, *Pointer;
  // The flag that says an exception is propagating; null if the program has
  // nothing that can set it.
  GlobalVariable *Unwinding;
  DenseMap<Constant *, uint32_t> TypeIds;
  std::string Error;

  // The number that stands for a type in a landing pad's selector. Zero
  // stands for no type.
  uint32_t typeId(Constant *Type) {
    auto [Slot, Inserted] = TypeIds.try_emplace(Type->stripPointerCasts(), TypeIds.size() + 1);
    return Slot->second;
  }

  FunctionCallee runtime(StringRef Name, Type *Result, ArrayRef<Type *> Parameters) {
    FunctionCallee Callee = M.getOrInsertFunction(Name, FunctionType::get(Result, Parameters, false));
    if (auto *F = dyn_cast<Function>(Callee.getCallee()))
      F->setDoesNotThrow();
    return Callee;
  }

  // Whether a call may be how an exception reaches this function. The
  // runtime's functions that start one are compiled like any other code and
  // look as if they could not: they return, having set the flag.
  static bool mayThrow(const CallBase &Call) {
    // The function is named even where the call gives it another type
    // than its definition has.
    if (const auto *Callee = dyn_cast<Function>(Call.getCalledOperand()->stripPointerCasts());
        Callee && is_contained({"__cxa_throw", "__cxa_rethrow", "__cxa_rethrow_primary_exception"},
                               Callee->getName()))
      return true;
    return !Call.doesNotThrow() && !Call.isInlineAsm() && !isa<IntrinsicInst>(Call);
  }

  void lower(Function &F) {
    SmallVector<InvokeInst *, 8> Invokes;
    SmallVector<CallInst *, 16> Calls;
    SmallVector<LandingPadInst *, 8> Pads;
    SmallVector<ResumeInst *, 4> Resumes;
    SmallVector<IntrinsicInst *, 8> TypeTests;
    for (Instruction &I : instructions(F)) {
      if (auto *Invoke = dyn_cast<InvokeInst>(&I))
        Invokes.push_back(Invoke);
      else if (auto *Pad = dyn_cast<LandingPadInst>(&I))
        Pads.push_back(Pad);
      else if (auto *Resume = dyn_cast<ResumeInst>(&I))
        Resumes.push_back(Resume);
      else if (auto *Intrinsic = dyn_cast<IntrinsicInst>(&I);
               Intrinsic && Intrinsic->getIntrinsicID() == Intrinsic::eh_typeid_for)
        TypeTests.push_back(Intrinsic);
      else if (auto *Call = dyn_cast<CallInst>(&I);
               Call && Unwinding && !F.doesNotThrow() && mayThrow(*Call) && !Call->isMustTailCall())
        Calls.push_back(Call);
    }
    for (IntrinsicInst *Test : TypeTests) {
      Test->replaceAllUsesWith(ConstantInt::get(Test->getType(), typeId(cast<Constant>(Test->getArgOperand(0)))));
      Test->eraseFromParent();
    }
    if (Invokes.empty() && Calls.empty() && Pads.empty() && Resumes.empty())
      return;

    // Where the flag is, for this thread, and where the function goes when
    // an exception leaves it.
    Value *Flag = nullptr;
    BasicBlock *Leave = nullptr;
    if (Unwinding) {
      IRBuilder<> Entry(&*F.getEntryBlock().getFirstInsertionPt());
      Flag = Entry.CreateThreadLocalAddress(Unwinding);
      Leave = BasicBlock::Create(Context, "unwind", &F);
      IRBuilder<> Builder(Leave);
      if (F.getName() == "_start") {
        // Nothing is above the program's entry to catch it.
        Builder.CreateCall(runtime("__smir_unhandled", Type::getVoidTy(Context), {}));
        Builder.CreateUnreachable();
      } else if (F.getReturnType()->isVoidTy()) {
        Builder.CreateRetVoid();
      } else {
        Builder.CreateRet(PoisonValue::get(F.getReturnType()));
      }
      // It returns now where it never did.
      F.removeFnAttr(Attribute::NoReturn);
    }
    auto Propagating = [&](IRBuilder<> &Builder) {
      return Builder.CreateICmpNE(Builder.CreateLoad(Int32, Flag), ConstantInt::get(Int32, 0));
    };

    for (InvokeInst *Invoke : Invokes) {
      BasicBlock *Block = Invoke->getParent(), *Normal = Invoke->getNormalDest(), *Pad = Invoke->getUnwindDest();
      SmallVector<Value *, 8> Arguments(Invoke->args());
      SmallVector<OperandBundleDef, 1> Bundles;
      Invoke->getOperandBundlesAsDefs(Bundles);
      CallInst *Call = CallInst::Create(Invoke->getFunctionType(), Invoke->getCalledOperand(), Arguments, Bundles,
                                        "", Invoke->getIterator());
      Call->takeName(Invoke);
      Call->setCallingConv(Invoke->getCallingConv());
      Call->setAttributes(Invoke->getAttributes());
      Call->setDebugLoc(Invoke->getDebugLoc());
      // What it calls returns here, whatever it was declared to do.
      Call->removeFnAttr(Attribute::NoReturn);
      Invoke->replaceAllUsesWith(Call);
      IRBuilder<> Builder(Invoke);
      if (Unwinding && mayThrow(*Call)) {
        Builder.CreateCondBr(Propagating(Builder), Pad, Normal);
      } else {
        Builder.CreateBr(Normal);
        Pad->removePredecessor(Block);
      }
      Invoke->eraseFromParent();
    }
    if (!Unwinding) {
      // The landing pads are reached from nowhere now.
      removeUnreachableBlocks(F);
      return;
    }

    for (CallInst *Call : Calls) {
      Call->removeFnAttr(Attribute::NoReturn);
      BasicBlock *Block = Call->getParent();
      BasicBlock *Rest = SplitBlock(Block, std::next(Call->getIterator()));
      Instruction *Jump = Block->getTerminator();
      IRBuilder<> Builder(Jump);
      Builder.CreateCondBr(Propagating(Builder), Leave, Rest);
      Jump->eraseFromParent();
    }

    Type *Pair = StructType::get(Pointer, Int32);
    for (LandingPadInst *Pad : Pads) {
      BasicBlock *Block = Pad->getParent();
      BasicBlock *Rest = SplitBlock(Block, std::next(Pad->getIterator()));
      Instruction *Jump = Block->getTerminator();
      IRBuilder<> Builder(Jump);
      // Which clause catches it: the runtime gets the types the clauses
      // name, in order, and the number that stands for each.
      SmallVector<Constant *, 4> Types, Ids;
      for (unsigned Index = 0; Index < Pad->getNumClauses(); ++Index) {
        if (!Pad->isCatch(Index)) {
          Error = ("exception specification with a list of types in " + F.getName()).str();
          continue;
        }
        Constant *Caught = Pad->getClause(Index);
        Types.push_back(ConstantExpr::getPointerBitCastOrAddrSpaceCast(Caught, Pointer));
        Ids.push_back(ConstantInt::get(Int32, typeId(Caught)));
      }
      Value *Selector = ConstantInt::get(Int32, 0);
      if (!Types.empty()) {
        auto Table = [&](ArrayRef<Constant *> Elements, Type *Element) {
          ArrayType *Type = ArrayType::get(Element, Elements.size());
          return new GlobalVariable(M, Type, true, GlobalValue::PrivateLinkage, ConstantArray::get(Type, Elements),
                                    "catches");
        };
        Selector = Builder.CreateCall(runtime("__smir_select", Int32, {Pointer, Pointer, Int32}),
                                      {Table(Types, Pointer), Table(Ids, Int32),
                                       ConstantInt::get(Int32, Types.size())});
      }
      BasicBlock *Landed = BasicBlock::Create(Context, "landed", &F, Rest);
      if (Pad->isCleanup())
        Builder.CreateBr(Landed);
      else
        Builder.CreateCondBr(Builder.CreateICmpEQ(Selector, ConstantInt::get(Int32, 0)), Leave, Landed);
      Jump->eraseFromParent();
      // The exception has landed: the flag is cleared, and the pad's code
      // gets the exception and the selector as the pair it expects.
      IRBuilder<> Arrived(Landed);
      Value *Exception = Arrived.CreateCall(runtime("__smir_landed", Pointer, {}));
      Value *Both = Arrived.CreateInsertValue(PoisonValue::get(Pair), Exception, 0);
      Both = Arrived.CreateInsertValue(Both, Selector, 1);
      Arrived.CreateBr(Rest);
      // Phis of the pad's successors named the pad's block; they are
      // reached from the rest of it now, which SplitBlock has seen to.
      Pad->replaceAllUsesWith(Both);
      Pad->eraseFromParent();
    }

    for (ResumeInst *Resume : Resumes) {
      IRBuilder<> Builder(Resume);
      Builder.CreateCall(runtime("__smir_resume", Type::getVoidTy(Context), {Pointer}),
                         {Builder.CreateExtractValue(Resume->getValue(), 0)});
      Builder.CreateBr(Leave);
      Resume->eraseFromParent();
    }
    scalarizePairs(F, Pair);
  }

  // The pair of exception and selector is an aggregate only in passing:
  // take phis of pairs apart and read fields from where they were written.
  void scalarizePairs(Function &F, Type *Pair) {
    SmallVector<PHINode *, 4> Phis;
    for (Instruction &I : instructions(F))
      if (auto *Phi = dyn_cast<PHINode>(&I); Phi && Phi->getType() == Pair)
        Phis.push_back(Phi);
    for (PHINode *Phi : Phis) {
      PHINode *Parts[2];
      for (unsigned Part = 0; Part < 2; ++Part) {
        Parts[Part] = PHINode::Create(Pair->getStructElementType(Part), Phi->getNumIncomingValues(), "",
                                      Phi->getIterator());
        for (unsigned Index = 0; Index < Phi->getNumIncomingValues(); ++Index) {
          BasicBlock *From = Phi->getIncomingBlock(Index);
          // One value for a predecessor, however many edges come from it.
          Value *Taken = Parts[Part]->getBasicBlockIndex(From) >= 0
                             ? Parts[Part]->getIncomingValueForBlock(From)
                             : ExtractValueInst::Create(Phi->getIncomingValue(Index), {Part}, "",
                                                        From->getTerminator()->getIterator());
          Parts[Part]->addIncoming(Taken, From);
        }
      }
      IRBuilder<> Builder(&*Phi->getParent()->getFirstInsertionPt());
      Value *Both = Builder.CreateInsertValue(PoisonValue::get(Pair), Parts[0], 0);
      Phi->replaceAllUsesWith(Builder.CreateInsertValue(Both, Parts[1], 1));
      Phi->eraseFromParent();
    }
    const DataLayout &Layout = M.getDataLayout();
    for (bool Changed = true; Changed;) {
      Changed = false;
      for (Instruction &I : make_early_inc_range(instructions(F)))
        if (auto *Extract = dyn_cast<ExtractValueInst>(&I))
          if (Value *Simple = simplifyInstruction(Extract, SimplifyQuery(Layout))) {
            Extract->replaceAllUsesWith(Simple);
            Extract->eraseFromParent();
            Changed = true;
          }
    }
    for (Instruction &I : make_early_inc_range(instructions(F)))
      if (isa<InsertValueInst>(I) && I.use_empty())
        RecursivelyDeleteTriviallyDeadInstructions(&I);
  }
};

} // namespace

std::string lowerExceptions(llvm::Module &M) { return Lowering(M).run(); }

bool declareExceptionRuntime(llvm::Module &M) {
  using namespace llvm;
  // Exceptions are handled where there is an invoke, and thrown through
  // every function that calls what may throw; either way some function has
  // a personality or the runtime's entry points are named.
  bool Handles = any_of(M, [](const Function &F) { return F.hasPersonalityFn(); }) ||
                 M.getFunction("__cxa_throw") || M.getFunction("__cxa_rethrow");
  if (!Handles)
    return false;
  LLVMContext &Context = M.getContext();
  Type *Int32 = Type::getInt32Ty(Context), *Pointer = PointerType::get(Context, 0);
  // Part of the runtime may be here already, brought by what the program
  // itself names; each of these is declared unless it is.
  bool Declared = false;
  if (!M.getNamedValue("__smir_unwinding")) {
    new GlobalVariable(M, Int32, false, GlobalValue::ExternalLinkage, nullptr, "__smir_unwinding", nullptr,
                       GlobalValue::GeneralDynamicTLSModel);
    Declared = true;
  }
  auto Declare = [&](StringRef Name, FunctionType *Type) {
    if (M.getFunction(Name))
      return;
    M.getOrInsertFunction(Name, Type);
    Declared = true;
  };
  Declare("__smir_select", FunctionType::get(Int32, {Pointer, Pointer, Int32}, false));
  Declare("__smir_landed", FunctionType::get(Pointer, false));
  Declare("__smir_resume", FunctionType::get(Type::getVoidTy(Context), {Pointer}, false));
  Declare("__smir_unhandled", FunctionType::get(Type::getVoidTy(Context), false));
  return Declared;
}

} // namespace smir
