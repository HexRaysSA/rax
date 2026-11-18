// `setjmp` and `longjmp` as ordinary control flow; see lowerJumps in
// program.h.
//
// A native `longjmp` puts back the registers `setjmp` saved, the stack
// pointer among them, and so drops every activation in between. A portable
// module has no registers to save. Here, as with exceptions, a jump on its
// way is a thread-local fact that every function between the two looks at:
//
//   - `longjmp`, in the C library (sysroot/jump.c), notes where the jump
//     goes and with what value, and returns.
//   - A call through which a jump may come is followed by a test of that
//     note. If a jump is on its way and this activation is not where it
//     goes, the function returns, with no value that means anything.
//   - `setjmp` writes into its buffer which activation it is in, by the
//     address of a stack object of that activation, and which of the
//     function's `setjmp` calls it is, and yields zero. The function goes
//     on from there a second time, with the value of the jump, when a jump
//     arrives whose buffer says so.
//
// In a function that calls `setjmp`, a value computed after the call may be
// used again after a jump has come back to it. Such a function's values are
// therefore kept in stack objects instead, as C says of its variables: what
// a non-volatile one holds after a jump is not specified.
#include "program.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
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

// The functions that note where a jump may come back to, and those that
// start one, by every name C and POSIX give them.
const std::initializer_list<StringRef> Sets = {"setjmp", "_setjmp", "sigsetjmp", "__sigsetjmp"};
const std::initializer_list<StringRef> Jumps = {"longjmp", "_longjmp", "siglongjmp"};

// The function a call names, whatever type the call gives it.
const Function *calleeOf(const CallBase &Call) {
  return dyn_cast<Function>(Call.getCalledOperand()->stripPointerCasts());
}

bool calls(const CallBase &Call, std::initializer_list<StringRef> Names) {
  const Function *Callee = calleeOf(Call);
  return Callee && is_contained(Names, Callee->getName());
}

class Lowering {
public:
  Lowering(Module &M, GlobalVariable *Target, GlobalVariable *Value)
      : M(M), Context(M.getContext()), Int32(Type::getInt32Ty(Context)), Pointer(PointerType::get(Context, 0)),
        Target(Target), Value(Value) {}

  std::string run() {
    findPassages();
    // A function a jump leaves through returns, whatever it was declared
    // to do; and that must be known of all of them before any is rewritten,
    // or what follows a call of one would be taken for dead code.
    for (Function &F : M)
      if (Passages.count(&F) || is_contained(Jumps, F.getName()))
        F.removeFnAttr(Attribute::NoReturn);
    for (Function &F : M)
      if (!F.isDeclaration() && !is_contained(Sets, F.getName()) && !is_contained(Jumps, F.getName()))
        lower(F);
    return Error;
  }

private:
  Module &M;
  LLVMContext &Context;
  Type *Int32, *Pointer;
  // Where a jump on its way goes, null if none is, and its value.
  GlobalVariable *Target, *Value;
  // The functions a jump may leave through, and whether a call through a
  // pointer may be a call of one.
  SmallPtrSet<const Function *, 32> Passages;
  bool ThroughPointers = false;
  std::string Error;

  bool mayPass(const CallBase &Call) const {
    if (Call.isInlineAsm() || isa<IntrinsicInst>(Call))
      return false;
    const Function *Callee = calleeOf(Call);
    return Callee ? Passages.count(Callee) != 0 : ThroughPointers;
  }

  void findPassages() {
    for (bool Changed = true; Changed;) {
      Changed = false;
      for (const Function &F : M) {
        if (F.isDeclaration() || Passages.count(&F))
          continue;
        bool Passes = any_of(instructions(F), [&](const Instruction &I) {
          const auto *Call = dyn_cast<CallBase>(&I);
          return Call && (calls(*Call, Jumps) || mayPass(*Call));
        });
        if (!Passes)
          continue;
        Passages.insert(&F);
        ThroughPointers |= F.hasAddressTaken();
        Changed = true;
      }
    }
  }

  // Keep every value that outlives its block, and every phi, in a stack
  // object, as LLVM's own pass for it does.
  static void demote(Function &F) {
    BasicBlock &Entry = F.getEntryBlock();
    BasicBlock::iterator Position = Entry.begin();
    while (isa<AllocaInst>(Position))
      ++Position;
    Instruction *Anchor = new BitCastInst(Constant::getNullValue(Type::getInt32Ty(F.getContext())),
                                          Type::getInt32Ty(F.getContext()), "slots", Position);
    auto Escapes = [](const Instruction &I) {
      return any_of(I.users(), [&](const User *U) {
        const auto *Use = cast<Instruction>(U);
        return Use->getParent() != I.getParent() || isa<PHINode>(Use);
      });
    };
    SmallVector<Instruction *, 32> Work;
    for (Instruction &I : instructions(F))
      if (I.getType()->isSized() && !(isa<AllocaInst>(I) && I.getParent() == &Entry) && Escapes(I))
        Work.push_back(&I);
    for (Instruction *I : reverse(Work))
      DemoteRegToStack(*I, false, Anchor->getIterator());
    Work.clear();
    for (BasicBlock &Block : F)
      for (PHINode &Phi : Block.phis())
        Work.push_back(&Phi);
    for (Instruction *Phi : reverse(Work))
      DemotePHIToStack(cast<PHINode>(Phi), Anchor->getIterator());
    Anchor->eraseFromParent();
  }

  void lower(Function &F) {
    auto Collect = [&](SmallVectorImpl<CallBase *> &Setting, SmallVectorImpl<CallBase *> &Jumping,
                       SmallVectorImpl<CallBase *> &Passing) {
      for (Instruction &I : instructions(F)) {
        auto *Call = dyn_cast<CallBase>(&I);
        if (!Call || Call->isMustTailCall())
          continue;
        if (calls(*Call, Sets))
          Setting.push_back(Call);
        else if (calls(*Call, Jumps))
          Jumping.push_back(Call);
        else if (mayPass(*Call))
          Passing.push_back(Call);
      }
    };
    SmallVector<CallBase *, 4> Setting, Jumping;
    SmallVector<CallBase *, 16> Passing;
    Collect(Setting, Jumping, Passing);
    if (Setting.empty() && Jumping.empty() && Passing.empty())
      return;
    if (any_of(Setting, [](CallBase *Call) { return !isa<CallInst>(Call); }) ||
        any_of(Jumping, [](CallBase *Call) { return !isa<CallInst>(Call); })) {
      Error = ("setjmp or longjmp where an exception is handled, in " + F.getName()).str();
      return;
    }
    if (!Setting.empty()) {
      demote(F);
      Setting.clear();
      Jumping.clear();
      Passing.clear();
      Collect(Setting, Jumping, Passing);
    }

    IRBuilder<> Entry(&*F.getEntryBlock().getFirstInsertionPt());
    llvm::Value *TargetAddress = Entry.CreateThreadLocalAddress(Target);
    llvm::Value *ValueAddress = Entry.CreateThreadLocalAddress(Value);
    // What a jump finds this activation by, and the slot each `setjmp`
    // yields its value from.
    AllocaInst *Frame = Setting.empty() ? nullptr : Entry.CreateAlloca(Type::getInt8Ty(Context), nullptr, "frame");
    SmallVector<AllocaInst *, 4> Results;
    for (size_t Site = 0; Site < Setting.size(); ++Site)
      Results.push_back(Entry.CreateAlloca(Int32, nullptr, "jumped"));

    // Where the function goes when a jump passes through it.
    BasicBlock *Leave = BasicBlock::Create(Context, "jump.through", &F);
    {
      IRBuilder<> Builder(Leave);
      if (F.getName() == "_start") {
        // Nothing is above the program's entry: the jump's buffer was of
        // an activation that has ended.
        Builder.CreateIntrinsic(Intrinsic::trap, {});
        Builder.CreateUnreachable();
      } else if (F.getReturnType()->isVoidTy()) {
        Builder.CreateRetVoid();
      } else {
        Builder.CreateRet(PoisonValue::get(F.getReturnType()));
      }
      F.removeFnAttr(Attribute::NoReturn);
    }

    // Each `setjmp`: the buffer gets the activation and the number of the
    // call, and what follows the call starts with the value it yields.
    SmallVector<BasicBlock *, 4> Continuations;
    const DataLayout &Layout = M.getDataLayout();
    uint64_t SiteOffset = Layout.getPointerSize(0);
    for (size_t Site = 0; Site < Setting.size(); ++Site) {
      CallBase *Call = Setting[Site];
      IRBuilder<> Builder(Call);
      llvm::Value *Buffer = Call->getArgOperand(0);
      Builder.CreateStore(Frame, Buffer);
      Builder.CreateStore(ConstantInt::get(Int32, Site + 1), Builder.CreateConstInBoundsGEP1_64(
                                                                 Type::getInt8Ty(Context), Buffer, SiteOffset));
      Builder.CreateStore(ConstantInt::get(Int32, 0), Results[Site]);
      BasicBlock *Continuation = SplitBlock(Call->getParent(), std::next(Call->getIterator()));
      llvm::Value *Yielded = new LoadInst(Int32, Results[Site], "", Continuation->begin());
      if (Call->getType() != Int32)
        Yielded = CastInst::CreateIntegerCast(Yielded, Call->getType(), true, "",
                                              std::next(cast<Instruction>(Yielded)->getIterator()));
      Call->replaceAllUsesWith(Yielded);
      Call->eraseFromParent();
      Continuations.push_back(Continuation);
    }

    // Where a jump that has reached this function is looked at: it is this
    // activation's if the buffer says so, and then goes on after the
    // `setjmp` the buffer names.
    BasicBlock *Arrive = Leave;
    if (!Setting.empty()) {
      Arrive = BasicBlock::Create(Context, "jump.arrive", &F);
      BasicBlock *Mine = BasicBlock::Create(Context, "jump.mine", &F);
      IRBuilder<> Builder(Arrive);
      llvm::Value *Buffer = Builder.CreateLoad(Pointer, TargetAddress);
      Builder.CreateCondBr(Builder.CreateICmpEQ(Builder.CreateLoad(Pointer, Buffer), Frame), Mine, Leave);
      Builder.SetInsertPoint(Mine);
      llvm::Value *Site = Builder.CreateLoad(
          Int32, Builder.CreateConstInBoundsGEP1_64(Type::getInt8Ty(Context), Buffer, SiteOffset));
      SwitchInst *Choice = Builder.CreateSwitch(Site, Leave, Setting.size());
      for (size_t Index = 0; Index < Setting.size(); ++Index) {
        BasicBlock *Land = BasicBlock::Create(Context, "jump.land", &F);
        Choice->addCase(ConstantInt::get(cast<IntegerType>(Int32), Index + 1), Land);
        IRBuilder<> Landing(Land);
        Landing.CreateStore(Landing.CreateLoad(Int32, ValueAddress), Results[Index]);
        // The jump has arrived.
        Landing.CreateStore(ConstantPointerNull::get(cast<PointerType>(Pointer)), TargetAddress);
        Landing.CreateBr(Continuations[Index]);
      }
    }

    // `longjmp` has noted the jump and returned; this function is the
    // first it may be for.
    for (CallBase *Call : Jumping) {
      Call->removeFnAttr(Attribute::NoReturn);
      BasicBlock *Block = Call->getParent();
      SplitBlock(Block, std::next(Call->getIterator()));
      Instruction *Jump = Block->getTerminator();
      IRBuilder<>(Jump).CreateBr(Arrive);
      Jump->eraseFromParent();
    }
    for (CallBase *Call : Passing) {
      Call->removeFnAttr(Attribute::NoReturn);
      // What follows a call, or what follows an invoke that returned.
      BasicBlock *Block, *Rest;
      if (auto *Invoke = dyn_cast<InvokeInst>(Call)) {
        Block = SplitEdge(Invoke->getParent(), Invoke->getNormalDest());
        Rest = Block->getSingleSuccessor();
      } else {
        Block = Call->getParent();
        Rest = SplitBlock(Block, std::next(Call->getIterator()));
      }
      Instruction *Jump = Block->getTerminator();
      IRBuilder<> Builder(Jump);
      llvm::Value *Coming = Builder.CreateICmpNE(Builder.CreateLoad(Pointer, TargetAddress),
                                                 ConstantPointerNull::get(cast<PointerType>(Pointer)));
      Builder.CreateCondBr(Coming, Arrive, Rest);
      Jump->eraseFromParent();
    }
    // What followed a `longjmp` is reached from nowhere now.
    removeUnreachableBlocks(F);
  }
};

} // namespace

std::string lowerJumps(llvm::Module &M) {
  // The C library's `longjmp` is what notes a jump: a program that links
  // none starts none, and its `setjmp` yields zero and nothing else.
  llvm::GlobalVariable *Target = M.getGlobalVariable("__smir_jump_target");
  llvm::GlobalVariable *Value = M.getGlobalVariable("__smir_jump_value");
  if (!Target || !Value || Target->isDeclaration() || Value->isDeclaration())
    return {};
  return Lowering(M, Target, Value).run();
}

} // namespace smir
