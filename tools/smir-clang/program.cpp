// Whole-program rewrites between linking and lowering; see program.h.
#include "program.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/CodeGen/ExpandReductions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Transforms/Scalar/DCE.h"
#include "llvm/Transforms/Scalar/Scalarizer.h"

namespace smir {

void addEntry(llvm::Module &M) {
  llvm::Function *Main = M.getFunction("main");
  if (!Main || Main->isDeclaration() || M.getFunction("_start"))
    return;
  llvm::LLVMContext &Context = M.getContext();
  llvm::Type *Int = llvm::Type::getInt32Ty(Context), *Pointer = llvm::PointerType::get(Context, 0);
  llvm::Type *Parameters[3] = {Int, Pointer, Pointer};
  // A `main` of another shape gets no entry; whoever runs the program
  // reports that.
  llvm::FunctionType *Declared = Main->getFunctionType();
  if (Declared->isVarArg() || Declared->getNumParams() > 3 ||
      !(Declared->getReturnType() == Int || Declared->getReturnType()->isVoidTy()) ||
      !std::equal(Declared->param_begin(), Declared->param_end(), Parameters))
    return;
  llvm::Function *Start =
      llvm::Function::Create(llvm::FunctionType::get(Int, Parameters, false), llvm::GlobalValue::ExternalLinkage,
                             Main->getAddressSpace(), "_start", &M);
  llvm::IRBuilder<> Builder(llvm::BasicBlock::Create(Context, "entry", Start));
  llvm::SmallVector<llvm::Value *, 3> Arguments;
  for (unsigned Index = 0; Index < Declared->getNumParams(); ++Index)
    Arguments.push_back(Start->getArg(Index));
  llvm::CallInst *Result = Builder.CreateCall(Main, Arguments);
  Result->setCallingConv(Main->getCallingConv());
  llvm::Value *Status = Result;
  if (Declared->getReturnType()->isVoidTy())
    Status = Builder.getInt32(0);
  llvm::FunctionCallee Exit = M.getOrInsertFunction("exit", llvm::Type::getVoidTy(Context), Int);
  Builder.CreateCall(Exit, Status);
  Builder.CreateRet(Status);
}

void finishEntry(llvm::Module &M) {
  llvm::Function *Start = M.getFunction("_start"), *Exit = M.getFunction("exit");
  if (!Start || !Exit || !Exit->isDeclaration())
    return;
  for (llvm::Instruction &I : llvm::make_early_inc_range(Start->getEntryBlock()))
    if (auto *Call = llvm::dyn_cast<llvm::CallInst>(&I); Call && Call->getCalledFunction() == Exit)
      Call->eraseFromParent();
  if (Exit->use_empty())
    Exit->eraseFromParent();
}

void resolveAliases(llvm::Module &M) {
  for (llvm::GlobalAlias &Alias : llvm::make_early_inc_range(M.aliases())) {
    llvm::GlobalObject *Target = Alias.getAliaseeObject();
    if (!Target || Target->isDeclaration() || Alias.isInterposable())
      continue;
    Alias.replaceAllUsesWith(Alias.getAliasee());
    if (Target->hasLocalLinkage() && !Alias.hasLocalLinkage() && Alias.getAliasee() == Target) {
      Target->takeName(&Alias);
      Target->setLinkage(Alias.getLinkage());
      Target->setVisibility(Alias.getVisibility());
    }
    Alias.eraseFromParent();
  }
}

// The format has no relocation that writes a label's address into data, and
// C code keeps such addresses in static tables. So the labels of a function
// whose address is taken are numbered from one (zero stays the null
// pointer), each address becomes its number as a pointer, and an indirect
// branch becomes a switch on the number over the labels it lists. A value
// that is none of those numbers reaches a block that is undefined to reach.
void expandIndirectBranches(llvm::Module &M) {
  llvm::LLVMContext &Context = M.getContext();
  llvm::IntegerType *Number = llvm::Type::getInt64Ty(Context);
  for (llvm::Function &F : M) {
    llvm::DenseMap<llvm::BasicBlock *, uint64_t> Numbers;
    llvm::SmallVector<llvm::IndirectBrInst *, 4> Branches;
    for (llvm::BasicBlock &Block : F) {
      if (auto *Branch = llvm::dyn_cast<llvm::IndirectBrInst>(Block.getTerminator()))
        Branches.push_back(Branch);
      llvm::BlockAddress *Address = llvm::BlockAddress::lookup(&Block);
      if (!Address)
        continue;
      uint64_t Next = Numbers.size() + 1;
      Numbers[&Block] = Next;
      llvm::Constant *Index = llvm::ConstantInt::get(Number, Next);
      // Clang converts the address to a data pointer wherever it is kept;
      // the number takes the type it is used at.
      for (llvm::User *Use : llvm::make_early_inc_range(Address->users()))
        if (auto *Cast = llvm::dyn_cast<llvm::ConstantExpr>(Use);
            Cast && Cast->getOpcode() == llvm::Instruction::AddrSpaceCast)
          Cast->replaceAllUsesWith(llvm::ConstantExpr::getIntToPtr(Index, Cast->getType()));
      Address->replaceAllUsesWith(llvm::ConstantExpr::getIntToPtr(Index, Address->getType()));
    }
    if (Branches.empty())
      continue;
    llvm::BasicBlock *Invalid = llvm::BasicBlock::Create(Context, "label.invalid", &F);
    new llvm::UnreachableInst(Context, Invalid);
    for (llvm::IndirectBrInst *Branch : Branches) {
      llvm::BasicBlock *From = Branch->getParent();
      llvm::Value *Index = new llvm::PtrToIntInst(Branch->getAddress(), Number, "label", Branch->getIterator());
      llvm::SwitchInst *Switch =
          llvm::SwitchInst::Create(Index, Invalid, Branch->getNumDestinations(), Branch->getIterator());
      llvm::SmallPtrSet<llvm::BasicBlock *, 8> Seen;
      for (unsigned Position = 0; Position < Branch->getNumDestinations(); ++Position) {
        llvm::BasicBlock *Target = Branch->getDestination(Position);
        auto Numbered = Numbers.find(Target);
        // The switch has one edge to each label; a label listed twice, or
        // one whose address nothing takes, loses the edge it had.
        if (Numbered == Numbers.end() || !Seen.insert(Target).second) {
          Target->removePredecessor(From, /*KeepOneInputPHIs=*/true);
          continue;
        }
        Switch->addCase(llvm::ConstantInt::get(Number, Numbered->second), Target);
      }
      Branch->eraseFromParent();
    }
  }
}

void scalarize(llvm::Module &M) {
  llvm::PassBuilder Builder;
  llvm::LoopAnalysisManager Loops;
  llvm::FunctionAnalysisManager Functions;
  llvm::CGSCCAnalysisManager Components;
  llvm::ModuleAnalysisManager Modules;
  Builder.registerModuleAnalyses(Modules);
  Builder.registerCGSCCAnalyses(Components);
  Builder.registerFunctionAnalyses(Functions);
  Builder.registerLoopAnalyses(Loops);
  Builder.crossRegisterProxies(Loops, Functions, Components, Modules);
  llvm::ScalarizerPassOptions Options;
  Options.ScalarizeLoadStore = true;
  Options.ScalarizeVariableInsertExtract = true;
  llvm::FunctionPassManager Passes;
  // A reduction over a vector first becomes shuffles and element
  // operations, which the scalarizer then takes apart.
  Passes.addPass(llvm::ExpandReductionsPass());
  Passes.addPass(llvm::ScalarizerPass(Options));
  // What scalarizing leaves behind: the vectors nothing reads any more.
  Passes.addPass(llvm::DCEPass());
  for (llvm::Function &F : M)
    if (!F.isDeclaration())
      Passes.run(F, Functions);
}

} // namespace smir
