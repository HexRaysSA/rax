// Whole-program rewrites between linking and lowering; see program.h.
#include "program.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/CodeGen/ExpandReductions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/xxhash.h"
#include "llvm/Transforms/Scalar/DCE.h"
#include "llvm/Transforms/Scalar/Scalarizer.h"
#include <set>

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

namespace {

const char *UnitKind = "smir.unit";

// What follows the name a library's local definition had.
const llvm::StringRef LocalMark = ".smir.local.";

// The translation unit a definition was tagged with; the empty name if none.
std::string unitOf(const llvm::GlobalObject &Object) {
  llvm::MDNode *Node = Object.getMetadata(UnitKind);
  if (!Node || Node->getNumOperands() != 1)
    return {};
  auto *Name = llvm::dyn_cast<llvm::MDString>(Node->getOperand(0));
  return Name ? Name->getString().str() : std::string();
}

// The globals a value refers to, through any constant expressions.
void collectGlobals(const llvm::Value *V, llvm::SmallVectorImpl<const llvm::GlobalValue *> &Found,
                    llvm::SmallPtrSetImpl<const llvm::Constant *> &Seen) {
  if (auto *Global = llvm::dyn_cast<llvm::GlobalValue>(V)) {
    Found.push_back(Global);
    return;
  }
  if (auto *Known = llvm::dyn_cast<llvm::Constant>(V))
    if (Seen.insert(Known).second)
      for (const llvm::Use &Operand : Known->operands())
        collectGlobals(Operand, Found, Seen);
}

// The functions of a list of constructors or destructors, in order.
llvm::SmallVector<const llvm::Function *, 8> structors(const llvm::GlobalVariable *List) {
  llvm::SmallVector<const llvm::Function *, 8> Result;
  if (List && List->hasInitializer())
    if (auto *Entries = llvm::dyn_cast<llvm::ConstantArray>(List->getInitializer()))
      for (const llvm::Use &Entry : Entries->operands())
        Result.push_back(llvm::dyn_cast<llvm::Function>(
            llvm::cast<llvm::Constant>(Entry)->getAggregateElement(1U)->stripPointerCasts()));
  return Result;
}

} // namespace

void nameLocals(llvm::Module &M, llvm::StringRef Library) {
  std::string Suffix = (LocalMark + llvm::utohexstr(llvm::xxh3_64bits(Library), true)).str();
  for (llvm::GlobalValue &Global : M.global_values()) {
    if (Global.isDeclaration() || !Global.hasLocalLinkage())
      continue;
    // A private constant is the same wherever it is copied to.
    auto *Variable = llvm::dyn_cast<llvm::GlobalVariable>(&Global);
    if (Variable && Variable->hasPrivateLinkage() && Variable->isConstant())
      continue;
    Global.setName((Global.hasName() ? Global.getName() : llvm::StringRef("local")) + Suffix);
    Global.setLinkage(llvm::GlobalValue::ExternalLinkage);
  }
}

void restoreLocals(llvm::Module &M) {
  for (llvm::GlobalValue &Global : M.global_values())
    if (!Global.isDeclaration() && Global.getName().contains(LocalMark))
      Global.setLinkage(llvm::GlobalValue::InternalLinkage);
}

void tagUnit(llvm::Module &M, llvm::StringRef Unit) {
  llvm::LLVMContext &Context = M.getContext();
  llvm::MDNode *Tag = llvm::MDNode::get(Context, llvm::MDString::get(Context, Unit));
  for (llvm::GlobalObject &Object : M.global_objects())
    if (!Object.isDeclaration())
      Object.setMetadata(UnitKind, Tag);
}

void pruneConstructors(llvm::Module &Library, const llvm::Module &Program, std::set<std::string> &Taken) {
  static const char *Lists[] = {"llvm.global_ctors", "llvm.global_dtors"};
  // What of the library the program needs: what it names and does not
  // define, and whatever that refers to in turn.
  llvm::SmallPtrSet<const llvm::GlobalValue *, 32> Needed;
  llvm::SmallVector<const llvm::GlobalValue *, 32> Work;
  std::set<std::string> Units;
  auto Need = [&](const llvm::GlobalValue *Global) {
    if (Global && !Global->isDeclaration() && Needed.insert(Global).second)
      Work.push_back(Global);
  };
  for (const llvm::GlobalValue &Wanted : Program.global_values())
    if (Wanted.isDeclaration())
      Need(Library.getNamedValue(Wanted.getName()));
  auto Close = [&] {
    while (!Work.empty()) {
      const llvm::GlobalValue *Global = Work.pop_back_val();
      llvm::SmallVector<const llvm::GlobalValue *, 16> Found;
      llvm::SmallPtrSet<const llvm::Constant *, 16> Seen;
      if (auto *Object = llvm::dyn_cast<llvm::GlobalObject>(Global))
        Units.insert(unitOf(*Object));
      if (auto *F = llvm::dyn_cast<llvm::Function>(Global)) {
        for (const llvm::Instruction &I : llvm::instructions(*F))
          for (const llvm::Use &Operand : I.operands())
            collectGlobals(Operand, Found, Seen);
      } else if (auto *Variable = llvm::dyn_cast<llvm::GlobalVariable>(Global)) {
        if (Variable->hasInitializer())
          collectGlobals(Variable->getInitializer(), Found, Seen);
      } else if (auto *Alias = llvm::dyn_cast<llvm::GlobalAlias>(Global)) {
        collectGlobals(Alias->getAliasee(), Found, Seen);
      }
      for (const llvm::GlobalValue *Each : Found)
        Need(Each);
    }
  };
  Close();
  // A constructor is kept if its unit is needed, or if it was never tagged,
  // unless the program has that unit's constructors already. What a kept
  // constructor refers to is needed too, which may need more units, until
  // nothing changes.
  auto Kept = [&](const llvm::Function *F) {
    std::string Unit = F ? unitOf(*F) : std::string();
    return !Taken.count(Unit) && (Unit.empty() || Units.count(Unit));
  };
  for (bool Changed = true; Changed;) {
    Changed = false;
    for (const char *Name : Lists)
      for (const llvm::Function *F : structors(Library.getGlobalVariable(Name)))
        if (F && Kept(F) && !Needed.count(F)) {
          Need(F);
          Close();
          Changed = true;
        }
  }
  std::set<std::string> Staying;
  for (const char *Name : Lists)
    for (const llvm::Function *F : structors(Library.getGlobalVariable(Name)))
      if (Kept(F))
        Staying.insert(F ? unitOf(*F) : std::string());
  for (const char *Name : Lists) {
    llvm::GlobalVariable *List = Library.getGlobalVariable(Name);
    if (!List || !List->hasInitializer())
      continue;
    auto *Entries = llvm::dyn_cast<llvm::ConstantArray>(List->getInitializer());
    if (!Entries)
      continue;
    llvm::SmallVector<llvm::Constant *, 8> Remaining;
    llvm::SmallVector<const llvm::Function *, 8> Functions = structors(List);
    for (unsigned Index = 0; Index < Entries->getNumOperands(); ++Index)
      if (Kept(Functions[Index]))
        Remaining.push_back(Entries->getOperand(Index));
    if (Remaining.size() == Entries->getNumOperands())
      continue;
    // The list's type has its length in it, so a shorter list is a new
    // variable of the same name.
    llvm::ArrayType *Type = llvm::ArrayType::get(Entries->getType()->getElementType(), Remaining.size());
    List->eraseFromParent();
    if (!Remaining.empty())
      new llvm::GlobalVariable(Library, Type, false, llvm::GlobalValue::AppendingLinkage,
                               llvm::ConstantArray::get(Type, Remaining), Name);
  }
  Taken.insert(Staying.begin(), Staying.end());
}

namespace {

// `Argument` as a pointer of type `Wanted`, which differs in its address
// space, to be computed before `Before`. A constant that was converted from
// the wanted type is that constant again, and null is null.
llvm::Value *convertPointer(llvm::Value *Argument, llvm::Type *Wanted, llvm::Instruction *Before) {
  if (auto *Known = llvm::dyn_cast<llvm::Constant>(Argument)) {
    llvm::Constant *Base = Known->stripPointerCasts();
    if (Base->getType() == Wanted)
      return Base;
    if (Base->isNullValue())
      return llvm::ConstantPointerNull::get(llvm::cast<llvm::PointerType>(Wanted));
    return llvm::ConstantExpr::getAddrSpaceCast(Known, Wanted);
  }
  return llvm::CastInst::Create(llvm::Instruction::AddrSpaceCast, Argument, Wanted, "", Before->getIterator());
}

} // namespace

void repairArguments(llvm::Module &M) {
  for (llvm::Function &F : M)
    for (llvm::Instruction &I : llvm::instructions(F)) {
      auto *Call = llvm::dyn_cast<llvm::CallBase>(&I);
      if (!Call)
        continue;
      llvm::FunctionType *Type = Call->getFunctionType();
      for (unsigned Index = 0; Index < Type->getNumParams() && Index < Call->arg_size(); ++Index) {
        llvm::Value *Argument = Call->getArgOperand(Index);
        llvm::Type *Wanted = Type->getParamType(Index);
        if (Argument->getType() == Wanted || !Argument->getType()->isPointerTy() || !Wanted->isPointerTy())
          continue;
        Call->setArgOperand(Index, convertPointer(Argument, Wanted, Call));
      }
    }
}

void reconcileCalls(llvm::Module &M) {
  // Whether the two types are the same but for the address spaces of
  // pointers.
  auto Alike = [](llvm::Type *Left, llvm::Type *Right) {
    return Left == Right || (Left->isPointerTy() && Right->isPointerTy());
  };
  for (llvm::Function &F : M)
    for (llvm::Instruction &I : llvm::make_early_inc_range(llvm::instructions(F))) {
      auto *Call = llvm::dyn_cast<llvm::CallInst>(&I);
      if (!Call || Call->getCalledFunction() || Call->isInlineAsm())
        continue;
      auto *Callee = llvm::dyn_cast<llvm::Function>(Call->getCalledOperand()->stripPointerCasts());
      if (!Callee)
        continue;
      llvm::FunctionType *Declared = Callee->getFunctionType(), *Used = Call->getFunctionType();
      if (Declared == Used || Declared->isVarArg() != Used->isVarArg() ||
          Declared->getNumParams() != Used->getNumParams() ||
          !Alike(Declared->getReturnType(), Used->getReturnType()) ||
          !std::equal(Declared->param_begin(), Declared->param_end(), Used->param_begin(), Alike))
        continue;
      llvm::IRBuilder<> Builder(Call);
      llvm::SmallVector<llvm::Value *, 8> Arguments;
      for (unsigned Index = 0; Index < Call->arg_size(); ++Index) {
        llvm::Value *Argument = Call->getArgOperand(Index);
        if (Index < Declared->getNumParams() && Argument->getType() != Declared->getParamType(Index))
          Argument = convertPointer(Argument, Declared->getParamType(Index), Call);
        Arguments.push_back(Argument);
      }
      llvm::CallInst *Direct = Builder.CreateCall(Declared, Callee, Arguments);
      Direct->setCallingConv(Call->getCallingConv());
      Direct->setTailCallKind(Call->getTailCallKind());
      Direct->setDebugLoc(Call->getDebugLoc());
      llvm::Value *Result = Direct;
      if (!Used->getReturnType()->isVoidTy()) {
        Result = Builder.CreatePointerBitCastOrAddrSpaceCast(Direct, Used->getReturnType());
        Direct->takeName(Call);
      }
      Call->replaceAllUsesWith(Result);
      Call->eraseFromParent();
    }
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
