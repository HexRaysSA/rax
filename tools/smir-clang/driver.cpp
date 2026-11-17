// smir-clang: compile C and C++ translation units to one portable SMIR
// module fragment, or to LLVM bitcode for a library.
//
//   smir-clang [-O0|-O1|-O2|-O3|-Os|-Oz] [-std=STD] [-I DIR]... [-D MACRO]...
//              [-f...] [-W...] [--resource-dir DIR] [--services CATALOG]
//              [--library FILE.bc]... [--emit-llvm FILE] [-c [--undefined FILE]]
//              -o OUTPUT INPUT...
//
// An INPUT ending in .c is C; in .cc, .cpp or .cxx, C++, compiled without
// exceptions and run-time type information; in .bc or .ll, an LLVM module to
// link as it is. `-std=` applies to the language it names. Clang parses and
// optimizes each source for the smir64-unknown-rax target in this process.
// The resulting modules are linked into one, which resolves the references
// between translation units. Each `--library` is then linked for the
// definitions the program still lacks, and nothing else of it.
//
// With `-c`, OUTPUT is the linked module as LLVM bitcode, references it does
// not resolve included: a library for a later link. `--undefined` then
// writes the names it refers to and does not define, one per line. Otherwise the emitter
// lowers the module, and OUTPUT is a JSON fragment (types, functions,
// symbols, entry index) that smircc.py merges into a complete module and
// assembles.
//
// CATALOG is the runtime service catalog (services-v1.json). Without it no
// function can be bound to a service.
//
// Exit status: 0 on success, 1 when a source does not compile, the
// translation units do not link, or the program uses a construct the emitter
// does not support (nothing is written), 2 on a usage or I/O error.
#include "emit.h"
#include "portable_target.h"

#include "clang/CodeGen/CodeGenAction.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/CompilerInvocation.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/CodeGen/ExpandReductions.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/DiagnosticPrinter.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Scalar/DCE.h"
#include "llvm/Transforms/Scalar/Scalarizer.h"
#include <memory>
#include <string>
#include <vector>

namespace {

const char *Usage =
    "usage: smir-clang [-O<level>] [-std=STD] [-I DIR]... [-D MACRO]... [-f...] [-W...]\n"
    "                  [--resource-dir DIR] [--services CATALOG] [--library FILE.bc]...\n"
    "                  [--emit-llvm FILE] [-c [--undefined FILE]] -o OUTPUT INPUT...\n";

struct Request {
  std::vector<std::string> Inputs, Libraries;
  std::string Output, EmitLLVM, ResourceDir, Services, Undefined;
  std::string Optimization = "-O2";
  std::string StandardC = "-std=c23", StandardCxx = "-std=c++23";
  std::vector<std::string> Passthrough;
  // Write the linked module as bitcode instead of lowering it.
  bool Bitcode = false;
};

bool hasExtension(llvm::StringRef Path, std::initializer_list<const char *> Extensions) {
  return llvm::any_of(Extensions, [&](const char *Extension) { return Path.ends_with(Extension); });
}

bool parse(int Count, char **Args, Request &R) {
  for (int Index = 1; Index < Count; ++Index) {
    llvm::StringRef Arg = Args[Index];
    auto Next = [&](std::string &Slot) {
      if (Index + 1 >= Count)
        return false;
      Slot = Args[++Index];
      return true;
    };
    if (Arg == "-o") {
      if (!Next(R.Output))
        return false;
    } else if (Arg == "--emit-llvm") {
      if (!Next(R.EmitLLVM))
        return false;
    } else if (Arg == "--resource-dir") {
      if (!Next(R.ResourceDir))
        return false;
    } else if (Arg == "--services") {
      if (!Next(R.Services))
        return false;
    } else if (Arg == "--library") {
      if (!Next(R.Libraries.emplace_back()))
        return false;
    } else if (Arg == "-c") {
      R.Bitcode = true;
    } else if (Arg == "--undefined") {
      if (!Next(R.Undefined))
        return false;
    } else if (Arg == "-I" || Arg == "-D" || Arg == "-U" || Arg == "-include" || Arg == "-isystem") {
      std::string Value;
      if (!Next(Value))
        return false;
      R.Passthrough.push_back(Arg.str());
      R.Passthrough.push_back(Value);
    } else if (Arg.starts_with("-I") || Arg.starts_with("-D") || Arg.starts_with("-U") || Arg.starts_with("-f") ||
               Arg.starts_with("-W") || Arg == "-w") {
      // Preprocessor, language and warning options go to Clang as they are.
      R.Passthrough.push_back(Arg.str());
    } else if (Arg == "-O0" || Arg == "-O1" || Arg == "-O2" || Arg == "-O3" || Arg == "-Os" || Arg == "-Oz") {
      R.Optimization = Arg.str();
    } else if (Arg.starts_with("-std=")) {
      (Arg.contains("++") ? R.StandardCxx : R.StandardC) = Arg.str();
    } else if (Arg.starts_with("-")) {
      return false;
    } else {
      R.Inputs.push_back(Arg.str());
    }
  }
  return !R.Inputs.empty() && !R.Output.empty() && (R.Bitcode || R.Undefined.empty());
}

bool write(const std::string &Path, llvm::function_ref<void(llvm::raw_ostream &)> Body) {
  std::error_code Error;
  llvm::raw_fd_ostream Out(Path, Error, llvm::sys::fs::OF_None);
  if (Error) {
    llvm::errs() << "smir-clang: " << Path << ": " << Error.message() << "\n";
    return false;
  }
  Body(Out);
  return true;
}

// Read the names and the parameter and result types of the catalog's
// services into Options. Returns false, with a message, if Path is not such
// a catalog.
bool readServices(const std::string &Path, smir::EmitOptions &Options) {
  auto Fail = [&](const llvm::Twine &Why) {
    llvm::errs() << "smir-clang: " << Path << ": " << Why << "\n";
    return false;
  };
  auto Buffer = llvm::MemoryBuffer::getFile(Path);
  if (!Buffer)
    return Fail(Buffer.getError().message());
  auto Parsed = llvm::json::parse((*Buffer)->getBuffer());
  if (!Parsed)
    return Fail(llvm::toString(Parsed.takeError()));
  const llvm::json::Object *Catalog = Parsed->getAsObject();
  const llvm::json::Array *Records = Catalog ? Catalog->getArray("records") : nullptr;
  auto Namespace = Catalog ? Catalog->getString("namespace") : std::nullopt;
  if (!Records || !Namespace)
    return Fail("not a service catalog");
  Options.ServiceNamespace = Namespace->str();
  for (const llvm::json::Value &Record : *Records) {
    const llvm::json::Object *Row = Record.getAsObject();
    auto Name = Row ? Row->getString("name") : std::nullopt;
    if (!Name)
      return Fail("a service has no name");
    smir::Service Service{Name->str(), {}, {}};
    for (auto [Key, Types] : {std::pair{"params", &Service.Params}, std::pair{"results", &Service.Results}}) {
      const llvm::json::Array *Items = Row->getArray(Key);
      if (!Items)
        return Fail("service " + *Name + " has no " + Key);
      for (const llvm::json::Value &Item : *Items) {
        const llvm::json::Object *Entry = Item.getAsObject();
        auto Type = Entry ? Entry->getString("type") : std::nullopt;
        if (!Type)
          return Fail("service " + *Name + " has an untyped entry in " + Key);
        Types->push_back(Type->str());
      }
    }
    Options.Services.push_back(std::move(Service));
  }
  return true;
}

// Read an LLVM module from a bitcode or textual IR file.
std::unique_ptr<llvm::Module> read(const std::string &Input, llvm::LLVMContext &Context) {
  llvm::SMDiagnostic Problem;
  std::unique_ptr<llvm::Module> M = llvm::parseIRFile(Input, Problem, Context);
  if (!M)
    Problem.print("smir-clang", llvm::errs());
  else if (M->getTargetTriple().str() != smir::Triple) {
    llvm::errs() << "smir-clang: " << Input << ": compiled for " << M->getTargetTriple().str() << ", not "
                 << smir::Triple << "\n";
    return nullptr;
  }
  return M;
}

// Compile one translation unit to an optimized module in Context. Returns
// null after Clang has reported why not; Status is then the exit status.
std::unique_ptr<llvm::Module> compile(const Request &R, const std::string &Input, llvm::LLVMContext &Context,
                                      int &Status) {
  std::string InternalInclude = R.ResourceDir + "/include";
  bool Cxx = hasExtension(Input, {".cc", ".cpp", ".cxx"});
  std::vector<const char *> Options{
      "-triple", smir::Triple, "-x", Cxx ? "c++" : "c", (Cxx ? R.StandardCxx : R.StandardC).c_str(),
      "-emit-llvm-only", R.Optimization.c_str(),
      // Freestanding: no host headers and no assumptions about library calls.
      "-ffreestanding", "-nostdsysteminc",
      // The cc1 default is position-independent code; portable modules are
      // relocated through their own records.
      "-mrelocation-model", "static"};
  if (Cxx) {
    // Exceptions are off unless asked for; run-time type information must be
    // turned off. A function's static variable is initialized without a
    // lock: programs run on one thread so far.
    Options.push_back("-fno-rtti");
    Options.push_back("-fno-threadsafe-statics");
  }
  if (R.ResourceDir.empty()) {
    Options.push_back("-nobuiltininc");
  } else {
    Options.push_back("-resource-dir");
    Options.push_back(R.ResourceDir.c_str());
    Options.push_back("-internal-isystem");
    Options.push_back(InternalInclude.c_str());
  }
  for (const std::string &Arg : R.Passthrough)
    Options.push_back(Arg.c_str());
  Options.push_back(Input.c_str());

  auto Invocation = std::make_shared<clang::CompilerInvocation>();
  clang::CompilerInstance CI(Invocation);
  CI.setVirtualFileSystem(llvm::vfs::getRealFileSystem());
  CI.createDiagnostics();
  Status = 2;
  if (!clang::CompilerInvocation::CreateFromArgs(*Invocation, Options, CI.getDiagnostics()))
    return nullptr;
  Status = 1;
  clang::EmitLLVMOnlyAction Action(&Context);
  if (!CI.ExecuteAction(Action) || CI.getDiagnostics().hasErrorOccurred())
    return nullptr;
  std::unique_ptr<llvm::Module> M = Action.takeModule();
  if (!M)
    llvm::errs() << "smir-clang: " << Input << ": code generation produced no module\n";
  return M;
}

// The entry of a program: `int _start(int argc, char **argv, char **envp)`.
//
// It calls `main` with as many of its three arguments as `main` declares and
// then calls `exit` with the result, as returning from `main` is defined to
// do. It is added before the libraries are linked, so that its reference
// brings in the C library's `exit` when there is one.
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

// Without a C library nothing defines `exit`: the entry then returns the
// status instead, and whoever runs the program ends it.
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

// Rewrite vector operations as operations on their elements. The optimizer
// produces vectors even from scalar code (a sixteen-byte structure copied as
// one <2 x double>, for example), and the emitter lowers scalars only.
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

// Reports what LLVM says while linking; an error makes the link fail instead
// of ending the process.
struct LinkDiagnostics : llvm::DiagnosticHandler {
  bool handleDiagnostics(const llvm::DiagnosticInfo &Info) override {
    if (Info.getSeverity() != llvm::DS_Error)
      return true;
    llvm::errs() << "smir-clang: error: E-LINK: ";
    llvm::DiagnosticPrinterRawOStream Printer(llvm::errs());
    Info.print(Printer);
    llvm::errs() << "\n";
    return true;
  }
};

} // namespace

int main(int Count, char **Args) {
  Request R;
  if (!parse(Count, Args, R)) {
    llvm::errs() << Usage;
    return 2;
  }
  smir::EmitOptions Options;
  if (!R.Services.empty() && !readServices(R.Services, Options))
    return 2;
  llvm::LLVMContext Context;
  Context.setDiagnosticHandler(std::make_unique<LinkDiagnostics>());
  std::unique_ptr<llvm::Module> M;
  // Link Unit into the program: all of it, or only what the program refers
  // to and does not define.
  auto Link = [&](std::unique_ptr<llvm::Module> Unit, bool OnlyNeeded) {
    if (!M) {
      M = std::move(Unit);
      return true;
    }
    // Definitions replace declarations, and local names that collide are
    // renamed. Two definitions of one external name are an error.
    unsigned Flags = OnlyNeeded ? llvm::Linker::LinkOnlyNeeded : llvm::Linker::None;
    if (!llvm::Linker::linkModules(*M, std::move(Unit), Flags))
      return true;
    llvm::errs() << "smir-clang: the translation units do not link; nothing written\n";
    return false;
  };
  for (const std::string &Input : R.Inputs) {
    int Status = hasExtension(Input, {".bc", ".ll"}) ? 2 : 0;
    std::unique_ptr<llvm::Module> Unit = Status ? read(Input, Context) : compile(R, Input, Context, Status);
    if (!Unit)
      return Status;
    if (!Link(std::move(Unit), false))
      return 1;
  }
  if (!R.Bitcode)
    addEntry(*M);
  for (const std::string &Library : R.Libraries) {
    std::unique_ptr<llvm::Module> Unit = read(Library, Context);
    if (!Unit)
      return 2;
    if (!Link(std::move(Unit), true))
      return 1;
  }
  if (llvm::verifyModule(*M, &llvm::errs())) {
    llvm::errs() << "smir-clang: generated IR does not verify\n";
    return 1;
  }
  if (R.Bitcode) {
    // What a library leaves for the program, or for another library, to define.
    auto Names = [&](llvm::raw_ostream &Out) {
      for (const llvm::GlobalObject &Global : M->global_objects())
        if (Global.isDeclaration() && !Global.use_empty() && !Global.getName().starts_with("llvm."))
          Out << Global.getName() << "\n";
    };
    if (!R.Undefined.empty() && !write(R.Undefined, Names))
      return 2;
    if (!R.EmitLLVM.empty() && !write(R.EmitLLVM, [&](llvm::raw_ostream &Out) { M->print(Out, nullptr); }))
      return 2;
    return write(R.Output, [&](llvm::raw_ostream &Out) { llvm::WriteBitcodeToFile(*M, Out); }) ? 0 : 2;
  }
  finishEntry(*M);
  // The program is complete, so an alias is just a second name for what it
  // refers to: every use becomes a use of that. An alias that other modules
  // could see hands its name to a definition that had only a local one.
  for (llvm::GlobalAlias &Alias : llvm::make_early_inc_range(M->aliases())) {
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
  scalarize(*M);
  if (!R.EmitLLVM.empty() && !write(R.EmitLLVM, [&](llvm::raw_ostream &Out) { M->print(Out, nullptr); }))
    return 2;

  llvm::json::Object Fragment;
  std::vector<smir::Diagnostic> Diagnostics;
  if (!smir::emit(*M, Options, Fragment, Diagnostics)) {
    for (const smir::Diagnostic &D : Diagnostics) {
      llvm::errs() << "smir-clang: error: " << D.Code << ": ";
      if (!D.Function.empty())
        llvm::errs() << "in " << D.Function << ": ";
      llvm::errs() << D.Detail << "\n";
    }
    llvm::errs() << "smir-clang: " << Diagnostics.size() << " unsupported construct(s); nothing written\n";
    return 1;
  }
  Fragment["triple"] = M->getTargetTriple().str();
  Fragment["datalayout"] = M->getDataLayoutStr();
  llvm::json::Value Document(std::move(Fragment));
  return write(R.Output, [&](llvm::raw_ostream &Out) { Out << llvm::formatv("{0:1}\n", Document); }) ? 0 : 2;
}
