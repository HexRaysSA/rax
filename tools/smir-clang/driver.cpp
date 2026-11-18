// smir-clang: compile C and C++ translation units to one portable SMIR
// module fragment, or to LLVM bitcode for a library.
//
//   smir-clang [-O0|-O1|-O2|-O3|-Os|-Oz] [-std=STD] [-I DIR]... [-D MACRO]...
//              [-f...] [-W...] [--hosted] [--resource-dir DIR] [--services CATALOG]...
//              [--library FILE.bc]... [--emit-llvm FILE] [-c [--undefined FILE]]
//              -o OUTPUT INPUT...
//
// An INPUT ending in .c is C; in .cc, .cpp or .cxx, C++, compiled without
// exceptions and run-time type information unless `-fcxx-exceptions` asks
// for both; in .bc or .ll, an LLVM module to link as it is. `-std=` applies to the language it names. Clang parses and
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
// CATALOG is a runtime service catalog (services-v1.json, and
// services-v2.json for the services added since). Without one no function
// can be bound to a service.
//
// Sources are compiled as freestanding unless `--hosted` says that the
// program has a C library. That changes what the language means, not what
// the compiler may assume: `main` is then the program's entry in C++ too,
// and returns zero when control reaches its end. No library function is
// taken to be known either way.
//
// Exit status: 0 on success, 1 when a source does not compile, the
// translation units do not link, or the program uses a construct the emitter
// does not support (nothing is written), 2 on a usage or I/O error.
#include "emit.h"
#include "portable_target.h"
#include "program.h"

#include "clang/CodeGen/CodeGenAction.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/CompilerInvocation.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/DiagnosticPrinter.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace {

const char *Usage =
    "usage: smir-clang [-O<level>] [-std=STD] [-I DIR]... [-D MACRO]... [-f...] [-W...]\n"
    "                  [--hosted] [--resource-dir DIR] [--services CATALOG]... [--library FILE.bc]...\n"
    "                  [--emit-llvm FILE] [-c [--undefined FILE]] -o OUTPUT INPUT...\n";

struct Request {
  std::vector<std::string> Inputs, Libraries, Services;
  std::string Output, EmitLLVM, ResourceDir, Undefined;
  std::string Optimization = "-O2";
  std::string StandardC = "-std=c23", StandardCxx = "-std=c++23";
  std::vector<std::string> Passthrough;
  // Write the linked module as bitcode instead of lowering it.
  bool Bitcode = false;
  // The program has a C library: `main` is the program's entry in C++ as
  // in C, and falling off its end returns zero.
  bool Hosted = false;
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
      if (!Next(R.Services.emplace_back()))
        return false;
    } else if (Arg == "--library") {
      if (!Next(R.Libraries.emplace_back()))
        return false;
    } else if (Arg == "-c") {
      R.Bitcode = true;
    } else if (Arg == "--hosted") {
      R.Hosted = true;
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
               Arg.starts_with("-W") || Arg == "-w" || Arg.starts_with("-isystem") || Arg == "-nostdinc++") {
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
  bool Exceptions = Cxx && llvm::is_contained(R.Passthrough, "-fcxx-exceptions");
  std::vector<const char *> Options{
      "-triple", smir::Triple, "-x", Cxx ? "c++" : "c", (Cxx ? R.StandardCxx : R.StandardC).c_str(),
      "-emit-llvm-only", R.Optimization.c_str(),
      // No host headers, and no assumptions about what library calls do:
      // either the program is freestanding, or its library is the one it
      // is linked with, whose functions are not known to the compiler.
      R.Hosted ? "-fno-builtin" : "-ffreestanding", "-nostdsysteminc",
      // The cc1 default is position-independent code; portable modules are
      // relocated through their own records.
      "-mrelocation-model", "static"};
  if (Cxx) {
    // Exceptions are off unless asked for with `-fcxx-exceptions`, and so
    // is run-time type information, which they need. A function's static
    // variable is initialized under a guard where there is a library to
    // supply one, and without otherwise.
    if (!Exceptions)
      Options.push_back("-fno-rtti");
    if (!R.Hosted)
      Options.push_back("-fno-threadsafe-statics");
    // With exceptions Clang passes function pointers where it declared
    // data pointers, which its own check of the module refuses; the module
    // is repaired and checked once Clang has handed it over.
    if (Exceptions)
      Options.push_back("-disable-llvm-verifier");
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
  if (!M) {
    llvm::errs() << "smir-clang: " << Input << ": code generation produced no module\n";
    return M;
  }
  if (Exceptions) {
    smir::repairArguments(*M);
    if (llvm::verifyModule(*M, &llvm::errs())) {
      llvm::errs() << "smir-clang: " << Input << ": code generation produced an invalid module\n";
      return nullptr;
    }
  }
  return M;
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
  // One catalog or several: a later one adds services to the first.
  for (const std::string &Catalog : R.Services)
    if (!readServices(Catalog, Options))
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
    // In a library, each input is a translation unit, which its static
    // objects' constructors go with.
    if (R.Bitcode)
      smir::tagUnit(*Unit, Input);
    if (!Link(std::move(Unit), false))
      return 1;
  }
  if (!R.Bitcode)
    smir::addEntry(*M);
  // A library is linked for what the program lacks. Code that handles
  // exceptions comes to need the runtime under them once it is lowered, and
  // such code may itself come from a library: the libraries are linked once
  // more when the first pass has brought some in.
  std::set<std::string> Taken;
  for (int Pass = 0; Pass < 2; ++Pass) {
    bool Declared = !R.Bitcode && smir::declareExceptionRuntime(*M);
    if (Pass == 1 && !Declared)
      break;
    for (const std::string &Library : R.Libraries) {
      std::unique_ptr<llvm::Module> Unit = read(Library, Context);
      if (!Unit)
        return 2;
      smir::pruneConstructors(*Unit, *M, Taken);
      if (!Link(std::move(Unit), true))
        return 1;
    }
  }
  if (llvm::verifyModule(*M, &llvm::errs())) {
    llvm::errs() << "smir-clang: generated IR does not verify\n";
    return 1;
  }
  if (R.Bitcode) {
    smir::nameLocals(*M, R.Output);
    // What a library leaves for the program, or for another library, to
    // define. A weak reference asks for nothing.
    auto Names = [&](llvm::raw_ostream &Out) {
      for (const llvm::GlobalObject &Global : M->global_objects())
        if (Global.isDeclaration() && !Global.use_empty() && !Global.hasExternalWeakLinkage() &&
            !Global.getName().starts_with("llvm."))
          Out << Global.getName() << "\n";
    };
    if (!R.Undefined.empty() && !write(R.Undefined, Names))
      return 2;
    if (!R.EmitLLVM.empty() && !write(R.EmitLLVM, [&](llvm::raw_ostream &Out) { M->print(Out, nullptr); }))
      return 2;
    return write(R.Output, [&](llvm::raw_ostream &Out) { llvm::WriteBitcodeToFile(*M, Out); }) ? 0 : 2;
  }
  // The program is complete: what follows rewrites it into what the
  // emitter lowers.
  smir::restoreLocals(*M);
  smir::resolveWeak(*M);
  smir::finishEntry(*M);
  smir::resolveAliases(*M);
  if (std::string Refused = smir::lowerJumps(*M); !Refused.empty()) {
    llvm::errs() << "smir-clang: error: E-UNSUPPORTED-JUMP: " << Refused << "\n";
    return 1;
  }
  if (std::string Refused = smir::lowerExceptions(*M); !Refused.empty()) {
    llvm::errs() << "smir-clang: error: E-UNSUPPORTED-EXCEPTION: " << Refused << "\n";
    return 1;
  }
  smir::reconcileCalls(*M);
  smir::expandIndirectBranches(*M);
  smir::scalarize(*M);
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
