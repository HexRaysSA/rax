// smir-clang: compile C translation units to one portable SMIR module fragment.
//
//   smir-clang [-O0|-O1|-O2|-O3|-Os|-Oz] [-std=STD] [-I DIR]... [-D MACRO]...
//              [--resource-dir DIR] [--services CATALOG] [--emit-llvm FILE]
//              -o OUTPUT INPUT.c...
//
// CATALOG is the runtime service catalog (services-v1.json). Without it no
// function can be bound to a service.
//
// Clang parses and optimizes each source for the smir64-unknown-rax target in
// this process. The resulting LLVM modules are linked into one, which resolves
// the references between translation units, and the emitter lowers that
// module. OUTPUT is a JSON fragment (types, functions, symbols, entry index)
// that smircc.py merges into a complete module and assembles.
//
// Exit status: 0 on success, 1 when a source does not compile, the
// translation units do not link, or the program uses a construct the emitter
// does not support (nothing is written), 2 on a usage or I/O error.
#include "emit.h"
#include "portable_target.h"

#include "clang/CodeGen/CodeGenAction.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/CompilerInvocation.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/DiagnosticPrinter.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include <memory>
#include <string>
#include <vector>

namespace {

const char *Usage =
    "usage: smir-clang [-O<level>] [-std=STD] [-I DIR]... [-D MACRO]... [--resource-dir DIR]\n"
    "                  [--services CATALOG] [--emit-llvm FILE] -o OUTPUT INPUT.c...\n";

struct Request {
  std::vector<std::string> Inputs;
  std::string Output, EmitLLVM, ResourceDir, Services;
  std::string Optimization = "-O2";
  std::string Standard = "-std=c23";
  std::vector<std::string> Passthrough;
};

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
    } else if (Arg == "-I" || Arg == "-D") {
      std::string Value;
      if (!Next(Value))
        return false;
      R.Passthrough.push_back(Arg.str());
      R.Passthrough.push_back(Value);
    } else if (Arg.starts_with("-I") || Arg.starts_with("-D")) {
      R.Passthrough.push_back(Arg.str());
    } else if (Arg == "-O0" || Arg == "-O1" || Arg == "-O2" || Arg == "-O3" || Arg == "-Os" || Arg == "-Oz") {
      R.Optimization = Arg.str();
    } else if (Arg.starts_with("-std=")) {
      R.Standard = Arg.str();
    } else if (Arg.starts_with("-")) {
      return false;
    } else {
      R.Inputs.push_back(Arg.str());
    }
  }
  return !R.Inputs.empty() && !R.Output.empty();
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

// Compile one translation unit to an optimized module in Context. Returns
// null after Clang has reported why not; Status is then the exit status.
std::unique_ptr<llvm::Module> compile(const Request &R, const std::string &Input, llvm::LLVMContext &Context,
                                      int &Status) {
  std::string InternalInclude = R.ResourceDir + "/include";
  std::vector<const char *> Options{
      "-triple", smir::Triple, "-x", "c", R.Standard.c_str(), "-emit-llvm-only",
      R.Optimization.c_str(),
      // Freestanding: no host headers and no assumptions about library calls.
      "-ffreestanding", "-nostdsysteminc",
      // The cc1 default is position-independent code; portable modules are
      // relocated through their own records.
      "-mrelocation-model", "static"};
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
  std::unique_ptr<llvm::Module> M;
  for (const std::string &Input : R.Inputs) {
    int Status = 0;
    std::unique_ptr<llvm::Module> Unit = compile(R, Input, Context, Status);
    if (!Unit)
      return Status;
    if (!M) {
      M = std::move(Unit);
      continue;
    }
    // Definitions replace declarations, and local names that collide are
    // renamed. Two definitions of one external name are an error.
    Context.setDiagnosticHandler(std::make_unique<LinkDiagnostics>());
    if (llvm::Linker::linkModules(*M, std::move(Unit))) {
      llvm::errs() << "smir-clang: the translation units do not link; nothing written\n";
      return 1;
    }
  }
  if (llvm::verifyModule(*M, &llvm::errs())) {
    llvm::errs() << "smir-clang: generated IR does not verify\n";
    return 1;
  }
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
