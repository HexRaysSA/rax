// smir-clang: compile one C translation unit to a portable SMIR module fragment.
//
//   smir-clang [-O0|-O1|-O2|-O3|-Os|-Oz] [-std=STD] [-I DIR]... [-D MACRO]...
//              [--resource-dir DIR] [--emit-llvm FILE] -o OUTPUT INPUT.c
//
// Clang parses and optimizes the source for the smir64-unknown-rax target in
// this process, and the emitter lowers the resulting LLVM module. OUTPUT is a
// JSON fragment (types, functions, symbols, entry index) that smircc.py merges
// into a complete module and assembles.
//
// Exit status: 0 on success, 1 when the source does not compile or uses a
// construct the emitter does not support (nothing is written), 2 on a usage
// or I/O error.
#include "emit.h"
#include "portable_target.h"

#include "clang/CodeGen/CodeGenAction.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/CompilerInvocation.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include <memory>
#include <string>
#include <vector>

namespace {

const char *Usage =
    "usage: smir-clang [-O<level>] [-std=STD] [-I DIR]... [-D MACRO]... [--resource-dir DIR]\n"
    "                  [--emit-llvm FILE] -o OUTPUT INPUT.c\n";

struct Request {
  std::string Input, Output, EmitLLVM, ResourceDir;
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
    } else if (Arg.starts_with("-") || !R.Input.empty()) {
      return false;
    } else {
      R.Input = Arg.str();
    }
  }
  return !R.Input.empty() && !R.Output.empty();
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

} // namespace

int main(int Count, char **Args) {
  Request R;
  if (!parse(Count, Args, R)) {
    llvm::errs() << Usage;
    return 2;
  }
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
  Options.push_back(R.Input.c_str());

  auto Invocation = std::make_shared<clang::CompilerInvocation>();
  clang::CompilerInstance CI(Invocation);
  CI.setVirtualFileSystem(llvm::vfs::getRealFileSystem());
  CI.createDiagnostics();
  if (!clang::CompilerInvocation::CreateFromArgs(*Invocation, Options, CI.getDiagnostics()))
    return 2;

  llvm::LLVMContext Context;
  clang::EmitLLVMOnlyAction Action(&Context);
  if (!CI.ExecuteAction(Action) || CI.getDiagnostics().hasErrorOccurred())
    return 1;
  std::unique_ptr<llvm::Module> M = Action.takeModule();
  if (!M) {
    llvm::errs() << "smir-clang: code generation produced no module\n";
    return 1;
  }
  if (llvm::verifyModule(*M, &llvm::errs())) {
    llvm::errs() << "smir-clang: generated IR does not verify\n";
    return 1;
  }
  if (!R.EmitLLVM.empty() && !write(R.EmitLLVM, [&](llvm::raw_ostream &Out) { M->print(Out, nullptr); }))
    return 2;

  llvm::json::Object Fragment;
  std::vector<smir::Diagnostic> Diagnostics;
  if (!smir::emit(*M, smir::EmitOptions(), Fragment, Diagnostics)) {
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
