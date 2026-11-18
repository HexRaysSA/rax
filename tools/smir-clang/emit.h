// Lowering from an LLVM module to portable SMIR records.
#ifndef RAX_SMIR_CLANG_EMIT_H
#define RAX_SMIR_CLANG_EMIT_H

#include "llvm/Support/JSON.h"
#include <string>
#include <vector>

namespace llvm {
class Module;
}

namespace smir {

// A construct the emitter does not lower. Nothing is emitted when any exist.
struct Diagnostic {
  std::string Code;     // Stable identifier, for example E-UNSUPPORTED-INSTRUCTION.
  std::string Function; // Enclosing function, or empty for module-level findings.
  std::string Detail;
};

// One runtime service of the catalog, as far as lowering needs it: its name
// and the catalog's names for the types of its parameters and results.
struct Service {
  std::string Name;
  std::vector<std::string> Params, Results;
};

struct EmitOptions {
  // First identifier to use for execution types and for memory layouts, so
  // that they do not collide with those of the module the fragment is merged
  // into.
  unsigned TypeBase = 2000;
  // The runtime services a program may call. A declared function whose link
  // name is ServiceNamespace, a colon and a service's name is that service.
  std::string ServiceNamespace = "smir.portable.v1";
  std::vector<Service> Services;
  // What each module this one depends on offers: the link names of its
  // functions, one list for each dependency in the order of their slots. A
  // call of a function that this module declares and does not define, and
  // that a dependency offers, is a call of that module's function; the
  // first dependency that offers the name is the one.
  std::vector<std::vector<std::string>> Dependencies;
};

// The emitted part of a module: execution types, memory layouts, functions and
// one symbol per function, the runtime helpers and services they call (by
// name; the caller assigns import identifiers), the functions of each
// dependency they call (by name, with the signature each is called through;
// a call names one by its dependency's slot and its position in that list),
// plus an index of entry points by name. The caller merges this into a
// ten-root module; see smircc.py.
//
// Returns false and fills Diagnostics, leaving Fragment untouched, if the
// module uses anything outside the supported subset. The scan covers the whole
// module, so every unsupported construct is reported at once.
bool emit(const llvm::Module &M, const EmitOptions &Options, llvm::json::Object &Fragment,
          std::vector<Diagnostic> &Diagnostics);

} // namespace smir

#endif
