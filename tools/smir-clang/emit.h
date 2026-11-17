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

struct EmitOptions {
  // First identifier to use for execution types, so that they do not collide
  // with the types of the module the fragment is merged into.
  unsigned TypeBase = 2000;
};

// The emitted part of a module: execution types, functions and one symbol per
// function, plus an index of entry points by name. The caller merges this into
// a ten-root module; see smircc.py.
//
// Returns false and fills Diagnostics, leaving Fragment untouched, if the
// module uses anything outside the supported subset. The scan covers the whole
// module, so every unsupported construct is reported at once.
bool emit(const llvm::Module &M, const EmitOptions &Options, llvm::json::Object &Fragment,
          std::vector<Diagnostic> &Diagnostics);

} // namespace smir

#endif
