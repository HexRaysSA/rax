// What the driver does to a whole program before the emitter lowers it.
#ifndef RAX_SMIR_CLANG_PROGRAM_H
#define RAX_SMIR_CLANG_PROGRAM_H

namespace llvm {
class Module;
}

namespace smir {

// Add the program's entry, `int _start(int argc, char **argv, char **envp)`,
// if the module defines `main`. It calls `main` with as many of its three
// arguments as `main` declares and then calls `exit` with the result, as
// returning from `main` is defined to do. It is added before the libraries
// are linked, so that its reference brings in the C library's `exit` when
// there is one.
void addEntry(llvm::Module &M);

// Without a C library nothing defines `exit`: the entry then returns the
// status instead, and whoever runs the program ends it.
void finishEntry(llvm::Module &M);

// Make a call that names a function, but with pointers of other address
// spaces than the function declares, a call of that function. Clang
// declares some runtime functions itself, such as the one that registers a
// static object's destructor, and gives their function-pointer parameters
// the address space of data, while the library that defines them gives them
// that of functions. The arguments are converted between the two.
void reconcileCalls(llvm::Module &M);

// Replace every alias by what it names. The program is complete, so an alias
// is just a second name; one that other modules could see hands its name to
// a definition that had only a local one.
void resolveAliases(llvm::Module &M);

// Make the address of a label a small integer and a `goto` through such an
// address a switch over the labels it may reach.
void expandIndirectBranches(llvm::Module &M);

// Rewrite vector operations as operations on their elements.
void scalarize(llvm::Module &M);

} // namespace smir

#endif
