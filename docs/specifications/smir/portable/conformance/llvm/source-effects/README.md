# Structural source-effect witnesses

This package tests the pinned LLVM parser/optimizer against the selected partial
LLVM018 REV3 compiler-IR contract. It implements no SMIR target, emitter, helper
registry, private issuer, source admission or execution engine. The address space
and DataLayout in the IR are existing native-target structural test choices;
they do not assign a portable program address space.

`effects.ll` preserves unused observing exposure, real descriptor operands,
conservative effects, and a `noinline optnone` wrapper. Its single source-object
begin consumes actual opaque Journal SSA and returns new Scope SSA used by
publish. There is no prior scope reservation or outcome-free exit helper. The
one-byte Ref globals are deliberately **invalid RAX descriptors**: LLVM syntax
acceptance cannot establish source context, plan identity or runtime authority.

`binding-group.ll` passes and returns an aggregate of two opaque Binding values
without sizing/storing them, retaining one call per group exposure/recovery.
Generated negative IR tests reject missing `noinline` with `optnone`, allocation
of an unsized Binding, and a vector of unsupported opaque Binding elements.

`byte-relay.cpp` shows an unresolved producer boundary: O0/O1 external character
relay remains `i8 -> i8` with `i8` loads/stores. Local raw-byte load/store lowering
alone cannot pass origins through an unchanged numeric Int8 ABI. The local relay
may optimize away. These observations prove neither ISO source-definedness nor
portable provenance preservation. Exact source-character/ABI/native transport,
Exception/outcome exits and object-end interfaces remain separate blockers.

From any working directory:

```sh
SMIR_LLVM_ROOT=/Users/int/dev/llvm-project \
SMIR_RECORD_WITNESS_DIR=/tmp/rax-portable-smir-01/LLVM/source-effect-runs \
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover \
  -s /Users/int/dev/rax3/tools/smir-llvm-contract -p test_source_effects.py -v
```

There are seven methods and eight actual compiler invocations. Missing tools,
pin mismatch, changed compiler/source inputs, timeout or unexpected acceptance
fail rather than skip. `SMIR_LLVM_BIN` can select the actual compiler directory;
`LLVM_REFERENCE_CHECKOUT` is a compatible source-root override, and conflicting
source roots reject. The compiler must report LLVM24 and the exact pinned commit.
All five package files, compiler bytes and source HEAD are checked before/after.

Outputs use a unique retained child of `SMIR_RECORD_WITNESS_DIR`, resolved before
writes; paths or symlinks inside either source checkout reject. The child retains
actual copied inputs/mutants, commands, stdout/stderr, output IR and
`observations.json` with hashes and explicit evidence scope. Existing full LLVM
validation discovers the top-level test module without a runner change. No source
program is executed, no native lowering/linking is requested, and no parser result
is treated as actual helper semantic verification or compiler freeze.

Assumptions: the actual compiler matches the pinned source (version, binary and
HEAD guard); opaque SSA/effect behavior remains supported (positive and rejection
probes); source byte transport needs an explicit rule (numeric versus raw and
external relay falsifiers). Observation storage is proportional to retained input
and output bytes; compiler resource complexity and runtime performance are not
measured. High impact: false authority/provenance inference. Medium: effect loss
or incorrect output isolation. Low: no performance qualification.
