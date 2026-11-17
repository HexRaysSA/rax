# smir-clang: C to portable SMIR

An out-of-tree Clang driver and LLVM-IR-to-SMIR emitter for the
`smir64-unknown-rax` target. It compiles C over integers, pointers, arrays,
structures, function pointers and global data to a portable SMIR object that
`crates/smir-portable` verifies and runs.

```sh
python3 -B tools/smir-clang/smircc.py -O2 -o gcd.smo gcd.c
cat gcd.smo.index.json        # function identifiers and parameter widths
crates/smir-portable/target/debug/smir-run gcd.smo --entry-function 0 \
  --argument-bits 3000000000000000 --argument-bits 1200000000000000

python3 -B tools/smir-clang/smircc.py -O2 -o program.smo store.c order.c report.c
```

Several sources are compiled separately and linked into one object.

## Requirements

- The pinned LLVM checkout (commit `36763294ef639d8a6a4379d81da653dda1c20686`)
  with a build under `build/` that contains `bin/clang++`, `bin/llvm-ar`,
  `bin/llvm-config` and the static Clang and LLVM libraries. `build.py` looks
  for it in `$SMIR_LLVM_ROOT`, then in `llvm-project` beside this repository.
  The checkout is read, never modified.
- Python 3.11 or later and, for the tests, cargo and a host C compiler.

That build directory's `opt`, `llc`, `llvm-as`, `llvm-dis` and `llvm-link` are
older LLVM 23 binaries. Nothing here runs them; all IR work happens in-process
against the pinned libraries.

## How it works

1. `portable_target.h` defines the Clang `TargetInfo` for the triple and the
   function Clang calls to create it. The pinned Clang does not know the
   target, so `build.py` links a copy of `libclangBasic.a` with its
   `Targets.cpp.o` removed and this definition takes its place.
2. `driver.cpp` runs Clang's parser, code generator and optimization pipeline
   in-process for each source and takes the resulting `llvm::Module`. No LLVM
   backend target is registered or needed for that: an unknown architecture
   gets Clang's default ABI lowering, which passes scalars directly. The
   modules are then linked into one with LLVM's IR linker: a definition
   replaces the declarations that refer to it, local names that collide are
   renamed, and two definitions of one external name are an error (`E-LINK`).
   Each unit is optimized on its own; nothing is optimized across units.
3. `emit.cpp` lowers the module to SMIR records and writes a JSON fragment:
   execution types, memory layouts, functions, data segments with their
   relocations, one symbol per function and per global, the runtime helpers
   the functions call, and an index of entry points.
4. `smircc.py` merges the fragment into `template.json`, which supplies the
   sections the emitter does not produce yet (manifest, ABI contract root,
   empty TLS, exception and capability roots), writes the data, relocation and
   import records, and assembles the object with `tools/smir-format/smir.py`.

## What compiles

Functions whose parameters and results are integers of at most 128 bits,
data pointers or function pointers, built from:

- integer arithmetic with its wrap and exact flags, shifts, comparisons
  (of integers and of pointers), `select`, `trunc`/`zext`/`sext`, `freeze`,
  phis and direct calls between functions of the program;
- function pointers: the address of a function defined in the program, calls
  through a pointer, and function pointers as arguments, results,
  stored values and operands of `==` and `!=`;
- `ret`, `br`, `switch` and `unreachable`, and `llvm.trap`, which becomes a
  `trap` terminator with the reason `llvm_trap`;
- memory: `alloca` with a constant element count, `load` and `store` of
  integers and pointers, `getelementptr`, and for data pointers `ptrtoint`,
  `ptrtoaddr` and `inttoptr`,
  the lifetime markers, and `memcpy`, `memmove` and `memset`. Arrays and
  structures therefore work, including whole-aggregate initializers,
  assignments and structure results, at every optimization level including
  `-O0`;
- global variables defined in the program, constant or mutable,
  whose initializers are integers, aggregates of them, zero, undef, the
  addresses of other globals (with constant offsets, as pointers or as
  integers) and the addresses of functions. String literals and the tables
  the optimizer generates are such globals;
- these intrinsics: `ctlz`, `cttz`, `ctpop`, `abs`, `bswap`, `bitreverse`,
  `smin`/`smax`/`umin`/`umax`, `scmp`/`ucmp`, `uadd.sat`/`usub.sat`, and
  `fshl`/`fshr` when they are rotates.

Everything else is refused: globals no unit defines, thread-local variables,
aggregates passed by value, variable-length arrays, volatile and atomic
access, floating point, aggregate values, calls to and addresses of functions
no unit defines, variadic functions and calls, conversions between function
pointers and integers or data pointers, ordered comparisons of function
pointers, inline assembly and all other intrinsics. The emitter scans the
whole module, reports every unsupported construct with a stable `E-...` code,
and writes nothing if there is any.

## Choices that differ from LLVM IR

- **Dropped poison flags.** SMIR has no field for `disjoint` on `or`,
  `samesign` on `icmp`, `nneg` on `zext` or `nuw`/`nsw` on `trunc`, and value
  range attributes have no counterpart. They are dropped. This is a
  refinement: where LLVM would produce poison, the SMIR operation produces a
  defined value.
- **Calling conventions.** The optimizer moves internal functions to `fastcc`
  or `coldcc`. A portable call is logical, so these are emitted as ordinary
  calls. A call whose convention differs from its callee's is refused.
- **Global data.** Each global becomes one data segment and one data symbol.
  Bytes the initializer does not cover, such as padding, start undef; a
  `zeroinitializer` defines every byte. The address of a global inside an
  initializer becomes a `data_address` relocation, or `data_integer` when it
  is converted to an integer. In code, the address of a global is an
  `address_of` operation at the start of the entry block; a constant offset
  from it is a `ptr_offset` with no in-bounds promise.
- **Aggregates by value** would need the call to copy the object (`byval`).
  That is not modelled yet, so such parameters are refused. Structure results
  use a hidden result pointer and work.
- **Constants.** SMIR operands are always values, so each constant becomes a
  `constant` operation at the start of the entry block, once per function.
- **Address arithmetic.** Each `getelementptr` index becomes its own
  `ptr_offset` step, in index order, carrying the instruction's `inbounds`,
  `nuw` and `nusw` promises; a variable index is sign-extended and multiplied
  by its stride under the same no-wrap promises. An `inbounds` instruction
  whose indices are all variable keeps its base pointer when they are all
  zero at run time, through a `select`, because that case promises nothing.
- **Stack objects** are calls to the runtime's `stack_alloc` helper and end
  when their function returns. Lifetime markers become the `lifetime_start`
  and `lifetime_end` helpers over the whole object.
- **Unreachable blocks** are not emitted; the format requires every block to
  be reachable.
- **Switch cases** are written in ascending unsigned order, as the format
  requires, whatever order the source or the optimizer left them in.
- **Signatures** never mark a parameter or result `noundef`. A call through a
  pointer must name exactly its callee's signature, and the optimizer infers
  `noundef` on definitions in ways a call site cannot see. Leaving it out is
  a refinement: a poison argument or result flows on instead of being
  undefined at the call boundary, and the faults `ub_noundef_argument` and
  `ub_noundef_result` do not arise in compiled C.
- **Function pointers.** LLVM pointers are untyped, SMIR code pointers carry
  a signature. Every function pointer value therefore has one type, a pointer
  to a function of no parameters and no results. Taking a function's address
  is `address_of`, which yields a pointer of the function's own signature,
  then a `bitcast` to that common type; the address is computed once per
  function at the start of the entry block. A call through a pointer is a
  `bitcast` to a pointer of the signature the call uses, then an indirect
  `call`. The engine checks that signature against the function the pointer
  designates, so a call through a pointer converted to another function type
  stops with `code_token_signature`, and a null pointer with
  `code_token_invalid`. A function address in an initializer is a
  `function_token` relocation; a pointer loaded from it designates the
  function, while bytes that merely equal a token do not
  (`code_token_stale`).
- **No source ABI records.** Functions are emitted as generic functions
  (`source_linkage` `none`, no nominal type, no ABI signature), which is what
  the specification's `generic-functions` conformance modules are.

## Tests

```sh
python3 -B -m unittest discover -s tools/smir-clang -p 'test_*.py' -v
```

`test_e2e.py` compiles every file in `tests/c` at `-O0`, `-O1`, `-O2` and `-Os`, runs
each exported function on generated argument vectors in `smir-run`, and
compares each result with a native build of the same source. The native build
runs under the undefined behaviour sanitizer, so a corpus program that is not
fully defined on some vector fails the test. A sample of the same runs is also
compared, step count included, with the Python reference machine. A further
test compiles programs that go wrong at run time (out-of-bounds and stale
accesses, writes to constants, null and forged pointers, null, forged and
wrongly typed function pointers, division faults, poison results, traps,
runaway recursion and loops) and checks the fault each
one stops with. Three more check that unsupported constructs, source errors
and units that do not link are refused with nothing written.

Each directory under `tests/linked` is one program of several translation
units. Its units are compiled and linked into one object, and its exported
functions compared with a native build of the same units in the same way. The
header named after the directory declares them for the native harness.

The corpus programs must be fully defined for every argument value: unsigned
arithmetic, checked divisors, masked shift amounts and bounded loops. Each
case runs in a fresh machine while the native build calls every case in one
process, so a function that reads global state must reset it first.

This test needs the pinned LLVM build, so it is not part of the hosted
workflow.
