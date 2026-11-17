# smir-clang: C and C++ to portable SMIR

An out-of-tree Clang driver and LLVM-IR-to-SMIR emitter for the
`smir64-unknown-rax` target. It compiles C, and C++ without exceptions or
run-time type information, over integers, `float` and `double`, pointers,
arrays, structures, function pointers and global data to a portable SMIR
object that
`crates/smir-portable` verifies and runs.

```sh
python3 -B tools/smir-clang/smircc.py -O2 -o gcd.smo gcd.c
cat gcd.smo.index.json        # function identifiers and parameter widths
crates/smir-portable/target/debug/smir-run gcd.smo --entry-function 0 \
  --argument-bits 3000000000000000 --argument-bits 1200000000000000

python3 -B tools/smir-clang/smircc.py -O2 -o program.smo store.c order.c report.c
```

Several sources are compiled separately and linked into one object. A source
is C or, by its extension (`.cc`, `.cpp`, `.cxx`), C++. A library is compiled
once to LLVM bitcode and then supplies each program with the definitions it
uses and no others:

```sh
python3 -B tools/smir-clang/smircc.py -c -O2 -o shapes.bc area.c perimeter.cpp
python3 -B tools/smir-clang/smircc.py -O2 -o program.smo main.c --library shapes.bc
```

A program with a `main` runs as a whole:

```c
#include <smir/services.h>

int main(void) {
  uint64_t written;
  return (int)smir_file_write(SMIR_STANDARD_OUTPUT, "hello, world\n", 13, &written);
}
```

```sh
python3 -B tools/smir-clang/smircc.py -O2 -o hello.smo hello.c
crates/smir-portable/target/debug/smir-run hello.smo --program
```

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
   Each unit is optimized on its own; nothing is optimized across units. An
   input that is already LLVM bitcode or textual IR is linked as it is, and
   each `--library` is linked last, for the definitions still missing only.
   With `-c` the driver stops here and writes the linked module as bitcode.
   Otherwise the program is complete, and every alias is replaced by what it
   names. A program that defines `main` also gets its entry, `_start`,
   before the libraries are linked: it calls `main` with as many of the
   argument count, the argument vector and the environment vector as `main`
   declares, and then the C library's `exit`, or returns the status when no
   library provides one.
3. The emitter (`emit.cpp`, `emit_abi.cpp`, `emit_atomic.cpp`, `emit_calls.cpp`,
   `emit_code.cpp`, `emit_float.cpp` and `emit_memory.cpp`, over the
   shared state in `emitter.h`) lowers the module to SMIR records and writes
   a JSON fragment:
   execution types, memory layouts, functions, data segments with their
   relocations, one symbol per function and per global, the runtime helpers
   and services the functions call, the functions to run before and after
   the program, and an index of entry points.
4. `smircc.py` merges the fragment into `template.json`, which supplies the
   sections the emitter does not produce yet (manifest, ABI contract root,
   empty TLS and exception roots), writes the data, relocation and import
   records and the capabilities the imported services need, and assembles the
   object with `tools/smir-format/smir.py`.

## What compiles

Functions whose parameters and results are integers of at most 128 bits,
`float`, `double`, data pointers or function pointers, built from:

- integer arithmetic with its wrap and exact flags, shifts, comparisons
  (of integers and of pointers), `select`, `trunc`/`zext`/`sext`, `freeze`,
  phis and direct calls between functions of the program;
- `float` and `double`: arithmetic, negation, every comparison, conversion
  to and from integers and between the two, reinterpretation as an integer
  of the same width, and the intrinsics `fabs`, `sqrt`, `copysign`, `fma`,
  `fmuladd`, the `minnum`/`maxnum`, `minimum`/`maximum` and
  `minimumnum`/`maximumnum` pairs, `fptosi.sat`/`fptoui.sat` and
  `is.fpclass`, which is what `isnan`, `isinf`, `isfinite`, `isnormal` and
  `fpclassify` become;
- structures and unions passed and returned by value, at any size;
- variadic functions and calls of them, direct or through a pointer:
  `va_start`, `va_arg`, `va_copy` and `va_end`, and an argument list passed
  on to another function. A variadic argument is an integer of at most 128
  bits, a `double`, a `long double` or a pointer;
- `long double`, which is binary128, as a value: stored, loaded, passed,
  returned, negated and reinterpreted as an integer. Its arithmetic is
  emitted too, but the engine does not perform it yet and refuses an object
  that contains any;
- the overflow-checked arithmetic builtins (`__builtin_add_overflow` and its
  relatives) on integers of at most 64 bits;
- C++ classes, virtual functions with single and multiple inheritance,
  templates, lambdas, and objects whose constructors run before the program
  (`llvm.global_ctors`, which becomes the object's initializer list). A
  function's static variable is initialized without a lock;
- function pointers: the address of a function defined in the program, calls
  through a pointer, and function pointers as arguments, results,
  stored values and operands of `==` and `!=`;
- calls of the runtime services declared in `include/smir/services.h`, which
  `smircc.py` puts on the include path: reading and writing the standard
  streams, and ending the program;
- `ret`, `br`, `switch` and `unreachable`, and `llvm.trap`, which becomes a
  `trap` terminator with the reason `llvm_trap`;
- atomic and volatile access: `_Atomic` objects and the `<stdatomic.h>`
  operations in every ordering, `atomicrmw` with the integer actions and
  exchange, compare-and-exchange, fences, and `volatile` objects;
- memory: `alloca` with a constant element count, `load` and `store` of
  integers and pointers, `getelementptr`, and for data pointers `ptrtoint`,
  `ptrtoaddr` and `inttoptr`,
  the lifetime markers, and `memcpy`, `memmove` and `memset`. Arrays and
  structures therefore work, including whole-aggregate initializers,
  assignments and structure results, at every optimization level including
  `-O0`;
- global variables defined in the program, constant or mutable,
  whose initializers are integers, floats, aggregates of them, zero, undef, the
  addresses of other globals (with constant offsets, as pointers or as
  integers) and the addresses of functions. String literals and the tables
  the optimizer generates are such globals;
- these intrinsics: `ctlz`, `cttz`, `ctpop`, `abs`, `bswap`, `bitreverse`,
  `smin`/`smax`/`umin`/`umax`, `scmp`/`ucmp`, the four saturating additions
  and subtractions, and `fshl`/`fshr`, as a rotate when both values are the
  same and as two shifts otherwise.

Everything else is refused: C++ exceptions and run-time type information,
globals no unit defines, thread-local variables,
variable-length arrays, atomic arithmetic on floats, a structure as a variadic
argument, the float formats other than these three, rounding to an integral
value and the other library functions of floating point (`floor`, `pow`,
`sin`, ...), aggregate values other than the result of an overflow-checked
operation, calls to and addresses of functions no unit defines, conversions
between function
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
- **Floating point** is IEEE 754 in the default environment. The driver
  leaves contraction off, so a product and a sum are rounded separately; a
  fused multiply-add happens only where the source asks for one, and
  `llvm.fmuladd`, should it appear, is lowered as the two separate
  operations it permits. Fast-math flags have no SMIR field and are dropped,
  which refines the cases they make poison to the IEEE result. The engine
  fixes which NaN an operation returns; a native build does not, so the
  tests compare NaN results only as NaNs.
- **Virtual tables.** Clang keeps the entries of a virtual table as data
  pointers: it stores a function's address converted to the data address
  space, loads a plain pointer from the table and calls through it. A data
  pointer cannot designate a function in SMIR. The emitter therefore finds
  the data-pointer values that hold function pointers (what a call goes
  through, what an address-space conversion produces or consumes, and what
  flows between those through phis and selects) and gives them the code
  pointer type; a table entry is a `function_token` relocation. A function
  pointer that reaches such a value from anything but a load, or leaves it
  for anything but a call, a store or a comparison, is refused.
- **Constructors and destructors of globals.** Each entry of
  `llvm.global_ctors` is an initializer of the object and each entry of
  `llvm.global_dtors` a finalizer, with its priority; the engine runs them.
  A global with a destructor needs `__cxa_atexit`, which a C library
  supplies.
- **Atomics.** The target description lets Clang emit atomic accesses of up
  to sixteen bytes as instructions, and each becomes the format's atomic
  operation with its ordering. The ABI chapter instead describes a
  lock-backed implementation behind library calls, whose lock-free macros
  report zero; here they report lock-free. The engine runs one thread, so
  the choice is not yet observable in behaviour.
- **Hints.** `llvm.expect` is its argument, `llvm.is.constant` is false, and
  `llvm.objectsize` is unknown.
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
- **Aggregates by value.** Clang passes a structure by value as a pointer
  that the call is to copy (`byval`). The copy is made by the function that
  receives it: at entry it copies the object into a stack object of its own
  and its body uses that. The caller's object is therefore never changed
  through the parameter, and each activation of a recursive function has its
  own copy. A structure result is written through a hidden result pointer.
- **Variadic arguments.** A variadic function takes one more parameter than
  it declares: the address of its variadic arguments. A call stores them in
  consecutive eight-byte slots of a stack object that belongs to the call
  site, and passes that address, or a null pointer when there are none. A
  sixteen-byte argument takes two slots and starts at an address that is a
  multiple of sixteen. A `va_list` is one pointer to the next slot:
  `va_start` stores the hidden parameter in it, `va_arg` loads the slot and
  advances past it, first moving up to a multiple of sixteen for a
  sixteen-byte argument, and `va_copy` copies the pointer. Reading past the last argument is therefore
  an access outside the object and stops the program. This is the compiler's
  own convention, not the 32-byte `va_list` of the ABI chapter, which needs
  a compiler that produces its records.
- **Overflow-checked arithmetic** returns a pair in LLVM. The pair is never
  materialized: the operation computes two values, the result and the flag,
  and each `extractvalue` of it is one of them. Addition and subtraction
  test the signs or compare with an operand; multiplication computes the
  exact product in twice the width.
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
- **Runtime services.** A declared function whose link name is
  `smir.portable.v1:` followed by a service's name is that service; the
  header gives each declaration its name with an `__asm__` label. The service
  catalog, which the driver reads, fixes the types. A service returns up to
  two results and a C function one, so the declaration returns the first
  result (the status) and takes a pointer for each further one: the call
  becomes one `call` of the import with all its results, followed by a
  `store` of each further result through its pointer. A name that is no
  service, or a declaration of another shape, is refused with
  `E-SERVICE-BINDING`. The address of a service cannot be taken.
- **No source ABI records.** Functions are emitted as generic functions
  (`source_linkage` `none`, no nominal type, no ABI signature), which is what
  the specification's `generic-functions` conformance modules are.

## Tests

```sh
python3 -B -m unittest discover -s tools/smir-clang -p 'test_*.py' -v
```

`test_e2e.py` compiles every file in `tests/c` and `tests/cxx` at `-O0`, `-O1`, `-O2` and `-Os`, runs
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

Each directory under `tests/programs` is a whole program. It is compiled at
the four levels and run with `smir-run --program` on each entry of its
`runs.json`, which gives the arguments and the standard input. Standard
output, standard error and the exit status must equal those of the native
build, which takes the services from `tests/native/services.c`. One more test
runs programs that cannot complete (a buffer a service refuses, an exhausted
limit, no usable `main`) and checks the report.

Each directory under `tests/linked` is one program of several translation
units. Its units are compiled and linked into one object, and its exported
functions compared with a native build of the same units in the same way. The
header named after the directory declares them for the native harness.

Functions that take or return a pointer, which includes every variadic
function, are not called by the test directly; exported functions over
integers and floats exercise them. Nor are functions whose names begin with
two underscores, which are runtime support a source may have to define.
Another test builds a bitcode library from C and C++ and checks that a
program gets from it exactly what it uses, constructors included.

The corpus programs must be fully defined for every argument value: unsigned
arithmetic, checked divisors, masked shift amounts, bounded loops, and a
range check before a float is converted to an integer. Float arguments are
generated as encodings, so they include infinities, subnormals and NaNs. A
function must not expose the payload of a NaN it computed, because that is
the one result a native build may legitimately differ in. Each
case runs in a fresh machine while the native build calls every case in one
process, so a function that reads global state must reset it first.

This test needs the pinned LLVM build, so it is not part of the hosted
workflow.
