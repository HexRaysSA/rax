# smir-clang: C and C++ to portable SMIR

An out-of-tree Clang driver and LLVM-IR-to-SMIR emitter for the
`smir64-unknown-rax` target. It compiles C and C++ over integers, `float`
and `double`, pointers, arrays, structures, function pointers and global
data to a portable SMIR object that `crates/smir-portable` verifies and
runs.

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
   A library keeps to what an archive of object files would do, though it is
   one module. Each definition is marked with the source file it came from,
   and the constructor of a static object is linked only into a program
   that takes something from the same file, or from a file whose own
   constructors need it (`pruneConstructors` in `program.cpp`); without
   that, every program would construct every static object of the library
   and carry all that the constructors refer to. And a library's local
   definitions are written under names no other module has
   (`name.smir.local.<hash>`) as external ones, since LLVM's linker copies a
   module's local definitions every time it takes anything from the module:
   a library linked twice into one program, as happens for the runtime
   under exceptions, would have two of each of its static variables. In the
   complete program they are local again.
   Otherwise the program is complete, and every alias is replaced by what it
   names, and every vector operation by operations on its elements (LLVM's
   scalarizer, after its expansion of vector reductions): the optimizer
   makes vectors even of scalar code, for instance when it copies a
   structure of two doubles. Labels whose address is taken are numbered,
   and a `goto` through such an address becomes a switch. These rewrites
   are in `program.cpp`. A program that defines `main` also gets its entry, `_start`,
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
  bits, a `double`, a `long double`, a pointer or a structure;
- `long double`, which is binary128;
- vector types inside a function: the vector extensions of GNU C, element
  access, shuffles, conversions and reductions. A vector cannot be a
  parameter or a result;
- the overflow-checked arithmetic builtins (`__builtin_add_overflow` and its
  relatives) on integers of at most 64 bits;
- C++ classes, virtual functions with single and multiple inheritance,
  templates, lambdas, and objects whose constructors run before the program
  (`llvm.global_ctors`, which becomes the object's initializer list), and
  pointers to member functions, at `-O1` and above: without optimization
  Clang loads and stores such a pointer as one value of two fields, which
  is not lowered. A function's static variable is initialized under a guard
  when the program is hosted (see "C++" below) and without a lock otherwise;
- weak references: the address of a weak function or variable that nothing
  in the program or its libraries defines is null;
- thread-local variables (`_Thread_local`, `thread_local`) with constant
  initializers that hold no address;
- function pointers: the address of a function defined in the program, calls
  through a pointer, function pointers as arguments, results,
  stored values and operands of `==` and `!=`, and conversions between a
  function pointer and `void *` or an integer, as a callback with an untyped
  payload makes them;
- calls of the runtime services declared in `include/smir/services.h`, which
  `smircc.py` puts on the include path: reading and writing the standard
  streams, reading clocks, ending the program, mapping memory, starting and
  joining threads, and waiting on a word of memory;
- `ret`, `br`, `switch` and `unreachable`, and `llvm.trap`, which becomes a
  `trap` terminator with the reason `llvm_trap`;
- labels as values: `&&label` in a static table and `goto *address`;
- atomic and volatile access: `_Atomic` objects and the `<stdatomic.h>`
  operations in every ordering, `atomicrmw` with the integer actions and
  exchange, compare-and-exchange, fences, and `volatile` objects;
- memory: `alloca`, including variable-length arrays and
  `__builtin_alloca`, `load` and `store` of
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

Everything else is refused: globals no unit defines, thread-local variables whose initializer holds an
address or runs code,
atomic arithmetic on floats,
the float formats other than these three, rounding to an integral
value and the other library functions of floating point (`floor`, `pow`,
`sin`, ...), aggregate values other than the result of an overflow-checked
operation, calls to and addresses of functions no unit defines, conversions
between function
pointers and integers or data pointers, ordered comparisons of function
pointers, inline assembly other than an empty statement, and all other
intrinsics. The emitter scans the
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
  pointer type; a table entry is a `function_token` relocation, and a
  function's address converted to an integer in an initializer, as in a
  constant pointer to a member function, a `function_integer` relocation.
- **Function pointers as data pointers and integers.** Where a function
  pointer converted to `void *` travels as one (it is an argument, a result,
  or reaches anything else that only takes a data pointer), the values
  connected to it stay data pointers. The conversion is then real:
  `ptrtoint` of the function pointer, which exposes the function, and
  `inttoptr` to a data pointer, which designates no object and holds the
  function's token as its address. The conversion back is `ptrtoint` of
  that and `inttoptr` to a code pointer, which designates the function
  because it was exposed. A conversion to or from an integer in the source
  is the one operation. A comparison of such a data pointer with a value
  that was given the code pointer type compares both as data pointers.
- **Thread-local variables.** Each is a thread-local segment of the object,
  with its initial image, and a `tls` symbol. `llvm.threadlocal.address`,
  through which LLVM reaches every such variable, is a `call` of an import
  of the `tls_address_raw` helper whose target is that segment, with offset
  zero; there is one such import for each variable a function uses. The
  engine gives every thread its own copy of a segment when the thread first
  asks for its address.
- **Exceptions.** See "Exceptions" under "The C library".
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
- **Inline assembly** has no meaning for a portable program and is refused,
  except the empty statement that C code uses as an optimization barrier,
  which is nothing by the time the emitter sees it.
- **Labels as values.** The format has no relocation that writes a label's
  address into data, where C code keeps such addresses. So each label of a
  function whose address is taken gets a number, from one; its address is
  that number as a pointer, and `goto *address` is a switch on the number
  over the labels the statement may reach. An address that is none of them
  reaches `unreachable`. Clang itself emits invalid IR for a label address
  used outside a static initializer on a target whose code is in its own
  address space, so only tables are supported.
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
  sixteen-byte argument, and `va_copy` copies the pointer. A structure is
  passed as a pointer to a copy the call makes; `va_arg` reads the pointer
  and the callee copies again. Reading past the last argument is therefore
  an access outside the object and stops the program. This is the compiler's
  own convention, not the 32-byte `va_list` of the ABI chapter, which needs
  a compiler that produces its records.
- **Overflow-checked arithmetic** returns a pair in LLVM, and so does a
  compare-and-exchange. The pair is never
  materialized: the operation computes two values, the result and the flag,
  and each `extractvalue` of it is one of them. A phi that merges such pairs
  around a loop is two phis. Addition and subtraction
  test the signs or compare with an operand; multiplication computes the
  exact product in twice the width, or, for an unsigned 128-bit product,
  divides it by one factor and compares with the other.
- **Constants.** SMIR operands are always values, so each constant becomes a
  `constant` operation at the start of the entry block, once per function.
- **Address arithmetic.** Each `getelementptr` index becomes its own
  `ptr_offset` step, in index order, carrying the instruction's `inbounds`,
  `nuw` and `nusw` promises; a variable index is sign-extended and multiplied
  by its stride under the same no-wrap promises. An `inbounds` instruction
  whose indices are all variable keeps its base pointer when they are all
  zero at run time, through a `select`, because that case promises nothing.
- **Stack objects** are calls to the runtime's `stack_alloc` helper and end
  when their function returns. That holds for a variable-length array too:
  `llvm.stacksave` and `llvm.stackrestore`, which would end it with its
  scope, are dropped, so one declared in a loop is a new object on every
  iteration and all of them stay until the function returns. Lifetime markers become the `lifetime_start`
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
  `store` of each further result through its pointer. A declaration that
  has no use for the further results leaves those pointers out. A service
  parameter that is a code pointer is a function pointer of any type in the
  declaration. A name that is no service, or a declaration of another
  shape, is refused with `E-SERVICE-BINDING`. The address of a service
  cannot be taken.
- **No source ABI records.** Functions are emitted as generic functions
  (`source_linkage` `none`, no nominal type, no ABI signature), which is what
  the specification's `generic-functions` conformance modules are.

## The C library

```sh
python3 -B tools/smir-clang/smircc.py --hosted -O2 -o program.smo program.c
crates/smir-portable/target/debug/smir-run program.smo --program -- arguments
```

`--hosted` compiles against the C library's headers and links the library.
The library is LLVM libc from the pinned checkout, built by
`sysroot/build_libc.py` the first time it is needed, into
`crates/smir-portable/target/smir-sysroot`: generated public headers under
`include/` and the library as bitcode, `lib/libc.bc`, from which a program
takes what it uses. It needs a Python with PyYAML for LLVM libc's header
generator and takes about ten seconds.

What is built is LLVM libc's freestanding configuration: the entry points its
list for 32-bit Arm names unconditionally, about 650 functions of `ctype.h`,
`string.h`, `stdlib.h`, `stdio.h`, `inttypes.h`, `math.h`, `time.h` and
others, compiled as LLVM's own build compiles them. The differences are few
and all outside the checkout:

- `sysroot/platform.c` is the embedder's side, over the runtime services: the
  standard streams (unbuffered), `exit`, `_Exit`, the error number and the
  clocks.
- `sysroot/threads.c` is `pthread.h`, `threads.h` and `sched.h`, whose
  headers are in `sysroot/overlay`; see "Threads" below. LLVM libc's own
  threads are written for the Linux kernel.
- The heap is one zero-filled object of one mebibyte that `malloc` carves up.
  LLVM libc's freestanding heap is for one thread, so its entry points are
  built under their internal names and `sysroot/allocator.cpp` defines
  `malloc`, `free` and the others around them, one caller at a time.
- `errno.h` names every error number of the portable catalog
  (`errno-v1.json`), which are those of Linux; LLVM libc's header for an
  unknown system has only the few ISO C requires.
- `sysroot/overlay` defines `fenv_t`, which LLVM libc defines per
  architecture.
- `printf` converts floating point, which the freestanding configuration
  turns off to save space.
- `setjmp`, `longjmp` and `memset_explicit` are written in assembly, and
  `localtime` does not compile at the pinned revision; they are left out.
  There is no file system, so no `fopen`.

`long double` works through `printf`, `scanf` and `strtold`, since the engine
computes binary128. `test_hosted.py` runs the programs of the repository's
morok corpus (`tests/fixtures/user/linux/programs`) against the standard
output and exit status recorded for them on Linux: 81 of the 97 match, 69 of
the 81 in C and 12 of the 16 in C++. The others are listed in the test with
their causes. In C: seven need operating system services, two `setjmp`, and
one each `clock_gettime`, `time` and `localtime`, and a float-to-integer
conversion that is out of range and so undefined. In C++: one reads a file,
one divides by the number of processors, which the library does not know
here, and two print what no other build would print either: the hash of a
type, which is an address, and a sum that depends on the order in which a
vector destroys its elements, which libc++ has changed since the recording.
The test fails if one of them starts to match.

### C++

A C++ source compiled with `--hosted` gets libc++'s headers, from the pinned
checkout, ahead of the C library's, and is linked with `lib/libc++.bc` as
well. That library is the part of libc++ that is compiled separately, as far
as it goes here: strings and their conversions, `charconv`, what `format`
and `print` need, regular expressions, containers, algorithms,
`std::function`, `any`, `optional`, `variant`, `chrono`, the exception
classes, memory resources, the stream classes with the locale under them,
and threads, mutexes, condition variables, `call_once`, promises and futures
over the `pthread.h` above. What is left out needs files, a source of random
numbers or time zones. A program takes from it what it uses. C++ with a
library is compiled with exceptions and run-time type information, as the
library is.

- libc++ is configured (`__config_site`, written by `build_libc.py`) for
  LLVM libc, pthreads, localization, no wide characters, no file system and
  no random device. `iostream`, `sstream` and `iomanip` work, over the
  standard streams and over strings, in the one locale there is, "C".
  `fstream` does not compile: there are no files to open.
- The standard streams are objects with static storage that the library
  constructs before `main`. Only a program that names a stream gets that
  constructor, and with it the locale and its facets, which are most of
  such a program: "hello" through `printf` is 48 functions, and through
  `std::cout` 571.
- Under it, in place of libc++abi's unwinder, is `sysroot/exceptions.cpp`
  (see "Exceptions" below), with libc++abi's own sources for what describes
  types: `dynamic_cast`, `typeid`, the choice of a handler by type, and the
  standard exception classes.
- `sysroot/cxx.cpp`, in the C library, has what C++ needs with no C++
  library: storage functions behind `new` and `delete` that end the program
  when storage runs out, the guard of a function's static variable, the
  function a pure virtual call reaches, and `__dso_handle`. A program
  linked with libc++ gets libc++abi's storage functions instead, which call
  the new-handler and throw `bad_alloc`.
- The guard (`__cxa_guard_acquire` and its two companions) keeps its state
  in the guard variable itself and waits with `sync.wait32`, so that the
  first thread to reach a static variable initializes it and the others
  wait for that; if the initializer throws, the next thread tries again.
- The destructor of an object with static storage is registered with the C
  library's `__cxa_atexit` and runs at `exit`, after the functions
  registered later and before those registered earlier.
- Clang declares `__cxa_atexit` itself, with a destructor parameter in the
  address space of data, while the library defines it with a function
  pointer. The driver makes such a call a call of the function as defined
  and converts the arguments (`reconcileCalls` in `program.cpp`).
- `main` is the entry in C++ as in C: sources are compiled as hosted, which
  tells the compiler nothing about what library functions do.

`test_hosted.py` also compiles the programs of `tests/cxxlib` (containers
and strings, the library's threads and futures, objects with static
storage, exceptions, run-time type information, streams, text (`charconv`,
`format`, `print` and `regex`), and what the language leaves to its runtime:
pointers to member functions, static variables that several threads reach
at once, storage that runs out) and compares what
they write and return with builds by the host's compiler and library, on
both engines. It checks as well that a program without streams carries none
of them, and that a library linked twice constructs its objects once.

### Exceptions

A portable module has no stack an unwinder could walk, and the engines know
nothing of exceptions. The compiler makes them ordinary control flow
instead, in one pass over the whole program (`exceptions.cpp`):

- A thread-local flag, `__smir_unwinding`, is set while an exception
  propagates. `__cxa_throw` records the exception, sets the flag and
  returns; the code after it returns to its caller in turn.
- Every call that may throw, in a function that may let an exception out,
  is followed by a test of the flag. If it is set, the function returns at
  once, with a value that means nothing. Functions that cannot throw, which
  is all of C, are not touched.
- An `invoke` is a call followed by the same test, which goes to the landing
  pad. A landing pad asks the runtime which of its clauses catches the
  exception (`__smir_select`, which uses libc++abi's type descriptions). If
  none does and the pad has no cleanup, the function returns as above;
  otherwise the flag is cleared and the pad runs. `resume` sets the flag
  again and returns.
- The number by which a pad's code recognizes a caught type
  (`llvm.eh.typeid.for`) is given out by the pass.
- At the program's entry an exception that nothing caught ends the program
  with a message, through `abort`. So does one that leaves a thread's
  function: the C library, to which that function returns, calls the
  runtime's `__smir_thread_returned` if the program has one. The reference
  is weak, so a program without exceptions has nothing of this.

What this costs is a load and a branch after each call that may throw, and
nothing where nothing can. What it does not do: exception specifications
with a list of types, which C++17 removed, are refused.

Clang passes function pointers to `__cxa_throw` and `__cxa_atexit` as data
pointers, and for `__cxa_throw` without converting them, which its own check
of the module rejects on this target. With exceptions on, the driver turns
that check off, repairs the arguments (`repairArguments`) and checks the
module itself.

`abort` ends the program through the runtime's `process.abort`, so that
whoever runs it sees an abort (status 134 from `smir-run`), where LLVM libc
would execute a trap.

### Threads

A program's threads are threads of the runtime: each runs on a host thread of
its own, in parallel with the others. `pthread.h` has threads (create, join,
detach, exit, self, the detach state and stack size attributes), mutexes of
the normal, recursive and error-checking kinds with `trylock` and
`timedlock`, condition variables with `timedwait`, `pthread_once`,
read-write locks, and thread-specific keys with their destructors.
`threads.h` is ISO C's interface to the same objects, with
`thrd_sleep` and `tss_t`. `errno` is each thread's own. Everything that blocks does so in the runtime's `sync.wait32`,
on a word of the object it waits for, after an atomic operation found that it
must; an uncontended lock or unlock is one atomic operation and no service
call. Not there: cancellation and scheduling parameters.

What differs from a POSIX system:

- The program ends when `main` returns or any thread calls `exit`; the other
  threads are stopped where they are. `pthread_exit` in the first thread ends
  the program with status 0 without waiting for the others.
- A thread's result travels as 64 bits, so a pointer a thread returns must
  point into an object that is still there when it is joined: the stack of
  the thread is not.
- A program all of whose threads wait for one another is stopped and
  reported as a deadlock.
- `rand`, `strtok` and the functions registered with `atexit` are for one
  thread at a time, as in LLVM libc's freestanding configuration.

## Tests

```sh
python3 -B -m unittest discover -s tools/smir-clang -p 'test_*.py' -v
```

`test_threads.py` compiles the programs of `tests/threads` (shared counters
under a mutex and with atomics, a bounded queue with condition variables,
every kind of mutex, once, read-write locks, the allocator under several
threads, threads that only finish if they run at the same time) and compares
their output with native builds of the same sources; the ISO C threads
program has its expected output beside it, since the host of the tests need
not have `threads.h`. Each runs several times at two levels. One test times
a sum that four threads share against the same sum by one, and requires the
four to be faster. Further
programs race on a counter, read the stack of a thread that has ended,
deadlock, and end while a thread still runs; each must be reported as what it
is. One of the compared programs is about what a thread has of its own:
thread-local variables, `errno`, and its values for keys.

`test_e2e.py` compiles every file in `tests/c` and `tests/cxx` at `-O0`, `-O1`, `-O2` and `-Os`, runs
each exported function on generated argument vectors in `smir-run`, and
compares each result with a native build of the same source. Every run in
these tests is made twice, interpreted and with `smir-run --native`, and the
two must report the same, down to the number of steps. The runner is built
for the host; with `SMIR_RUN_TARGET` set to another Rust target the machine
can run, the tests use a runner built for that one, which is how x86-64
native code is tested on Apple silicon, under Rosetta:

```sh
SMIR_RUN_TARGET=x86_64-apple-darwin python3 -B -m unittest discover -s tools/smir-clang -p 'test_*.py'
``` The native build
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
program gets from it exactly what it uses, constructors included; a third,
that a static object of a library is constructed exactly when the program
takes something from the file that defines it, directly or through another
constructor.

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
