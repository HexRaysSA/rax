# Implementation packages and exit conditions

Dependencies:

```text
P0 inventory -> P1 specification -> P2 codec/verifier
                                             |
                                  P3 parallel memory/runtime
                                             |
                                    P4 interpretation
                                             |
                         +-------------------+-------------------+
                         |                   |                   |
                     P5 JIT              P6 LLVM             P7 linking
                         +-------------------+-------------------+
                                             |
                                    P8 hosted runtime
                                             |
                                    P9 foreign C++
                                             |
                                    P10 launch/embedding
                                             |
                                    full qualification
```

The graph records logical dependencies between packages. Work proceeds in the
order given under "Implementation order" below, which runs an end-to-end slice
first. No package waits for a contract freeze.

P0: Record baselines and worktree ownership. Inventory SMIR operands/metadata,
architectural dependencies, LLVM constructs and personality serialization
assumptions. Map every requirement to implementation/test ownership.
Exit: finite requirement matrix with no unowned capability.

P1: Complete chapters, operation/ABI/import/descriptor/section schemas and stable
registries. Produce independent layout and semantic witnesses. Reconcile
contradictions. Exit: all compiler-facing decisions fixed, candidate hash and
reference vectors; pure constant-initialization, external-TLS, partial-construction
journals and retained source lifecycle metadata are included. Exact-candidate
review and coherent independent qualification are recorded externally rather than
in the immutable contract bytes.

P2: Independent Rust/C++ codecs, verifier, assembler/disassembler/inspection,
archive integration and mutation corpus. Separate framing from semantic/type/
CFG validation and executable admission. Exit: identical canonical output and
accept/reject behavior plus complete static semantic verifier conformance.
Otherwise valid supported grammar must not remain excluded by temporary finite
success-profile guards at this exit. Unresolved provider, native and live lifetime
requirements remain explicit; static verification does not discharge them.

P3: Per-thread execution ownership, synchronized process objects, guarded memory,
alias-aware atomics, mapping/code lifetime, worker scheduling, waits/safepoints,
callbacks, signal/debugger coordination and fresh-runtime process cloning.
Exit: race/lifetime protocols verified without a global execution lock.

P4: Portable state, activation frames, typed calls/results, indirect signatures,
phi semantics, stack/TLS/fenv, faults and exceptions. Audit reusable OpKinds.
Exit: hand-authored executable images run independently of LLVM.

P5: Both host lowerers, register allocation, helpers, phi cycles, state maps,
precise transitions, concurrent compilation/reclamation and six-host qualification.
Exit: actual native execution and fault/exception/side-effect parity.

P6: Target/triple, TargetInfo/ABI, DataLayout/macros, legalization/IR emission,
coverage matrix, diagnostics, object reader, Clang driver and dedicated sysroot.
Exit: direct SMIR compiler output, layout witnesses, no ISA-lift detour.

P7: Symbols/relocations, archives, COMDAT/weak behavior, dependencies,
constructors, dynamic load/unload leases, debug/provenance and LTO.
Exit: separately compiled modules remain compatible across invocations.

P8: Port LLVM libc/compiler-rt/libc++abi/libc++, logical unwinder, thread/TLS/fenv/
setjmp support and OS service adapters. Separate upstream gaps from port gaps.
Exit: hosted suites under all personalities in interpreter/JIT modes.

P9: Generate typed ABI descriptors and adapters; implement C/varargs/callbacks,
C++ objects/ownership/RTTI and mixed-frame two-phase EH/nonlocal exit.
Exit: bidirectional nested transitions and registered type/exception identity.

P10: All carriers, explicit loader, installed-runtime bootstrap, embedded runtime,
C/C++ embedding API, signing/stripping retention and backward compatibility.
Exit: all launch forms and six native host lanes qualified.

No package is complete because its document exists. A package is complete when
its exit test runs.

## Implementation order

The first specification run produced these chapters, the wire format, a static
verifier and a Python reference interpreter, and no production interpreter, JIT,
runtime or emitter. Implementation now proceeds as one stream of milestones.
Each milestone ends in a test that runs a program. Contracts are settled by
those tests; a chapter that disagrees with working code is corrected in the
same change.

| Milestone | Scope | Exit test |
|---|---|---|
| M0 | Portable work under version control, observed test baseline, freeze gate removed | Branch exists; baseline results recorded |
| M1 | Typed in-memory IR and a scalar interpreter in `crates/smir-portable` (P4, first part) | Every object the Python reference CLI can run returns identical result bytes from the Rust runner |
| M2 | Out-of-tree Clang driver and IR-to-SMIR emitter for scalar C (P6, first part) | Scalar C programs built at `-O1` and `-O2` match native results across input vectors |
| M3 | Guarded memory, stack, pointers, data segments, relocations, fault codes | Programs using arrays, structures, strings and global tables match native results; invalid accesses trap with defined codes |
| M4 | Function pointers, several translation units, imports bound to runtime services | A multi-file C program prints through an import; output and exit status match native |
| M5 | Floating point, aggregates, vectors, by-value and hidden-result passing, variadics | Numeric kernels are bit-exact against the host for binary32 and binary64; a small `printf` works |
| M6 | C++ without exceptions or RTTI; LLVM libc and compiler-rt built for SMIR (P8 first part, P7 minimal) | Hosted C programs that need only standard I/O produce their expected output |
| M7 | Parallel guest threads, host atomics, safepoints, mapping and code lifetime, TLS (P3) | Threaded programs run on several host threads; race and lifetime stress tests pass |
| M8 | x86-64 and AArch64 JIT on the typed IR (P5) | Interpreter and JIT agree on the whole end-to-end corpus on both architectures |
| M9 | Virtual dispatch, RTTI, exceptions; libc++abi, libc++ and the logical unwinder | Hosted C++ programs produce their expected output |
| M10 | Separate compilation and linking, OS personalities, carriers, launchers, embedding API, six hosts (P7, P10) | All launch forms run on the six host lanes |
| M11 | One foreign guest ISA per process, mixed calls and callbacks, two-phase exceptions (P9) | Bidirectional nested transitions with preserved exception identity |

M0 to M6 have passed their exit tests. The commits on the `portable-smir`
branch record the observed test results for each. Two parts of their scope
are open. Vector types (M5) are not in emitted objects: the compiler rewrites
vector code as scalar code instead, which serves until a JIT can use them.
For M6, 73 of the 81 C programs of the hosted corpus match their recordings;
the test names the other eight and what each needs: seven want an operating
system, and one has undefined behaviour that the engine reports. `setjmp`
and `longjmp` are lowered by the compiler to ordinary control flow, as
exceptions are, and not through the `setjmp_capture` and `longjmp_restore`
helpers, whose source ABI records the emitter does not produce.

M7 has passed its exit test. Guest threads run in parallel on host threads in the
interpreter, with the `thread` and `sync` services (chapter 06, "Services as
implemented"), and the C library has `pthread.h` and `threads.h` over them:
threaded C programs match their native builds. Thread-local variables are
compiled to thread-local segments, of which the interpreter gives every
thread its copy, and `errno` and the values of thread-specific keys are each
thread's own. Memory is mapped, protected and unmapped through the `memory`
services. The engine stops every thread at its next step when the program
ends, which is the interpreter's safepoint; the lifetime of compiled code
belongs to M8, which creates such code. Threads that read shared
data scale to about four and a
half times one thread on eight processors in the interpreter; beyond that
they contend for the reader count of the object they share, which a
lock-free read path would remove.

M8 has passed its exit test: the interpreter and native code agree on the
whole end-to-end corpus, on AArch64 and, built for x86-64 and run under
Rosetta, on x86-64. Modules are compiled to code that runs on the
interpreter's own state, so that the two engines agree by construction;
chapter 08, "Native code as implemented", describes it. Every test that runs
a program runs it on both engines and compares. The code is in
`crates/smir-portable`, beside the representation it compiles, and not in the
main crate as first planned. Constants, copies, phis, conditional branches,
selections, integer arithmetic, comparisons and conversions have
instructions of their own; every other operation, and every unusual case of
those, is performed by the interpreter's code. What is open in M8 is speed,
not agreement: memory accesses, address arithmetic, calls and returns still
go through the engine, and that is where most of the remaining time goes. A
program of integer arithmetic over an array runs about three times as fast
as interpreted.

M9 has passed its exit test. C++ programs are compiled against libc++'s headers and
linked with libc++'s compiled part; objects with static storage are
constructed and destroyed in order. Exceptions and run-time type information
work on both engines: the compiler lowers exceptions to explicit propagation
(a flag and a test after each call that may throw), so that neither engine
needs an unwinder, and libc++abi's type descriptions decide which handler
catches. The stream classes work over the standard streams, over strings
and over files, with libc++'s localization in its one locale; so do
`charconv`, `format`, `print` and regular expressions, pointers to member
functions, guarded static variables, `bad_alloc` when storage runs out, and
the end of the program when an exception leaves a thread. The C library
under them has LLVM libc's buffered streams over the runtime's file
services, and a program learns from `thread.concurrency`, a service of a
second catalog, how many threads run at once. 86 of the 97 programs of the
hosted corpus match their recordings, 13 of the 16 in C++. None of the
other three C++ programs can match: two print what differs between any two
builds (the hash of a type, and a sum that depends on the order in which a
vector destroys its elements), and one uses a local variable from its worker
threads after the variable's lifetime has ended, which the engine reports.
Open at the end of M9: `std::filesystem` beyond its headers, which wants
directory services, and unoptimized code that handles pointers to member
functions as two-field values. The whole suite passes with the runner
built for AArch64 and with the one built for x86-64 and run under Rosetta.

M10 is in progress, in this order: carriers and the explicit launch form;
the embedding C interface; an executable that carries its runtime; modules
that are linked when they are loaded; and what the hosts other than this
one need, which can be compiled here and run only there. A carrier's payload
is found in ELF, Mach-O and PE files as chapter 10 says, `smir-run` runs
what a carrier holds, and `smir-pack` wraps an object in one. The host C
interface is a static library with the functions of an image's life and of
a library's, which is called again and again in a process that lasts; and a
program linked with it and with a launcher is an executable of this
machine that runs like any other; that is done for Mach-O, and for ELF
as far as chapter 10 says.
Modules that call functions of one another are linked into one program
before it starts (chapter 06, "Linking as implemented"), and the compiler
emits a module that depends on others (`smircc.py --needs`): C and C++
modules compiled apart, each with a C library of its own if it has one, run
linked as they do built into one program. Only calls cross modules so far.
A host links modules through the C interface, and an executable that
carries its runtime carries the modules of its program beside it. A host
may have functions of its own that its programs call, registered through
the C interface and declared in C by a link name; twenty of the
interface's twenty-one functions work, the last being the one for
aggregate values, of which the runtime has none. An
executable may also carry its program alone and find the runtime installed
(chapter 10, "As implemented"); that is tested for Mach-O, and an ELF
executable of the kind is made and has not been started.
`.github/workflows/smir-portable.yml` runs the runtime's tests on the six
hosts and, on the four that are not Windows, makes and starts an
executable of each kind; it has not run yet. Four of the six have run them from this machine:
macOS on AArch64; macOS on x86-64 under Rosetta; and Linux on both
architectures in containers (`crates/smir-portable/tests/linux.sh`), built
there against glibc for AArch64 and built here against musl for both, the
x86-64 programs emulated. On Linux the unit tests, the interpreter and
native-code tests with their comparisons against the reference machine, and
the host C interface pass as they do on macOS. Running them there found two
things the runtime owed to its first host, which are corrected: fused
multiply-add was the host's, which is not right in every C library, and the
processor's caches were synchronized by a compiler library that not every
program has. For Windows on x86-64 the crates compile and their programs
and tests link, with native code as on the other systems: its memory comes
from the Windows functions, and it calls the engine by the convention it
uses everywhere (chapter 08, "Native code as implemented"). The launchers
compile for Windows and Linux with another C compiler. Nothing has run on
Windows.

M11 has begun. Portable code calls functions of foreign machine code
through bridges, with integers and floats (chapter 07, "As implemented"):
the engine makes the frame and the arena and judges the return, and the
processor that runs the foreign code is the embedder's. Callbacks, nested
transitions and exceptions at a bridge, which the exit test is about, are
not done.

M7 precedes M8 because JIT memory access and safepoint paths depend on the
threading design. The memory implementation in M3 is shared and atomics-capable
from the start so that M7 extends it instead of replacing it.

Until an in-tree LLVM target is needed, the emitter is built out of tree against
the pinned LLVM checkout, which stays unmodified. It represents some source-level
facts differently from the full contract in chapters 03 and 09 (function-pointer
call plans, the variadic argument list, complex-number passing, virtual table
slots); each difference is recorded in the affected chapter when it is introduced.

The first run's role ownership map, proposal acknowledgements and integration
receipts are retained outside the repository as an archive. They are not inputs
to any check, and nothing in this tree depends on them.
