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
For M6, 69 of the 81 C programs of the hosted corpus match their recordings;
the test names the other 12 and what each needs, and of those `setjmp` is a
language feature still to be lowered: its helpers need source ABI records
that the emitter does not produce.

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

M9 is in progress. C++ programs are compiled against libc++'s headers and
linked with the part of libc++ that needs neither localization nor a C++ ABI
library; objects with static storage are constructed and destroyed in order.
74 of the 97 programs of the hosted corpus match their recordings, 5 of the
16 in C++. Still to come in M9: exceptions and run-time type information,
with the runtime under them, and the stream classes.

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
