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
P3 requires both the P1 compiler-contract freeze and the complete P2 exit.

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

No package is complete because its document exists. See `status.json` for actual
implementation state. Do not begin compiler emission while P1 is unfrozen.

## First-wave exclusive ownership

The run `rax-portable-smir-01` uses the shared checkout. Initial foundation files
were largely untracked; a HEAD-only checkout cannot reproduce that baseline.
Coordination and proposal acknowledgements live under each role's directory in
`/tmp/rax-portable-smir-01/`; claims are atomic directories under `claims/`.

| Role | Exclusive paths in this wave |
|---|---|
| INTEGRATOR | `src/smir/mod.rs`, `src/smir/portable/{mod,tests}.rs`, existing files directly under `tools/smir-format/`, `.github/workflows/smir-format.yml`, `docs/specifications/smir/README.md`, portable root `{README,01-platform,11-conformance,12-work-packages,PROVENANCE}.md`, all portable root JSON, `references/`, `conformance/envelope/` |
| SEMANTICS | `02-execution.md`, `05-encoding.md`, `schema/execution/`, `conformance/execution/`, `src/smir/portable/execution/`, `tools/smir-format/execution/` |
| ABI | `03-abi.md`, `07-foreign-domains.md`, `schema/abi/`, `conformance/abi/`, `tools/smir-abi/` |
| RUNTIME | `04-memory-concurrency.md`, `06-linking-runtime.md`, `08-jit.md`, `10-packaging.md`, `schema/runtime/`, `conformance/runtime/`, `tools/smir-runtime-contract/` |
| LLVM | `09-llvm.md`, `llvm/`, `conformance/llvm/`, `tools/smir-llvm-contract/` |

Unqualified chapter/schema/fixture paths in this table are under portable/.
Other paths remain read-only. Ownership is by whole file. The LLVM checkout is
read-only. A draft reference tool passing does not authorize a later-wave source
rewrite. Subsequent packages require a new explicit ownership map and accepted
interfaces from the integrator after the prerequisite gates pass.

Cross-role decisions requiring closure include execution/ABI identities and
logical calls; poison, undef and freeze refinements; memory/import/EH frontiers;
and frontend DataLayout/storage layout. Acknowledgement of a local draft is not
acceptance of a complete executable schema. Do not replace missing FP, exception,
foreign-descriptor or runtime decisions with host defaults.

Approved first-wave extensions are recorded by exact whole-file ownership maps in
`/tmp/rax-portable-smir-01/INTEGRATOR/`. They include the integrator's private Rust
`record_refinements.rs` and three direct Rust payload-oracle tools; SEM's original-v3
context and registry repair; ABI's optional actual-factory meter; runtime's carrier,
comparison and current fixture metadata repairs; and LLVM's new typed AST witness.
These maps preserve the role boundaries above and do not authorize later-wave
runtime or compiler-emission changes. Exact paired SEM17/runtime16 observer and
new LLVM46 scalar references are now installed and current-qualified: 474 execution
and 227 runtime tests per mode, 785 consumed inputs with zero drift. Lifecycle cost
implementation remains under review. P1/P2 and all production gates remain incomplete.
Current compiler-contract readiness distinguishes undecided carrier/character/
source-mapping choices from later verifier/runtime/emitter implementations; no
finite package or stale historical blocker alone determines compiler freeze.

R14 integrated the exact18 flat-v3 lifecycle/cost package, exact12 CodeAddress
literal consistency package, exact39 LLVM program-space contract, and exact16
provenance-only repairs. CI registers the new reference checks. Current combined
qualification is recorded in status.json and validation.json. The next first-wave
work is the Raw8 scalar atomic reference implementation, explicit source ABI epoch
and nonordinary C++ caller/implicit-created portable associations. These remain
owned contract/reference packages; no later-wave subsystem rewrite is released.

R15 integrated exact10 scalar Raw8 exchange paths and registered67 fixture
reproduction in CI. Whole reference/static494/227 per mode and freshRust174+3
pass at the guarded current cut. Next exact14 metadata transitive-closure package
is approved for a separate install. Required union pre-store creation remains
an explicit compiler-freeze blocker. The proposed source recipe also requires
deterministic preprocessing clock/virtual-file policy after an actual counter.

R16 exact14 metadata transitiveclosure is integrated and currentfocused checks
pass. CPPsourceevidence recipe has a mandatoryfixedclock/virtualpath correction
after actualnativecounter; its sourceproducer andrequiredunionprestore creation
contract remainincomplete. Nativebytecategory observation is a separate
nonauthoritative firstwave tool, never proof of portable source ABI admission.

R18 integrates the exact five-file CodeAddress byte-relay reference package.
Full execution discovery passes 503 tests per Python mode; the genuine positive
returns 42 after eight byte helper calls and memory reconstruction. Nine methods
cover ten profiles, with foreign/mixed origin, numeric, stale and guard controls.
The source ABI epoch package has an acknowledged exact 22-file ownership map
and remains pending its explicit start and paired active-provenance repair.
Source-init SSA custody, union prestore, genuine category production and LLVM
transport remain required first-wave implementation work; compiler freeze is false.

R20/R21 integrates the 23-file known-source-epoch/static-descriptor package with
two active provenance updates, then repairs its test import isolation and CI.
The paired source update and all current affected checks pass; historical receipts
remain unchanged. The next owned first-wave work is the unbound SSA-flow
schema/checker, the finite union protocol oracle, the complete native category
observer, and an actual portable TargetInfo/type-projection prototype. Each needs
its exact review and ownership release. Genuine source/body/initialization event
issuers and the required C23/varargs/coroutine/wider-Raw gaps still block compiler
freeze; no later-wave runtime or backend implementation is released.

R22 exact ownership release SOURCE-VALUE-FLOW-exact7 assigns SEMANTICS only the
three source_value_flow tool files, its test module, execution assertion schema
and conformance cases/README. Root owns workflow registration and shared records.
All7 are installed/quiet and independently qualified:517 execution tests per mode,
owner115 per mode,856 combined current consumed inputs with0 drift. It remains
an UNBOUND reference package; source/private value/init/phase issuers and complete
source routes are first-wave dependencies. No later-wave production path is granted.

The native category package remains withheld for corrected bounded file guards
and fresh qualification. ABI owns the actual finite portable TargetInfo prototype
in its coordination directory. Runtime owns a forthcoming finite quiescent union
reference package; shared installation requires its reviewed exact map. LLVM
checkout and unrelated foundation remain read-only.

R23-R25 release exact native40r5, union14r3 and paired guard/inventory4 maps.
All58 worker paths are installed/quiet and current reference qualification passes
517 execution/230 runtime tests per Python mode, native40 per mode/four CLI,
908 consumed hashes with0 drift. Root owns shared records/CI; exact maps and
all before images remain in integration coordination. Earlier failed schema-count
cut and withdrawn buffered-guard cuts remain historical, never relabeled passing.

Next explicitly owned work stays first-wave: SEM actual completed-core-event
reference hooks, Runtime nested pre-store reference and LLVM physical Raw8 helper
reference, all in their own coordination directories. ABI's finite portable TargetInfo/type projector is integrated under the exact11
map; R26 qualification is recorded below. These grants
authorize no shared core, LLVM checkout, private source issuer or later-wave backend.

R26 integrates the [portable type frontend](../../../../tools/smir-abi/PORTABLE-TYPE-FRONTEND.md).
It runs a real out-of-tree pinned Clang TargetInfo for the portable LP64/little-endian
ABI and projects finite declarations into executable type, nominal, layout and
call-plan fragments. An independent checker verifies geometry and complete emitted
fragment relations. No LLVM checkout files are modified.

Root independently passes 168 actual cases across O0/O2_NDEBUG native builds and
normal/optimized Python, with 160 native tool invocations. Both fresh owner builds
guard 660 inputs each. Parent-module identity, loader filtering, absent-native
unavailability and nonwriting schema checks are exercised. Root freshly reruns
ABI64, epoch/projection13 and basic CI28 tests per Python mode. All 917 consumed
source hashes match current bytes. Execution517/runtime230 retain unchanged R25
as-run evidence; Rust178+3 retain their earlier unchanged as-run scope.

This is an UNBOUND type facet. Function bodies, records, source varargs, complete
source recipes and genuine private source issuers remain unavailable. No source
ABI2 execution, backend emission, compiler freeze or production admission follows.

R27 integrates the [actual-core event reference](../../../../tools/smir-format/execution/source_value_flow/DYNAMIC.md)
under the exact seven-file ownership map, with one dependent active fixture
provenance update. The real generic Python interpreter now retains actual
parameter/phi/operation births and scalar selections, carries explicit public
model masks, and publishes completed results once across park/resume. Retained
outputs survive metadata failure; a host failure during computation preserves
the original terminal exception. Current SSA binding identity and actual phi
snapshot checks reject stale value/birth pairs. No source facts are issued.

Fresh Root checks pass 551 execution, 230 runtime and 77 ABI/projection tests in
each normal/optimized Python mode. Execution has 213 and runtime 223 actual
process audits per mode, with verified flags, absent cache prefixes and no source
drift or unexpected inputs. Actual installed focused checks pass 149 tests and
six fixture groups per mode. The active union provenance change replaces exactly
two interpreter digest entries; 14 scenarios and all 1878 prior SMOs remain exact.
All 921 consumed source hashes match the current tree. A fresh independent C++
record codec oracle supports the runtime checks; no guest native execution is
inferred. Earlier native type/category and Rust checks retain their guarded
as-run scope. Historical failed cuts and counterexamples remain archived.

This is a finite sequential reference implementation. Genuine source/category/
body/initialization/phase issuers, source ABI2 execution, required language and
representation routes, full costs and every production platform gate remain
incomplete. Compiler freeze is false. The next explicitly owned work remains
first-wave: actual-core memory/init reference, nested union protocol, physical
Raw8 helpers and portable C record layout witnesses, each requiring its own
review, exact shared ownership and observed integration checks.

R28 nested-union exact15 is installed and reference-qualified. Remaining assigned first-wave implementations are actual-Core memory/init hooks, physical Raw8 native helpers and the portable C record frontend; each needs independent review and current installed qualification. Genuine source issuers and remaining compiler contract gaps still block compiler freeze and subsequent production waves.
