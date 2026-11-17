# Portable SMIR platform contract

Status: **legacy framing 0.1 and experimental compiler-contract candidate 0.2; qualification is tracked separately; production executable profile not admitted**.

This package implements the specification-first workstream of the approved
portable SMIR plan. It is a requirements contract for new portable execution;
it does not redefine current lifted-ISA behavior or advertise working compiler
support. `requirements.json` is the requirement ledger. `status.json`,
`validation.json`, `compiler-contract.json` and `contract-closure.json` are
historical records of the first specification run and are no longer maintained.

Legacy draft bytes use envelope revision 0.1 and profile ID 1. The separate
candidate uses revision 0.2/profile 2 with all ten semantic section slots.
These experimental identifiers are not a published 1.0 compatibility promise.
They may change while the interpreter and emitter are built; see the
[roadmap](12-work-packages.md).

The working tree is implementing the coherent ordinary function address cut.
Envelope 0.2 and profile 2 remain unchanged. Required roots 1, 2, 3 and 5 now use
payload revision 2; ABI root 10 uses revision 3; roots 4, 6, 7, 8 and 9 retain
revision 1. Decoders check the leading revision word before schema-dependent
fields. Earlier incompatible objects are preserved as `WIRE-REVISION` rejection
controls; new semantic fixtures must be generated from explicit source records.
The source ABI uses the V3 nominal hash contract. `CodeAddress` is a noncall
64-bit source function pointer; binding requires an explicit ordinary call plan.
Every call signature carries its execution type, and call/invoke/tailcall records
carry an explicit optional source plan. No decoder infers missing fields.
Earlier qualification receipts remain historical until the migrated schemas,
nominal hashes, fixtures and independent reference implementations are rechecked
together. Cohesive C++ method, dispatch, RTTI, data and lifecycle contracts are
incomplete; production portable execution remains unimplemented. A finite sequential
reference command now executes semantically verified objects through the actual
source-backed code registry and Machine.

## Fixed product requirements

- Hosted C23/C++23 against pinned Clang/library support, with explicit upstream gaps.
- Portable LP64 ABI, 64-bit pointers, little-endian guest memory.
- Interpretation and x86-64/AArch64 JIT on Linux/macOS/Windows, all six hosts.
- Parallel guest threads, portable imports and all three OS personalities.
- ELF/Mach-O/PE carriers, explicit loading, installed-runtime launchers,
  and runtime-embedded executables.
- Portable SMIR plus one foreign guest ISA per process, x86-64 or AArch64.
- Descriptor-based Itanium/Microsoft C++ objects, callbacks and cross-domain EH.

## Document map

| Chapter | Contract |
|---|---|
| [Platform](01-platform.md) | Identity, versions, compatibility and ownership |
| [Execution](02-execution.md) | Values, operations, calls, phis, traps and exceptions |
| [ABI](03-abi.md) | C/C++ layouts, frames, parameters and varargs |
| [Memory](04-memory-concurrency.md) | Addressing, faults, atomics and parallel lifetime |
| [Encoding](05-encoding.md) | Implemented byte-level envelope and admission boundary |
| [Linking](06-linking-runtime.md) | Symbols, modules, runtime imports and hosted libraries |
| [Interoperability](07-foreign-domains.md) | Native guest libraries, objects and coordinated unwinding |
| [JIT](08-jit.md) | Native state transfer, helpers and invalidation |
| [LLVM](09-llvm.md) | Frontend, lowering coverage and target implementation |
| [Packaging](10-packaging.md) | Containers, runtime discovery and embedding |
| [Conformance](11-conformance.md) | Evidence, independent checks and release gates |
| [Roadmap](12-work-packages.md) | Dependencies, granular work and exit conditions |
| [Provenance](PROVENANCE.md) | Baselines, assumptions, change surfaces and sources |

## Run the implemented checks

From the repository root, Python 3.11+ and Rust 2024 are required:

```sh
python3 tools/smir-format/check_spec.py
python3 -m unittest discover -s tools/smir-format -p 'test_*.py' -v
rustc --edition 2024 --test src/smir/portable/mod.rs -o /tmp/rax-portable-tests
/tmp/rax-portable-tests
python3 -B tools/smir-format/codec.py run-candidate-reference \
  docs/specifications/smir/portable/conformance/envelope/candidate/reference-execution/call42.smo \
  --entry-function 1 --argument-bits 2a000000 \
  --reference-policy docs/specifications/smir/portable/conformance/envelope/candidate/reference-execution/policy.json
```

The cross-codec test compiles Rust and C++ probes in a temporary directory and
compares actual acceptance, diagnostic codes and payloads with the independent
Python codec. Python and C++ independently encode envelope bytes; Python, Rust
and C++ independently decode and encode ordered payload records. It checks
each header/directory bit, explicit rejection fixtures, diagnostic precedence,
truncations, aligned payload sizes and deterministic mutations. The codec checks
representation and content identity. Scoped complete-module tests also compose
the actual role verifiers and execute sequential reference objects. The standalone
`verify-candidate-reference` command reports its restricted scope and never grants
production execution authority.

The `run-candidate-reference` example returns `2a000000` (integer 42) in seven
guest steps after real nonnull binding, indirect source entry and normal
completion. Its policy explicitly bounds fuel, frames, source queries and
registry resources. See [the tool guide](../../../../tools/smir-format/README.md)
for supported operations and conformance commands. This is sequential reference
execution. A Rust interpreter for integers, data pointers, memory and data segments is in
[crates/smir-portable](../../../../crates/smir-portable/README.md), and a C compiler
for the same subset is in [tools/smir-clang](../../../../tools/smir-clang/README.md);
function pointers, imports, floating point, the production runtime and the JIT are not implemented.

## Contract changes

There is no freeze gate. The contracts in these chapters are settled by tests
that compile and run programs. When an implementation and a chapter disagree,
the decision is made and the chapter is corrected in the same change. Version
1.0 is released only after the full host/runtime/LLVM/mixed-domain qualification
matrix passes. An envelope codec alone establishes nothing about execution.

For a macOS installation whose default Clang lacks a usable SDK/header setup,
select the configured Apple compiler explicitly:

```sh
CXX=/usr/bin/clang++ python3 -m unittest discover -s tools/smir-format -p 'test_*.py' -v
```

The C++ probe requires a C++20 compiler. Missing compiler/SDK support is a test
failure, not a skipped comparison.

## First-wave contract references

The role-owned reference tools run as separate processes to keep their local
module imports independent:

```sh
CXX=/usr/bin/clang++ python3 -m unittest discover -s tools/smir-format/execution -p 'test_*.py' -v
CXX=/usr/bin/clang++ python3 -m unittest discover -s tools/smir-runtime-contract -p 'test_*.py' -v
SMIR_ABI_CLANG=/Users/int/dev/llvm-project/build/bin/clang python3 -B tools/smir-abi/check.py --output /tmp/smir-abi-check
SMIR_LLVM_ROOT=/Users/int/dev/llvm-project SMIR_LLVM_BIN=/Users/int/dev/llvm-project/build/bin python3 -m unittest discover -s tools/smir-llvm-contract -p 'test_*.py' -v
```

Select `CXX=clang++` on Linux. The ABI witnesses require Clang identifying the
pinned LLVM commit; existing-target compilation is a layout oracle only. LLVM
witnesses record each binary identity separately: this checkout's Clang/TableGen
are 24.0.0git, while its opt/llvm-as are 23.0.0git. A shared build directory does
not establish a shared executable revision. No command above builds or edits LLVM.

Several of these suites need natively built oracle binaries named through
environment variables, and some `tools/smir-llvm-contract` tests still read from
or write under the first run's `/tmp/rax-portable-smir-01` prefix; without them
those tests fail and do not skip. `tools/smir-abi` cannot be run by whole-directory
discovery because two test modules share the name `test_candidate`; use the
per-module commands in `.github/workflows/smir-format.yml`. Neither an integer/FP
reference evaluator nor a descriptor/protocol model is a portable production
runtime.

## Active full-platform contract closure

`contract-closure.json` tracks the continuing implementation objective and the
current CC-001 assignments. The endpoint remains the complete platform above;
partial reference packages do not redefine completion. Compiler-facing contract
qualification precedes production runtime/LLVM waves.

`candidate-registry.json` records accepted experimental reservations for distinct
envelope0.2/profile2, mandatory ABI section10 and common ordered-record primitives.
The existing0.1/profile1 codec behavior remains unchanged. The new generic
`RecordCodec` and the independent Rust/C++ codecs implement bounded ordered
records. `CandidateCodec` decodes all ten schema roots, checks payload revisions
and canonical content identity, and returns `UnverifiedCandidateModule` for
inspection. It performs no whole-module semantic verification or execution.
Shared candidate operation/helper/ABI schemas and independent complete-module
witnesses have separate review and qualification records. Prior receipts cannot
qualify edited inputs; `status.json` records the computed current compiler gate
without changing the immutable contract bytes being reviewed.

## Isolated function-address reference tools

The independent V3 nominal hasher and source-call data view have separate
executable tests. The active nominal profile is V3, as recorded above; the
older isolated receipts qualify their own source cuts. From the repository root:

```sh
(cd tools/smir-abi && PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest function_address.test_hash_v3 -v)
(cd tools/smir-format/execution && PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest test_candidate_source_calls test_candidate_source_data test_candidate_context -v)
```

The integrator reproduced 22 hash methods and 47 capture/regression methods in
each of normal and optimized Python modes, with stable scoped inputs. The V3
quotient also matched an independent relation-elimination oracle on 4144 finite
graphs; this does not establish complete source normalization or ABI admission.
Exact tested source cuts and receipts are retained in the run coordination
directory. The older full-suite receipt applies to its archived source cut.

Source character transport across numeric `Int8` parameter/result boundaries,
source-object end after the creation frame exits, and exact exception outcome
markers remain compiler-facing gaps. A pinned LLVM parser accepting opaque
helper calls does not verify their source descriptors or runtime semantics.

The [canonical source-path resolver](conformance/abi/source-paths/README.md)
checks original declaration paths, symbolic array ranges, virtual-base identity
within a known most-derived class object, and explicit coverage views. Its
focused 27 tests pass in each Python mode; the owner qualification also runs
99 dependency tests in each mode. Run its tests and byte-preservation check from
the repository root:

```sh
(cd tools/smir-abi && PYTHONOPTIMIZE=0 python3 -B -m unittest record_layout.test_source_paths -v)
(cd tools/smir-abi && PYTHONOPTIMIZE=1 python3 -B -O -m unittest record_layout.test_source_paths -v)
python3 -B docs/specifications/smir/portable/conformance/abi/source-paths/generate.py --check
```

The independent [Clang source-cell oracle](conformance/llvm/source-cells/README.md)
observes the pinned compiler's declaration graph and target layouts. It checks
31 selectors and 17 authored relations on both target architectures. These
static tools issue unbound reports; neither equal byte offsets nor matching
source patterns establish runtime object identity, a source alias or a virtual
base adjustment. Missing enclosing most-derived metadata produces an explicit
unavailable result without a cell key or geometry.

The Python verifier now accepts ABI-checked nonordinary function entry
associations while retaining explicit hidden argument roles and ordinary-call
limits. Its complete 330-test execution suite passes in normal and optimized
Python on that recorded source cut. The Rust static verifier now accepts a finite
nonordinary-entry profile: 167 library tests and 3 documentation tests pass, and
23 CLI fixtures produce 7 verified objects, 10 semantic rejections and 6 unavailable
results. This covers explicit this/VTT/sret entry associations for the audited
flat-record profile; source method calls and native C++ execution remain outside
that profile. The static source-contract tool and canonical scope grounding have
separate finite profiles and correction gates.

The finite [source-grounding reference](conformance/execution/source-grounding/README.md)
checks canonical source geometry, rooted binding chains and captured scope values
through normal control flow against the genuine ABI and source-contract tools.
The last qualified captured Python execution suite passes 503 tests in each mode. This closes the
recorded stale-scope, root-cycle and metering defects within that profile; source
operation truth, lifecycle/EH and original-v3 admission remain separate work.

The experimental [source-carrier codec](conformance/runtime/source-carrier/README.md)
reads and writes complete ten-root modules with section 3 revision 2 or 3. The
actual [original-v3 context](conformance/execution/root3-context/README.md) preserves
the full embedded source contract, original stamps and one cumulative budget while
running real ABI, ordinary-body and finite source-constraint checks. Selected-function
comparison retains the original owners and digests. Revision 3 remains unavailable
to the generic executable reader, source registry and interpreter.

The earlier observer/scalar integration passed 227 runtime and 474 execution tests
in each Python mode. At that archived cut, 785 consumed inputs and all 79 newly
integrated paths matched their approved hashes. Earlier R10 failures and R11 passes
remain separate as-run evidence. Its historical Rust receipt reported 167 library tests and
3 documentation tests. These are finite reference/static results; full P2,
source semantics and compiler freeze remain incomplete.

The [static Journal observer](conformance/execution/source-observer/README.md)
has real ordinary typing and separate original-source/adoption/PRE freshness
checks. The [scalar source/body checker](conformance/llvm/scalar-alignment/README.md)
checks independently supplied SMIR against actual pinned compiler observations.
Its installed 24 native-backed and 4 pure tests pass per mode. It emits no SMIR
and proves no portable ABI or complete source-function equivalence. Revision 3
still cannot execute through the generic reader, registry or Machine.

The [typed Clang observation witness](conformance/llvm/semantic-observation/README.md)
records exact APInt bits, canonical types and operand/declaration identities. Only
actual guarded native observations issue original inspection witnesses. Its 23
native-backed and 9 pure tests pass in each mode; independent focused checks have
separate receipts. This does not establish source-to-SMIR lowering or guest execution.

The earlier lifecycle/literal/program-space integration passed 482 execution and
227 runtime tests per Python mode, plus 23 lifecycle-budget and 9 pinned LLVM
library witness tests per mode. A fresh unique Cargo target passes 173 library
and 3 documentation tests. Actual consumed inputs and all 85 installed package
paths match approved hashes; prior failed runs remain preserved.

The [lifecycle associations](conformance/abi/source-lifecycles/README.md) have
qualified logical costs only in the bounded flat original-v3 profile. The
[CodeAddress literals](conformance/execution/function-addresses/literal-values/README.md)
retain arbitrary 64 defined bits without call authority. The
[LLVM program-space contract](conformance/llvm/program-space/README.md) assigns
AS1 and private SSA carriers with independent structural witnesses. These results
leave the full compiler gate, portable production execution and later waves incomplete.

The [scalar Raw8 atomic extension](conformance/execution/atomic-bytes/README.md)
passes 494 execution and 227 runtime tests per Python mode. Fresh Rust passes
174 library tests and 3 doctests; all 763 consumed inputs match current bytes.
The 67 new static cases and real sequential memory/shadow witnesses preserve
old/desired origins and the independent CAS order sets. Only scalar Raw8 exchange
is added; vector/other-raw-width exchange remains rejected. Parallel commit,
precommit resource reservation and fault recovery remain unimplemented gates.

The subsequent metadata-only repair adds all observed transitive inputs for the
13 fixture generators. They reproduce 839 objects unchanged in normal/optimized
modes; 888 actual input paths are covered. Current affected registry tests pass
17 per mode and a fresh Rust174+3 run passes. The earlier whole494/227 suites
remain their recorded as-run checks; they are not relabeled as fresh reruns.

The [CodeAddress byte relay](conformance/execution/function-addresses/byte-relay/README.md)
now exercises a genuine issued address through eight generic Raw8 helper calls,
guarded memory and actual binding; the final ordinary source-plan call returns 42.
All ten profiles run, including equal-bit foreign/mixed origins, numeric and
reordered fragments, stale generations and memory faults. The full execution
suite passes 503 tests per Python mode. Original address roots remain retained;
this does not establish Raw8-only lifetime retention, source ABI revision 2 or
LLVM transport. Earlier runtime and Rust counts retain their recorded scope.

The [source-byte ABI epoch reference](conformance/abi/source-bytes/README.md)
recognizes exact source ABI revisions 1 and 2; existing no-argument APIs retain
revision 1. Revision 2 refuses full ABI facts without genuine original category
evidence, including for byte-free modules. The descriptor tool returns an
unbound static result. Current source checks pass 77 ABI tests per Python mode;
the captured broad run passes 503 execution and 227 runtime tests per mode,
with a fresh 178-test Rust library and 3 doctests. A subsequent test-only import
isolation repair passes current ordered/discovery controls and preserves the
broad run as recorded. All 823 consumed inputs match the current tree.

CI runs the 28 legacy ABI reference tests from their actual file, plus 14
ordered epoch/projection/API tests in both modes and exact fixture reproduction.
These checks do not implement a portable source frontend, source-init runtime,
LLVM emission or full compiler freeze.

The [SourceValueFlow assertion reference](conformance/execution/source-value-flow/README.md)
checks every definition in five original verified core modules, including parallel
phi moves, NoOp, select, freeze and seed relationships. Its39 cases contain6
positive and33 rejection assertions. The full execution suite passes517 tests in
each Python mode, with actual child flags and fresh cache prefixes verified. All
856 consumed source inputs match current bytes. Earlier unchanged runtime227,
ABI77 and Rust178+3 results retain their recorded as-run scope.

These are unbound assertions and generic interpreter witnesses. They do not
produce genuine source categories, source-body equivalence, private dynamic value
events, source initialization authority or source ABI revision2 execution. Complete
factory costs and mandatory C23/varargs/coroutine/wider-Raw source routes remain
required. Compiler freeze and production platform gates remain false.

The current combined reference tree passes517 execution and230 runtime tests in
each Python mode. The [native byte-category observer](conformance/llvm/source-bytes/README.md)
independently passes40 tests per mode and four CLI checks; its actual installed
native tool was rebuilt against725 guarded inputs. Its20-file library/config
closure distinguishes genuine pinned byte declarations from lookalikes. This is
a native LP64 AST reference, not a portable source producer or private source fact.

The [quiescent union reference](conformance/runtime/union-prestore-reference/README.md)
executes14 authored scenarios with42 real core-backed methods. Its separate
physical Raw and model-init planes preserve sticky indeterminacy, origins, first
birth and once-only park/store behavior. Nested unions, actual construction phase,
source eligibility/events and production parallel execution remain unimplemented.

All908 consumed source hashes match current bytes. The SourceValueFlow schema
guard uses unbuffered FileIO, with actual descriptor-position growth tests. A
combined-run failure exposed an old nine-schema test count; the repaired explicit
ten-schema positive/negative audit and both complete suites now pass. The failed
cut remains archived. Earlier ABI77 and Rust178+3 checks retain their as-run scope.
Compiler freeze, source ABI2 execution and production platform gates remain false.

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

R28 integrates the [nested union reference](../../../../tools/smir-runtime-contract/union_nested/README.md): fixed 16 B outer and 8 B inner storage, a sibling union, whole-candidate preflight, generations, separate model initialization and once-only park/resume around real generic Python Core operations. Runtime suites pass 233 tests in each normal/optimized mode at the immutable pre-relocation cut. Fresh checks under the relocated coordination prefix pass six ABI/runtime parent configurations with 18 actual process audits. All 931 consumed hashes match current source bytes. R27 execution551/ABI77 and prior native/Rust results retain guarded as-run scope. Source issuers, source ABI2, full costs, compiler freeze and production gates remain incomplete.
