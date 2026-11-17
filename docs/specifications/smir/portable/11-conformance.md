# Conformance and evidence

CONF-001: Every contract identifier maps to a test and a status entry. Distinguish
specified, implemented, verified and unsupported. A specification is not runtime
coverage. Keep failures, skips, fallback, rejected cases and actual oracle/native
execution counts separate.

CONF-002: Framing conformance uses hand-audited canonical bytes, Rust/Python/C++
cross-decoding, malformed-header/directory bit mutations, truncations, bounds,
alignment/padding and deterministic fuzz mutations. Empty envelopes are not
executable examples. Envelope fixtures test framing only. Candidate record tests
separately compare all three independent decoders and encoders with explicit
schema snapshots, all record variants, a complete ABI record, invalid UTF-8,
nested options, integer limits, truncations, quotas and deterministic mutations.
Shape-only records can pass these comparisons while failing semantic verification.

Candidate bundle tests check all ten root grammars, payload revision 2 for roots
1, 2, 3 and 5, revision 3 for ABI root 10, revision 1 for the remaining roots, exact
content preimage construction, self-identity normalization, optional metadata
exclusion and content/revision/schema conflict rejection. Only the named
manifest.identity field is zeroed; identical bytes elsewhere remain hashed.
`UnverifiedCandidateModule` exposes inspection data without executable authority.
Cross-role schema edits invalidate prior snapshot receipts until coherent reruns.

The metered source-data reference API separately checks declared local ranges and
dependency expectations before ABI proof. Its fixtures compare actual Python
source views with Rust's phase-independent declared-range behavior, preserving
original symbol/storage identities, alignment, bytes and full absolute patch
records. Huge zero tails stay symbolic. Checks cover shared budget/context
identity, immutable capture, active-schema/root mutation, host-size refusal and
malformed schema diagnostics. Defined weak/COMDAT input is not a selected link
winner; constant-initializer records remain unexecuted. Passing this producer,
reader and callback-transport scope does not implement C++ object construction,
native metadata certification or process execution admission.

The independent ABI materialization consumer now checks represented declared
source bytes, layout value masks and validated symbolic writes through the actual
phase-independent source-data API. Its 50 materialization tests, four source-data
tests and four source-comparison tests run in normal and optimized modes. They
preserve the original source owner, snapshot and cumulative budget; huge zero tails
remain symbolic. A ready result denotes defined pre-relocation bytes; a deferred
result denotes validated symbolic leaves. Neither result supplies a relocated
pointer, constructed C++ object, selected provider or runtime authority. Constants
remain unexecuted. Malformed known writes must reject before unsupported-content
refusal. Captured-source receipts record the exact implementation tested; the CI
job registers these checks without claiming that hosted CI has already run.

Revision rejection tests replace each root with fewer than four bytes or a wrong
revision word, including an ABI revision 1 word without a record body. They require
`WIRE-REVISION` before schema-dependent parsing. The independent C++
`--candidate-records` probe composes framing and ordered-record decoding with
canonical re-encoding. Its `decoded-records` result does not check content identity
or semantic validity; a separate test demonstrates that altered, stale-identity
bytes can pass this mode while failing the Python candidate identity check.

The standalone Rust public decode and static-verification APIs also consume
independently generated sparse revision mutations for every required root. These
retain stale content identities intentionally: each API must report the exact
revision error before identity or semantic checks. The generator records each
mutation's full-object checksum and preserves the original ABI1 object bytes.
This precedence coverage does not establish semantic admission for other objects.

The integrator's exact positive, boundary and rejection method mapping is
[`conformance/envelope/coverage/component.json`](conformance/envelope/coverage/component.json).
It specifies required witnesses and their oracle boundaries. It contains no
derived pass/fail result; current receipts supply observations separately.

Scoped complete-module reference tests encode and hash ten roots, run the actual
ABI, execution and runtime-root verifiers, independently recompute content identity,
and bind a single-module deployment. One object returns42; a separately source-ABI
verified wrapper calls the two-result memory.map primitive, stores and reloads42
through its freshly issued pointer. The reference effect ticket commits once;
duplicate completion/cancellation cannot publish another result. Rehashed invalid
SSA, unknown capability and wrong-site candidates must fail semantic checks.
A source-storage/TLS object additionally follows a data-address relocation with
provenance and computes27+7+8=42 using distinct allocation and typed-access bindings.
The reference CLI requires independent capability grants and rejects unsupported
composition explicitly. These single-module tests exclude COMDAT, dependencies,
native domains and executable startup.
They establish reference composition, not production admission or parallel memory.

The public `run-candidate-reference` command reads the canonical 6269-byte
`conformance/envelope/candidate/reference-execution/call42.smo`, performs actual
ten-root content/ABI/execution/runtime admission, obtains a nonnull code address,
binds an ordinary plan and enters the indirect source call. Its observed result
is integer 42 in seven guest steps. Explicit policy supplies all source/registry
quotas and fuel/frame limits. Normal and optimized conformance runs separately
audit every consumed source input and subprocess optimization mode. The source
assembler/disassembler in `tools/smir-format/smir.py` permits editing/rebuilding
these records, retains opaque metadata and checks exact round trips. Assembly
grants no semantic authority: a representation-valid undefined SSA use must fail
before guest execution. A separately authored add-one body executes to 43 in nine
steps through the same binding and call path. These remain finite sequential
reference witnesses, with production/compiler gates recorded independently.


The integer entry extension uses explicit Int1 through Int64 byte widths, zero
unused high bits, void results and multiple independently typed integer results.
Its unchanged pre-extension add64 object now executes UINT64_MAX plus one to zero
in four steps. Fourteen source-authoring and CLI methods pass in each mode on an
actual captured foundation, with every child process checked for optimization
mode and consumed-input drift. They include a generic wide internal call and a
bound pointer returned through a generic frame before an ordinary source call.
Opaque public entry values, malformed integer encodings, Int65, unsupported
variadic signatures and conflicting source plans reject before Machine entry.
A separately reviewed finite extension now checks every used original source
plan before Machine construction and supports the ten named signed/unsigned
C23/C++23 integer builtin types at 8, 16, 32 and 64 bits, with direct parameters
and scalar or canonical None-void results. The original Long64 before object
completes genuine address/bind/indirect execution with the same bits in seven
steps. Development witnesses cover all ten names, mixed parameters and void.
Nineteen public source/CLI methods pass in each mode on the corrected captured
source: 80 consumed inputs and 55 audited Python processes per mode, with zero
drift/unwatched inputs and correct child optimization. The original seven-method
byte CLI suite also passes in each mode. Their combined consumed-source union
contains 81 files matching that recorded cut; the preceding fourteen-method receipt
remains historical for its earlier codec hash. A later optional record-identity
repair changes one of those dependencies. On the resulting captured tree, four
affected bound-call/refusal methods pass in each mode with 79 consumed inputs and
nine process audits per mode; 13 typed-source-join methods per mode and all 154
Rust static library tests plus three doctests also pass. These focused results do
not transfer the complete nineteen-method receipt to a new source cut.
Plain char, Some(void), hidden,
variadic, aggregate/pointer/FP source boundaries and native adapters remain
explicitly outside this reviewed command subset.

A separate two-module witness validates all ten roots in each object, compares
actual source call plans with the ABI graph, projects actual function definitions
through the independent LLVM comparison reference, selects a whole COMDAT group,
and follows the selected qualified function to sequential reference execution.
Its scalar Any-selection case returns42. Typed export lookup rejects an admitted
incompatible source descriptor before issuance and issues one reference callable
token for the selected provider on a match. Its same-ABI/different-body ExactMatch
case rejects. A separate actual exception-carrier function returns semantic
selectors42 and73 in the two modules; ExactMatch must reject these different
outputs despite alpha-local handler IDs. This bounded witness does not broaden the single-module CLI or
establish dependency loading, complex lifecycle recipes or native execution.

The same complete-module witness distinguishes numeric code-token guesses from
issued pointers. A guessed token survives numeric casts without gaining an origin
or CODE exposure; an actually issued provider token still performs an indirect
call returning42. Separately, owner witnesses check external TLS with distinct
consumer/export/symbol/segment IDs and weak absence against every provider
snapshot. These results remain reference evidence, with exact input hashes and
current-versus-historical validity required in receipts.

Full binary rejection fixtures retain valid representation/content hashes and
individually valid execution/ABI records while deliberately contradicting the
runtime association: source symbol versus function body, TLS initializer or
destructor signature, and import symbol versus actual import signature. A test
must observe the specified semantic diagnostic; an import/setup/schema error
does not satisfy that rejection expectation. Coordinated schema/catalog changes
require each owner to migrate its fixtures and preserve the earlier observations.

CONF-003: Executable qualification requires independent mathematical/ISA/ABI
expectations, LLVM source/IR tests and native compiler witnesses. Compare O0 and
optimized SMIR interpretation, then JIT. Check raw FP bits and status, atomics,
precise traps and observable effects rather than return values alone.

CONF-004: Qualify Linux/macOS/Windows x x86-64/AArch64 hosts with interpreter,
native JIT, explicit loading, installed launcher and embedded-runtime executable.
Exercise all three personalities and both guest-ISA library configurations.
Native qualification cannot be replaced by cross-compilation or skipped tests.

CONF-005: Concurrency tests cover simultaneous access/unmap, shared aliases,
COW, publication/reclamation, lost wakeups, cancellation, callbacks, TLS teardown,
module unload and process clone. Use race instrumentation and bounded protocol
model checking in addition to stress tests. Preserve existing personality tests.

CONF-006: ABI witnesses cover bit-fields, alignas, varargs, aggregate passing,
virtual/multiple inheritance, member pointers, RTTI, throwing across both domain
boundaries, nested callbacks, rethrow and exception_ptr. Include incompatible
layout/ownership descriptors as rejection tests.

CONF-007: Record source/tool revisions, capabilities, CPU/OS, fixture hashes,
seeds, counts and exclusions in qualification receipts. Stable IDs/bytes need
backward compatibility tests. Performance work follows semantic qualification
and reports workload, repetitions and dispersion; no speed threshold is claimed.

## Executable gate accounting

`compiler-contract.json` assigns every compiler-facing requirement to a named
component and role. `requirements.json` uses `draft` for unresolved contracts;
`verified-reference-only` means only the explicitly identified reference subset,
and never production interpretation or native execution. Existing framing tests
retain `verified-framing-only`. `validation.json` separates historical receipts
from current-run receipts and hashes their source/fixture inputs.

Candidate registries and interface decisions contain contract bytes, without a
derived compiler-freeze result. `status.json` records that result, checked against
the complete blocker calculation. Status, validation, compiler-contract and
contract-closure accounting files remain outside candidate artifacts, including
through symbolic links or hard links. Publishing a gate result therefore preserves the exact
contract bytes reviewed and tested. This does not relax any schema, hash,
acknowledgement or independent-witness requirement.

Revision2 accounting also requires an exact-digest review from every role,
including the integrator, covering each role's assigned compiler components.
`candidate_acknowledgements` records the actual review text and its checksum
outside candidate inputs. Missing, stale or incomplete reviews block the gate;
unknown, duplicate or corrupted records reject accounting. Text checksums protect
the recorded statement and do not authenticate its author or prove its semantics.

Run both accounting modes from the repository root:

```sh
python3 tools/smir-format/check_spec.py
python3 -O tools/smir-format/check_spec.py
python3 tools/smir-format/check_spec.py --require-compiler-freeze
```

The first two commands can pass while reporting `INCOMPLETE`: they validate
consistent accounting of an unfinished implementation. The last exits 1 until
all required components, section payloads, cross-role decisions, independent
positive/boundary/rejection witnesses and candidate hashes qualify. This expected
failure is a gate result, not a passing compiler conformance test. Duplicate JSON
keys, missing artifacts and stale source/receipt hashes are accounting errors.
An edited or skipped witness cannot inherit a previous receipt.

The checker cannot establish the truth of an independence declaration, the
mathematical completeness of a schema, or a reviewer acknowledgement. Review
those claims against the archived primary sources and actual tool behavior.
Compiler freeze requires that review in addition to the mechanical checks.
Release qualification remains a separate gate, including actual production
execution and the complete native host matrix. No reference harness admits a
`DecodedEnvelope` to a production interpreter or JIT.


The final internal-Null reference slice qualifies codec
`e95c3d0425defe43ca083e79d20e92bd29b0f6c230cd570115a29cd44439d08d`
on an immutable3028-file actualfoundation cut. All27 publicCLI methods pass in
each Python mode (19 original+8 new), with83consumed inputs/106actualprocess
audits per mode, zero drift/unwatched inputs, and exactchild optimization0/1.
The seven byteCLI methods pass in both modes (78consumed/15audits each),
23canonicaljoin/callback methods pass in each mode, and163Rustlibrary+3doc tests
pass. The union103consumed source/fixture/schema inputs matches the live tree.
The new7038-octet wrapper returns Int1true in14actualgueststeps through genuine
address/bind/indirect/sourcephi/completion; the original6558-octet object remains
unchanged and staticallyverified with executable_admitted=false/sevenruntime
obligations. Independent runtime40outcomes per mode andsemantics9checks per
mode remain separatelyscoped receipts. No production/generalpointermemory,
parallel/JIT/nativeguest/LLVMbackend/hosted/foreignCpp/fullplatform result follows.

The Python entry-association repair is qualified on the actual dirty foundation
`entry-import-repair-combined-r3`: 330 execution tests in each Python mode,
7 byte CLI tests in each mode and the NULL diamond CLI in each mode. All 232
consumed source files match the current tree; process audits record no drift or
unwatched inputs. The earlier 315-test runs failed three codec import checks;
those failed receipts remain intact. A unique explicit fixture-codec import
restores legacy codec discovery without changing either codec. Hidden this/VTT/
sret entry associations preserve actual ABI and lowered signature checks. Source
method calls and CLI method entries remain refused. That earlier Rust CLI rejected
all four authored entries at its ABI coverage limit. The current finite Rust
nonordinary-entry implementation accepts those four original objects and the
other three positive fixtures. Root validation passes 167 library tests and
3 documentation tests; the 23 current CLI cases yield 7 verified objects,
10 semantic rejections and 6 unavailable results. The original ordinary ABI
source-call guard remains in force. These results establish reference/static
behavior; native C++ execution and compiler freeze remain incomplete. The runtime source-contract checker has separate retained-
call and parent-context correction receipts. The current finite grounding product
is qualified separately: 414 combined execution tests pass in normal and optimized
Python, with 288 consumed inputs and 145 process audits per mode. Its 56 products
and all consumed source hashes match the current tree. Independent ABI checks
cover 24 cases per mode; LLVM independently checks three abstract metering probes
per mode. These are separate evidence scopes. The root-cycle, captured receiver/
parent and repeated-vector/literal metering failures are closed for this profile.
Source operation truth, complete lifecycle/EH and active-v3 admission remain open.

The separate source-carrier package has 43 installed files and exact schema
`c64512a81e9716f1870e77c266d9de8aebf2b6ee7779f5dd44fb33a9aa8f9cb0`.
The earlier repaired R11 composition passes 225 runtime and 450 execution tests
per mode at its archived source cut. Earlier R10 registry/provenance failures and
all historical receipts remain unchanged; those results are not repinned.

The historical `observer-scalar-current-integration-r12` snapshot contains 3,441 files
and 110,140,137 bytes. Complete execution passes 474 tests in each mode
(297.456 s normal, 292.013 s optimized), with 315 consumed inputs and 202 process
audits per mode. Runtime passes 227 tests per mode (269.036 s, 267.699 s), with
571 consumed inputs and 222 audits per mode. Current scalar native focus passes
5 methods per mode; typed AST focus passes 9 pure and 2 native-backed methods per
mode. Their actual union has 785 consumed inputs, zero current drift and no
unwatched inputs. Every child uses the declared optimization mode and fresh cache
prefix. All 79 installed batch paths match approved hashes.

The typed observer source pass preserves complete genuine owners/stamps/budgets;
its strict inline callee/caller profile verifies logical Journal retention,
once-only adoption and the saved source value at observer PRE. Selected-closure
comparison renames only private source fields with their original graph bijection.
The scalar checker verifies a finite conditional value-body relation against an
already supplied original SMIR module and actual guarded compiler observations.
Installed owner scalar tests pass 24 native-backed and 4 pure methods per mode;
SEM observer checks pass 282 installed methods total; runtime source checks pass
128 direct methods and an actual 128-method isolated child per mode. These overlap
the Root suites and are not additive coverage counts.

The fresh installed scalar condition oracle has 720 guarded build inputs;
75 actual native processes run in each full owner mode and none in pure modes.
Root uses that same actual fresh binary for its independent focused checks.
Typed AST native observations preserve their separate exact schema and issuance
guards. Native compiler/parser observations are not native guest execution or
source ABI proof. No source3 executable, SourceRegistry or private runtime authority
is issued. The generic candidate/Rust executable reader remains revision2.

Fresh current Rust checks pass 167 library tests and 3 documentation tests
(1 ordinary, 2 compile-fail). Earlier independent Rust payload corpus results
remain as-run: 3,255 unique section payloads from 1,734 objects, 3,211 accepted and
44 rejected in each mode. They prove payload grammar/reencoding only, not module
identity/reference/source semantic admission. Full P1/P2/production gates remain
incomplete; the exact current receipts retain all scope limitations.

R14 supersedes current combined claims with exact recorded source cuts:
482 execution tests per mode from R13, 227 runtime tests per mode from repaired
R14, 23 lifecycle-budget tests per mode, and 9 independently built pinned LLVM
library witnesses per mode. All actually consumed inputs are rechecked against
current hashes. Fresh unique-target Rust compilation passes 173 library tests
and 3 documentation tests; the old R12 Rust receipt is historical rather than
current compilation-context proof. Exact source-input manifest repairs preserve
all encoded objects. Failed R13 runs and owner child-mode limitations are retained.
No whole compiler, full P2, native guest or parallel-runtime gate is promoted.

R15 current scalar Raw8 qualification: execution494 per mode
(300.399s normal/297.964s optimized); runtime227 per mode
(267.307s/267.074s); 763 actually consumed inputs current with zero drift.
Fresh unique-target Rust174+3 passes. New67 static cases and12 actual sequential
reference methods are included, not additional independent coverage totals.
Root primary archive/CI/required-union ledger changes were unconsumed metadata
and are recorded separately. No full compiler or production gate is promoted.

R16 metadata closure changes only fixture_provenance.py dependency declarations
and13 manifest input-hash maps. Original13 generators reproduce839objects/
6239837encoded octets in each mode at both freshfrozen and actualinstalledtargets;
888actualinputs have0unlisted/changed sources and1877SMOs remain byteexact.
Root current17registryconsumer tests per mode andfreshRust174+3 pass. Only the
function-address manifest in earlier763consumed paths changed, with all cases
and noninput metadata equal. WholeR15 counts remain asrun; R16 is scoped
focused requalification of that exactmetadata-only change.

R18 CodeAddress byte-relay qualification runs 503 execution tests per mode
(normal 442.739 s; optimized 415.422 s), with 328 consumed project inputs and
213 process audits per mode. The owner separately passes 101 tests per mode and
all nonwriting fixture checks, with actual child mode and fresh-cache flags
verified. Ten new encoded profiles and one foreign producer exercise the genuine
registry; successful binding returns 42 and every negative publishes no permit
or entry. CI fixture reproduction and 15 workflow policy tests pass. Runtime
and Rust suites were not rerun for this Python-only package; prior receipts stay
as run. Original roots remain live, so storage-holder reclamation and LLVM or
source ABI revision 2 transport are not established.

R20/R21 source-ABI epoch qualification: full execution 503 and runtime 227 tests
per Python mode, plus ABI 64+13 per mode and fresh installed Rust 178+3, pass.
The R20 native record oracle was freshly built; SDK/compiler subprocess inputs
remain subject to its recorded evidence limit. R21 changes only a test runner
and CI registration: ordered/reverse 14, legacy reference 28, discovery 6, epoch
13 and full ABI 64 tests per mode pass with actual parent/child flags and absent
cache prefixes. Fifteen workflow policy tests and fixture checks pass. The broad
R20 run remains as run; only its changed test runner was requalified. All 823
consumed current source hashes match. The original ordered-import failure and
pre-existing broad-discovery collision are retained in the integrator records;
no test is skipped or replaced by a positive validator. Source ABI 2 remains
unavailable without genuine category evidence; no source admission follows.

R22 independently captures the installed SourceValueFlow exact7 package and runs
the complete execution suite:517 normal and517 optimized tests,0 failures/errors/
skips,213 actual process audits and333 consumed project inputs per mode. Parent
and child optimization/dontwrite flags and absent fresh cache prefixes are checked.
Owner focused115 tests and five nonwriting fixture groups pass in each mode.
The39 cases cover6 positive/33 rejection assertions across5 complete modules
(5005449 octets). CI policy15 passes. Combined current source closure is856
consumed hashes,0 drift; prior unchanged runtime227/ABI77/Rust178+3 remain as-run.

Original failed guard cuts and metaclass callback counter remain historical; the
accepted checker validates exact primitives before lookup and bounds schema reads
by captured extent plus1 octet. Local guarded quotas are tested; full delegated
factory costs remain unqualified. No actual source/private dynamic event issuer,
source ABI2 execution, compiler freeze or production qualification is established.

R25 installs58 mapped worker paths: native observer40, quiescent union14,
unbuffered SourceValueFlow repair3 and schema-audit test repair1. Root captures
3596 files/119153165 octets and freshly reruns517 execution and230 runtime tests
per Python mode. Actual213 execution and223 runtime process audits per mode
verify optimization/dontwrite/cache-start absence and source hashes. No unexpected
inputs, bytecode products or source drift are observed. Independent installed
native checks pass40 per mode plus four CLI checks; pure10 checks also pass.
The native build guards725 inputs. Current consumed union is908 hashes,0 drift.

The earlier230-test runtime cut failed only its stale nine-schema assertion in
both modes; both failures remain immutable. The repaired explicit ten-schema
test audits all ten schemas and adds20 per-schema unknown-keyword negatives while
preserving the original two global negatives. Fresh complete230-test runs pass.
Owner focused union checks run42direct/42child/42hostile-path/1outer/8inventory
per normal/O/OO mode; all1878 prior SMOs remain byte-exact. SourceValueFlow
unbuffered checks run14 per mode and five fixture groups per mode.

These qualify finite references and test integration. They do not issue actual
source facts, full cost/allocator guarantees, portable source ABI2 admission,
production parallel/runtime/JIT/emitter or full-host conformance. ABI77 and
Rust178+3 are earlier unchanged as-run checks with current source guards.

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

R28 receipt NESTED-REFERENCE-current-intake-r28.json records 233 runtime tests and 224 actual process audits per Python mode at the pre-relocation cut, plus fresh six-parent normal/O/OO checks under the new coordination prefix. Full30 and selected1 child tests preserve parent namespaces; no-match selection runs zero children. The explicit eleven-schema audit retains every earlier positive and rejection probe; all 1878 prior SMOs remain byte-exact. The current consumed union is 931 hashes with zero drift. Older receipts remain immutable as-run evidence.
