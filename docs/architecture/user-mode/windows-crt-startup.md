# Windows CRT argument and environment startup

Startup dependency group against baseline `0753ca1c0b769da93d24390d1f24c4aad070b9d2`.
The whole Windows userland objective remains unproven. This group implements
actual argument/environment dependencies, not substitute `main`, standard-I/O,
floating-point, locale, exit, or on-exit stubs.

## Acceptance criteria

1. Genuine architecture-filtered MSVCRT data and function exports and UCRT
   startup leaf exports; no UCRT `__getmainargs` import fabricated from its
   static wrapper.
2. Guest-authoritative, pointer-width-correct cells, per-runtime process
   ownership, raw guest process parameters, separately owned rollback storage,
   and loader publication only after fallible initialization.
3. Microsoft C argument parsing, including the special program-name rule,
   narrow conversion before parsing, wide raw UTF-16 preservation, actual
   requested wildcard expansion, and terminated argument/environment vectors.
4. UCRT configure/environment/initial-environment/path/WinMain-tail services;
   modern legacy five-argument getters; new-mode state required by the actual
   UCRT static wrapper. Invalid parameters use real guest handler continuations.
5. Strategic all-ABI unit and independently compiled guest PE tests, preserved
   prechange CLI results, full reachable Windows runner, appropriate build/test
   gates, final adversarial diff and provenance audit.
6. Exact path staging followed by `red -m --staged --run` with those paths;
   independently verify commit and immediately push `origin user-win`.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| S1 | Modern XP-or-later legacy getter ABI is selected | Retained MinGW bridge source describes the pre-XP void/modern-int difference | Five-argument getter return convention | Failure leaves output arguments unchanged | Compare pinned pre-XP and modern native CRT binaries | Retained profile |
| S2 | Empty raw command line yields one empty program argument; leading whitespace yields empty argv0 | Public parsing page does not specify these raw boundary inputs | Boundary parser tests | Empty, NUL-first, whitespace-only | Native raw-input parser probe, separately recording OS substitution | Retained; native result unknown |
| S3 | Repeated same active-width/mode preserves guest-mutated cells; mode or width transitions reparse the exposed command buffer | One shared argc must remain consistent with the selected vector; private repeated-call behavior is unspecified | Stable uninterrupted cells; coherent width transitions | Narrow→wide→narrow with conversion-dependent counts; mutate cells then repeat | Pinned native UCRT observation of width/mode sequences and mutations | Revised after independent red-team; native cross-width identity unknown |
| S4 | The current process ACP profile is Windows 1252; unsupported supplementary/unpaired UTF-16 units each emit default byte | Existing engine ACP profile plus retained Windows BestFit mapping, not the older generic CP1252 table | Narrow command/path/environment conversion | Fullwidth quote; all mappings; surrogate pair/unpaired unit | Native CP1252 WideCharToMultiByte cardinality and manifest-ACP probes | Retained; surrogate cardinality unknown |
| S5 | Wildcards expand the last component only; leading-quoted arguments are preserved; matched names are deterministically ordered | Dedicated wildcard contract and explicit filesystem personality profile | Expanded argv | No match, extensionless `*.*`, quoted pattern, unsupported namespace | Native CRT enumeration/quote/collation probe on pinned filesystem | Retained; native ordering and private quote policy unknown |
| S6 | CRT storage may use separately owned checked VM allocations while observable public pointers/cells obey the API contract | Exact prepublication release is unavailable through retained private-heap capacity | Transaction rollback and process-pinned startup ownership | Source fault, OOM, late LDR failure, importer rollback | Allocation and live-module/trap snapshots in strategic tests | Confirmed engine ownership profile by all-ABI snapshots; native allocator identity unknown |
| S7 | Initial narrow environment is prepared at DLL installation; wide snapshot is initialized on demand; params==0 means empty input except live EXE path | Explicit engine startup profile; normal spawning establishes parameters first | Initial pointer timing and process-only loader tests | Empty environment, no threads, params==0, mutated current cells | Pinned native CRT initialization-time snapshots; all-ABI tests | Retained; native pointer timing unknown |
| S8 | Formal arguments are read in descriptor order, retaining successful reads; completed environment/PTD stages persist if a later argv stage faults/fails | Checked HLE frontier and owned staged startup state, not a native private fault-order oracle | Repair continuations and failure atomicity boundary | Fifth stack-formal fault, register/stack clobber, source fault and argv OOM after wide environment publication | Unit frontier probes and compiled actual vectored repair; pinned native CRT trace for fault-order equivalence | Confirmed engine profile by units and output/configure VEH probes; native ordering unknown |

## Layout and algorithm contracts

Windows C `int` is 32 bits. Guest pointers occupy P=4 bytes (x86) or P=8 bytes
(x64/ARM64); Windows wide characters are 16-bit units, not host `wchar_t`.
For A strings, lengths L_i code units and W=1 or 2 bytes/unit, the single vector
payload size is `(A+1)*P + sum((L_i+1)*W)` bytes, including the final NULL pointer
and every string terminator. Multiplication/addition and guest-width addresses
are checked; there is no silent truncation or host pointer dereference.

The fifth getter formal has index i=4. x86 reads at
`ESP + 4 bytes + 4*4 bytes = ESP + 20 bytes`; x64 reads at
`RSP + 8 bytes + 4*8 bytes = RSP + 40 bytes`. ARM64 uses X4 with no analogous
fifth-formal stack read. A fault at the latter stack slot retains the preceding
decoded values; the inaccessible unread slot is not assigned an invented value.
Resuming the same API frontier retries that read, then its captured request.

CRT parsing is O(N) time/output in raw input units. CP1252 conversion is
O(N log 698) time/O(N) output. WinMain-tail scanning follows the retained
compiler glue's control-padding (`<=0x20`) profile rather than the C argument
parser's space/tab rule; native private implementation equivalence is unknown.
Wildcard matching uses nonrecursive DOS-token frontiers: O(Pattern*Name) time,
O(Pattern) scratch per name. Sorting uses deterministic raw UTF-16 ordinal
comparison, not a claimed native enumeration/case/8.3 table.

Caller-output preflight precedes initialization. Successful environment
initialization remains process-owned if subsequent argv construction faults or
fails; the whole getter is not an atomic rollback transaction. Retry retains
decoded inputs and any already-read `startInfo.newmode`, rechecks remaining
work, and does not duplicate the completed environment allocation.

The partial-OOM probe leaves exactly 4096 bytes of commitment available. Its
small wide environment fits one page. A single 9000-unit argument requires
`(1+1)*P + (9000+1)*2` bytes: 18010 bytes on x86 or 18018 bytes on x64/ARM64,
each rounded to 20480 committed bytes. Environment publication consumes the
remaining page; argv admission then fails without caller-output changes or
duplicate environment storage. Releasing the test's filler permits success.
These are exact integer sizes, without measurement uncertainty.

## Change-surface map

| Plane | Assessment |
|---|---|
| Direct decode / execute | Unchanged ISA semantics; compiled probes exercise existing cores |
| CPU state | Existing HLE ABI state marshaling; no architectural state extension |
| Memory/MMU | Checked cells/buffers and owned VM allocations; translation contract unchanged |
| SMIR lift / IR / interpreter | No operation or lifter change |
| Optimizer / native lowering / JIT runtime | No admission or lowering change; no new native claim |
| Backend / machine / device | Unchanged; process-level Windows personality only |
| Oracle / analysis / C ABI | Unchanged; no C layout/status/enum change |
| Public Rust | Existing `init_data_exports` no-op retained and deprecated for source compatibility; loader uses internal fallible prepare/commit/abort instead |
| Loader / CRT | Data publication, startup storage, exports, argument/environment services affected |
| Tests / docs | Unit, registered compiled-PE runner, retained primary inputs, this audit record |

## Bounded discoveries

| Impact | Evidence / boundary | Blocks this group? |
|---|---|---|
| High | Ordinary linked `main`/`wmain` still requires real stdio, exit/onexit, locale and floating-point initialization services | No; blocks whole-goal completion |
| Medium | Native private startup timing, repeated-call identity, wildcard ordering/8.3 aliases and surrogate replacement cardinality are unknown | No; explicit profiles and falsification probes above |
| Medium | Wildcard directory lookup follows host directory symlinks and enumeration is not an atomic namespace snapshot; Windows reparse-point equivalence or drive confinement is not claimed | No; preserves the existing mapped-host filesystem boundary; immutable controlled inputs are verified by the runner |
| Medium | Existing loader failure consumes monotonic address cursor/history; abort removes live payload/image/traps, not historical indices | No; preserved existing contract |
| Medium | If LDR unlink cleanup itself fails, existing chained image release can retain mappings with a fatal `p.fail` diagnostic; resource recovery is not unconditional | No; successful-cleanup rollback is tested, corrupted-cleanup recovery is not claimed |
| High | Guest commitment OOM is handled, but infallible host Vec parsing/conversion/clone paths do not establish complete host-global OOM containment | No; host-memory pressure beyond tested guest admission remains unknown and requires subsequent resource-policy work |
| Medium | Existing `kernel::command_line_a` explicitly rejects non-ASCII conversion; the new best-fit table is currently used only by CRT startup, not every ANSI API | No for this dependency group; broader Windows ANSI coverage remains incomplete, without a fabricated successful conversion |

## Provenance and verification

Primary inputs are retained in
[`crt-startup`](../../specifications/windows/crt-startup/README.md) and the
previous [initializer archive](../../specifications/windows/crt-initializers/README.md).
Raw source/license bytes are not normalized. Generated CP1252 implementation
must match its retained input SHA and generator output. Compiler fixtures prove
executed dependency graphs, not native Windows equivalence or ordinary CRT
startup completion.

## Requirement evidence

| Criterion | Direct evidence |
|---|---|
| 1: binding admission | `startup/exports.rs`, all-ABI binding and actual loader-lookup tests; 45 independently compiled exact named-IAT sets in the registered runner |
| 2: ownership/publication | `startup/storage.rs`, loader prepare/commit/abort; nine storage tests and four all-ABI loader tests, including early source and late LDR failure, process pinning and compatibility-hook preservation |
| 3: parsing/conversion/expansion | Ten parser tests, three CP1252 tests, five filesystem/wildcard tests; independent raw golden PEs and controlled mapped-directory inputs |
| 4: startup APIs/retry | Active-width, environment, path, tail, new-mode, invalid-handler, alias, OOM and captured-input tests; actual static UCRT wrappers and guest VEH repairs |
| 5: reproducible validation | Commands and exact results below; 108 preserved prechange failures versus 108 successful new guest executions with identical hashed inputs |
| 6: delivery | Exact 145-path ownership set; whole-index equality is required before `red -m --staged --run`; actual commit/remote equality is verified at delivery, not inferred from this document |

This group owns the startup tree, CRT integration, loader transaction, program-
name serializer, registered runner/fixture bundle, CP1252 generator, retained
archive and three architecture records. Eleven tracked files changed against
the baseline; 134 new files are in the exact owned set. All other pre-existing
untracked material remains outside that set. No Cargo/toolchain/dependency/lock
or C-ABI file is changed.

## Validation receipts

Host: AArch64 macOS, `aarch64-apple-darwin`; stable Rust 1.98.1
(`48a229ceaefd4985c50990b14116b6d856af0985`, LLVM 22.1.8).
Commands below use `cargo +stable` and `--locked` unless noted.

| Gate | Result |
|---|---|
| Portable CRT unit filter, `test --no-default-features --lib user::windows::dll::crt -- --test-threads=1 --quiet` | 91 passed, 0 failed/ignored; 6530 filtered; includes 47 startup tests |
| Portable unfiltered library, `test --no-default-features --lib -- --test-threads=1 --quiet` | 6619 passed, 0 failed, 2 ignored, 0 filtered; 133.06 s |
| Portable registered Windows + CI targets, `test --no-default-features --test user_windows --test ci_actions_pinned -- --test-threads=1 --quiet` | Windows 191 passed, CI 10 passed; 0 failed/ignored/filtered |
| Portable workspace, `build --workspace --all-targets --no-default-features` | Passed |
| Apple-Silicon feature workspace, `build --workspace --all-targets --no-default-features --features x86_64-suite,smir-jit` | Passed |
| Serialized feature library, `test --no-default-features --features x86_64-suite,smir-jit --lib -- --test-threads=1` | 8791 passed, 0 failed, 2 ignored, 0 filtered; 965.51 s |
| CI lint selection, `clippy --workspace --all-targets --features x86_64-suite` | Passed |
| `cargo +stable fmt --all --check`; authored tracked diff whitespace | Passed |
| CP1252 generator syntax and `--check`; fixture shell syntax | Passed; 256/698 mappings; generated SHA `a4f9153abd0bfa53e5ca5ba8958bd080e3fb1988725e22e58cac759ede48d9a4` |
| Feature registered Windows + CI targets, `test --no-default-features --features x86_64-suite,smir-jit --test user_windows --test ci_actions_pinned -- --test-threads=1 --quiet` | Windows 191 passed, CI 10 passed; 0 failed/ignored/filtered |
| Portable and feature `test --doc` | Each: 0 passed/failed, 5 ignored, 0 filtered; no executed doctest coverage claimed |

The first unfiltered portable attempt found one stale foundation negative-
admission assertion for newly implemented UCRT mode functions (6617 passed,
1 failed, 2 ignored). The corrected test verifies actual UCRT plain-name
presence and legacy plain-name absence, retaining unsupported-handler and
unrelated-export rejection. The final unfiltered result above supersedes that
attempt; the failure is not omitted or treated as a passing retry without a fix.

Fixture manifest SHA is
`ba40156b9e9c21342370a7658de4cca3c1ca1e3809b438e06b918432cd2b34d3`:
29 inputs, 45 PEs totaling 196096 bytes, two byte-identical builds. Baseline
receipt SHA is `854c40d8ae1252d61c829657c1f77db94eea5ac96a8b5d811122f46e41009041`.
Its preserved CLI SHA is
`cb2fe8e1dc750165233922cf2712dac132cb42e127baf799d47322ac09d1f3ce`.
All 108 baseline executions fail explicitly for missing CRT exports, rather
than timeout, signal, skipped case or native execution. New guest executions
use scheduling slices of 1/4096 instructions; nine environment images also use
empty input, giving `45*2 + 9*2 = 108` executions.

Primary manifest SHA is
`cebc061cf7a3e9ee3e2b981c4e1dc0b0b416dc512aed94996c6c3fdd50f65887`:
60 verified inputs (46 local, 14 reused), 21 installed-input replays and nine
license/disclaimer inputs. Two acquisitions reproduce all bytes. The two
355-line CONTEXT/EXCEPTION excerpts are byte-identical and independently
corroborate the fixture's guest ABI offsets. Native private CRT fault ordering
is not established by public headers or this engine's guest execution.

Two ignored library tests concern separately built microkernel payload lifting
and exact-byte roundtrips; they were not run or counted as executed coverage.
Native Windows CRT observations are unrun because no native Windows execution
environment is available. Linux KVM and x86-64-host JIT require a different host;
HVF runtime, standalone excluded packages and C/C++ ABI runtime gates are unrun
because this group changes none of their contracts. The host is AArch64 macOS.
Library counts do not establish execution of every host-specific oracle.
Workspace compilation is not C-ABI execution. Both workspace builds report the pre-existing `librax.rlib` output
collision between root and C-API packages; dependency/package naming is outside
this group. Feature compilation is not native-backend runtime evidence.

All 144 frozen source/fixture/reference inputs remained byte-identical across
the final gates; only this audit record changed after that freeze. Authored
owned-file whitespace and architecture links passed. Raw upstream source and
license formatting is retained rather than rewritten to satisfy local style.
No parent-command RUSTFLAGS or RAX JIT switch overrides were present; compiled
PE probes explicitly set `RAX_NO_JIT=1`. Run durations are harness-reported
elapsed time, not comparative performance measurements.

## Final precommit quality audit

No ethical or normative judgment is required. The user's seven quality gates
are satisfied for implemented source behavior: assumptions and falsification
probes are registered, behavioral requirements are mapped to direct evidence,
integer calculations are reproducible, contradictions are reconciled,
provenance is verified, and scope expansion is bounded. Native profile unknowns
are not converted into architectural facts.

| Repository gate | Reconciliation |
|---|---|
| QG1: assumptions | S1–S8 registered; S3 revised by adversarial width/count testing; S6/S8 confirmed as engine profiles, not native allocator/fault-order equivalence |
| QG2: coverage | Criteria 1–5 have source and executed evidence above; criterion 6 requires exact index/commit/remote verification at delivery |
| QG3: reproducibility | Pointer/int/UTF-16 widths, layout/commit arithmetic, compiler inputs, full corpus and primary hashes verified |
| QG4: edges | Active-width count bug and staged-formal gap resolved; failed allocations/output faults preserve tested boundaries; late cleanup and native-private limits disclosed |
| QG5: provenance | 60 retained inputs and installed replay checked; producer/native unknowns explicitly retained |
| QG6: bounded expansion | Remaining ordinary startup, ANSI, host-OOM, filesystem and cleanup issues impact-labeled; no unrelated semantic edits |
| QG7: ownership | Exact 145-file set only; original tracked-clean baseline and unrelated untracked material preserved; final stage must equal the entire index |
| QG8: behavior | 47 new startup tests, four all-ABI loader tests, 108 new compiled guest executions, both full library selections and both registered Windows selections; ignored/unrun gates distinguished |
| QG9: consistency | Canonical ownership, registered Cargo target, generated table/provenance, actual IAT sets, public compatibility hook and documentation agree |

Publication is verified separately against actual Git state after this record
is committed; no self-referential commit hash or premature push claim is stored.
The whole Windows userland goal remains active. Ordinary linked CRT startup,
stdio/termination, locale/FP and broader ANSI services remain required; native
Windows equivalence is not claimed.
