# Windows CRT initializer tables

This group implements a required ordinary CRT startup dependency for x86,
x64 and ARM64: MSVCRT `_initterm` (plus `_initterm_e` on ARM64), and UCRT
`_initterm` / `_initterm_e` on all three ABIs.
It does not establish ordinary MSVC/MinGW startup, C++ exception handling,
argument/environment publication, onexit tables, termination or stream I/O.
These remain requirements of the continuing Windows userland objective.

## Acceptance and ownership

1. Admit only evidenced named imports. Legacy `_initterm_e` on x86/x64 remains
   excluded: the installed MinGW archives supply a static compatibility member,
   not a native MSVCRT import. Primary ARM-conditional DEF evidence establishes
   ARM64 admission instead. UCRT's runtime API-set reaches the same host.
2. Traverse an ascending, end-exclusive table of 4-byte (x86) or 8-byte
   (x64/ARM64) guest pointers. Skip NULL entries without calling them.
3. Execute actual zero-argument guest callbacks through the checked HLE ABI.
   Read future entries only after prior callbacks return; nested calls retain
   their independent cursor and endpoint. No host-recursive table traversal,
   whole-table snapshot or artificial entry-count cap is permitted.
4. `_initterm` returns void and disregards callback integer registers.
   `_initterm_e` interprets exactly 32 return bits, stops at the first nonzero
   result, and returns those bits unchanged; an exhausted table returns zero.
5. Guest memory faults preserve completed callback effects, do not execute later
   entries and do not become a successful initialization. Pointer arithmetic is
   checked against guest width; empty/reversed ranges perform no memory access.
   Handler repair resumes the faulting table read with its captured cursor/end,
   without replaying prior callbacks or re-reading clobbered API arguments.
6. Cross-ABI adversarial units and reproducible compiled constructor-table PE
   fixtures test actual import/callback transitions. Observe pre-change failure
   on the same final binaries and protect fixture inputs from guest writes.

Baseline HEAD: `b7498e58030bc0317cfa96845b509c9335c8fb30`. The tracked tree and
index were clean. The pre-change CLI was preserved before any build at
`/tmp/rax-crt-startup-baseline.yu6Sb0/rax-user`, SHA-256
`8ab3fbeafd5f8cf379fcdf0f826ffd89eb573a3db00c97558df151c278253fc5`.
It is a regression baseline, not an independent Windows oracle.

Owned paths: `src/user/windows/dll/crt/initialize{,_tests}.rs`, the CRT facade,
CRT test helpers and DLL registry; the registered runner
`tests/suites/user/windows/crt_init.rs` and fixture directory
`tests/fixtures/user/windows/crt_init/`; this record, Windows/test/
reference indexes, and `docs/specifications/windows/crt-initializers/`.
Unrelated pre-existing untracked material remains user-owned.
The checked HLE flow/frame/dispatch and its retry regression tests are also
owned; scheduler/fiber test constructors add the new retry field mechanically.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| I1 | Named admission follows retained import binding evidence, not every native DLL version's export inventory | Real IAT symbols versus MinGW static compatibility members and ARM DEF | MSVCRT/UCRT asymmetry and API-set fixture graph | Legacy `_initterm_e` absent on x86/x64 but admitted on ARM64 | Capture exports of a pinned native Windows DLL | Confirmed toolchain/fixture distinctions; retained native-version profile, complete native inventory unknown |
| I2 | The checked HLE frontier defines fault behavior for malformed tables; exact native partial-completion and malformed-range policy are unknown | Existing checked memory/callback infrastructure, no native execution oracle | Width-overflow rejection, page faults and retained earlier effects | Last pointer crossing an inaccessible page; callback removes a future mapping | Execute identical hostile input on pinned native Windows | Confirmed units/guest AV+guard repair; retained explicit native-unverified personality profile |
| I3 | Future pointer entries are read when reached, not snapshotted before the first callback | Retained initializer implementation and C table-walking startup pattern | Callback mutation/reentrant traversal | Replace a future entry from a nested callback | Native trace observes old rather than newly written entry | Confirmed units and compiled mutation/nesting probes; retained source-derived profile, native confirmation unknown |
| I4 | Compiled custom-entry constructor probes do not prove ordinary compiler startup | Actual crt2/crtexe dependency audit contains argument, onexit, stdio and FP services not implemented here | Completion boundary | Link and execute unmodified ordinary main/wmain startup | Genuine compiler-startup executable reaches main and exits correctly | Confirmed boundary; ordinary startup incomplete |

Microsoft's combined `_initterm` / `_initterm_e` API-location list includes
MSVCRT but does not distinguish function-level/version-specific availability.
This conflicts with treating the installed static compatibility member as a
native import on x86/x64. Primary MinGW ARM DEF evidence gives the distinct
ARM64 binding. Named admission follows these evidence classes [I1], without
claiming universal native absence. Its prose also does not
explicitly establish lazy reads or the precise native first-error frontier.
The source-derived profiles [I2, I3] are retained explicitly, not presented as
native differential observations.

## Change-surface map

| Plane | Status and reason |
|---|---|
| Direct decode | Unchanged; compiled callbacks use existing decoders |
| Direct execute | Unchanged semantics; exercised by all guest fixture ABIs |
| CPU state | Affected HLE retry frames retain original frontier/return/cursor; no architectural CPU state extension |
| Memory/MMU | Existing checked pointer reads and callback-stack preparation; no memory contract change |
| SMIR lift | Unchanged; no instruction or IR addition |
| SMIR IR | Unchanged; no new operation |
| SMIR interpreter | Unchanged; guest CPU adapter retains its existing execution path |
| Optimizer | Unchanged; HLE callback frontier remains opaque |
| Native lowering | Unchanged; no native admission is added |
| JIT runtime | Unchanged; controlled guest probes isolate the interpreter with RAX_NO_JIT |
| Backend | Unchanged; process-level HLE, not VM backend state |
| Machine/device | Unchanged; no board or device behavior |
| Oracle/analysis | Unchanged; no stateless decode/effects changes |
| C ABI | Unchanged; no public C identifiers, layout or implementation changes |
| Public Rust | Existing paths remain, but public Flow gains RetryFault and public Frame gains retry; old exhaustive matches/struct literals require updates |
| Tests/docs | Affected; unit, compiled guest, hash/import/baseline and primary-source evidence |

## Algorithm and bounds

For pointer size P in {4, 8} bytes, read the current P-byte entry only when
cursor < end. A non-NULL entry calls the guest with zero arguments. Upon its
return, `_initterm_e` first reduces the integer register to uint32_t; a nonzero
value returns immediately. Otherwise advance cursor by P bytes with checked
addition and reject any result outside the architecture's pointer width.
NULL entries use the same advancement without a guest call. No entry at end is
read. Valid table spans contain N = (end - first) / P pointer entries; there is
no rounding or truncation of a valid span. Invalid spans use the separately
documented checked-memory profile [I2].

Traversal costs O(N) time plus guest callback costs and O(1) host auxiliary
space per active invocation. Nested guest invocations consume their existing
guest/HLE frames; the host does not recurse once for every table entry. Earlier
callback side effects are not rolled back if a later read or callback faults.
Neither errno nor Win32 LastError is assigned by traversal itself.

On a checked table read fault, a separate HLE retry continuation captures the
current cursor, endpoint and function kind. The ordinary memory classifier
consumes a one-shot guard and dispatches SEH while retaining this frame. If a
handler resumes the same export PC and entry SP, dispatch takes the retry before
reading arguments or return-address storage. A context leaving that frontier
at the same stack height discards it; lower handler stacks retain it. Ordinary
pruning and terminal frame teardown drop it. Callback continuations and retry
continuations are distinct; an initializer has no process-global retry cursor.
Existing callback-stack preparation/failure semantics are unchanged.

The HLE types are publicly reachable Rust implementation surfaces. Adding the
`Flow::RetryFault` variant and `Frame::retry` field is source-breaking for old
external exhaustive matches and struct literals. All tracked construction and
dispatch sites were searched and updated; no C ABI change is made. External
consumers are unknown; their compatibility is not assumed.

## Bounded findings

| Impact | Evidence and boundary | Blocks this group? |
|---|---|---|
| High | Ordinary startup's argument/environment, onexit/exit, stdio and FP dependency graph is still incomplete; actual installed crt2/crtexe inspection | No; blocks whole-objective completion |
| High | Data-export initialization is currently an infallible no-op after loader publication; future CRT data publication requires checked initialization/rollback | No data exports added here |
| Medium | Native Windows execution and full version-specific DLL export inventory are unavailable | No; retained public/source-derived profile, not native equivalence |
| Medium | Both workspace builds warn that engine and C API library targets share `target/debug/librax.rlib`; pre-existing package naming | No; no incidental package/dependency change |
| Medium | Existing fiber machinery parks per-fiber HLE frames but rejects cross-thread migration while an ordinary API frame is live | No fiber contract changed; constructor migration is not claimed |
| Medium | The newly retained ARM DEF also declares legacy `_get_errno`, `_get_doserrno` and `_set_doserrno`; foundation admission still excludes them | Separate legacy ARM error-state follow-up; no universal native absence claim |
| Low | Compiler section-table fixtures can provide reusable startup dependency probes | Implemented only for this group's constructor contract |

## Verification

Host: AArch64 macOS; stable Rust 1.98.1. Validation uses `--locked` and leaves
Cargo/dependency/toolchain/default-feature state unchanged. Commands validate the
combined task-owned tree, not an isolated individual agent's contribution.

Observed portable checks:

- `cargo +stable test --locked --no-default-features --lib --test ci_actions_pinned -- --test-threads=4 --quiet`:
  6,567 library tests passed, two existing optional microkernel tests ignored,
  zero filtered; all ten CI-pin checks passed. Library execution took 56.56 s.
- `cargo +stable test --locked --no-default-features --test user_windows --test ci_actions_pinned -- --test-threads=1 --quiet`:
  all 144 Windows integration tests and ten CI-pin checks passed, zero ignored
  or filtered. The final rerun took 11.12 s and included 68 executions of
  this group's actual PE programs and the final 38-input archive integrity
  checks. The earlier run took 11.25 s.
- `cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --lib --test user_windows --test ci_actions_pinned -- --test-threads=1 --quiet`:
  8,739 library tests passed, two existing optional microkernel tests ignored,
  zero filtered, in 985.10 s; all 144 Windows tests passed in 11.20 s and ten
  CI-pin checks passed, none ignored or filtered. This ran the unchanged
  implementation and all 34 final PE binaries. A subsequent data-model comment
  correction regenerated only source-hash/receipt metadata; every PE remained
  byte-identical and the final portable integration rerun checked those receipts.
- The iteration-only Windows namespace run passed 295 library tests, including
  14 cross-ABI initializer units, three cross-ABI retry-frame units and one
  architecture-sensitive registry test. It is not the unfiltered gate above.
- Exact owned Rust files were formatted; `cargo +stable fmt --all --check`
  passed. No unrelated file was reformatted.
- Both final fixture builds had identical hashes for all 34 PE binaries and
  their manifest. Artifacts total 126,976 bytes. The manifest SHA-256 is
  `e4a5279ddebdcfef2459a6d0cce3c55ddc097a886ca28c606dead39b49e5b171`.
  The same final inputs produced 68 observed preserved-CLI failures, no timeout,
  and an exact missing initializer export diagnostic. Shell status was 125;
  the CLI did not expose an NTSTATUS, so its value is unknown, not inferred.

The retained [primary archive](../../specifications/windows/crt-initializers/README.md)
contains 38 inputs, 206,910 bytes, plus three metadata files; the complete
physical inventory matches its manifest. Its manifest SHA-256 is
`5b2f87dbd864a3dd036c5a7efe91996a4cda8b70e0f6d0e7be45e49792e32eab`.
Source and license bytes are retained unnormalized. Independent read-only
implementation, fixture and provenance reviews found no confirmed blocker.
The integer-to-void callback cast in the fixture is a machine-ABI return-register
probe, not strictly typed C conformance evidence. Test times are Cargo-reported
wall-clock observations, not throughput measurements.

Additional completed gates:

- `cargo +stable build --locked --workspace --all-targets --no-default-features`:
  passed in 19.25 s.
- `cargo +stable build --locked --workspace --all-targets --no-default-features --features x86_64-suite,smir-jit`:
  passed in 20.35 s. Both builds reported the pre-existing library filename
  collision above; this is not presented as warning-free validation.
- `cargo +stable clippy --locked --workspace --all-targets --features x86_64-suite`:
  passed in 23.70 s with CI's default-feature selection.
- `cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --doc`:
  passed with zero executed tests and five existing ignored examples. This is
  a completed command, not executed doctest coverage.
- Authored-file whitespace checks, Bash syntax for both fixture scripts, Ruby
  acquisition syntax, and all 51 authored local Markdown links in seven
  documents passed. The complete staged whitespace check reports 25 trailing-
  whitespace diagnostics in nine retained primary-source/license files only;
  their verified raw bytes are preserved unnormalized. No authored-file
  exception exists. Exact owned Rust formatting passed without unrelated edits.

Unrun gates: native Windows execution/export capture is unavailable; exact
native-version compatibility remains unknown [I1-I3]. Linux KVM and other
host-specific backend/ISA oracle suites were not run on this AArch64 macOS host;
no backend, decoder, instruction, optimizer or lowerer behavior changed. Other
integration binaries were built but not executed. C ABI consumer execution was
not required by this unchanged C surface; workspace consumers were compiled.
The two optional ignored library microkernel tests and five ignored doctests
remain explicitly unexecuted, not counted as passes.

## Acceptance audit

| Criterion | Direct evidence |
|---|---|
| 1: binding admission | Architecture-filtered registry test, exact PE IAT/machine checks, retained ARM DEF and x86/x64 I/T/D observations |
| 2: end-exclusive/NULL traversal | Ascending/NULL/exclusive-end units, compiler/linker `.CRT` bounds and non-NULL excluded-end tripwires on every admitted ABI/binding |
| 3: real lazy/reentrant callbacks | All nine traversal PEs, nested allocations/string imports, future-slot replacement, assembly SP/GPR/cdecl checks and 65,537-NULL unit; independent closures |
| 4: void/int results | Void return-register poison, seven error PEs, positive/negative first-error cutoff and low-32-bit/high-register-poison unit |
| 5: precise memory/retry frontier | Checked-width and partial-pointer units, original return-site/cursor tests, nine real VEH repair PEs for NOACCESS/GUARD, abandoned retry tests; empty/reversed loop condition is explicit |
| 6: regression/reproduction | 68 observed old-CLI failures and 68 current PE executions per integration selection, exact 14-source/34-artifact hash graph, double deterministic final builds, isolated immutable copied inputs |

This audit covers the initializer group only. The original Windows userland
objective remains active; the high-impact ordinary startup dependencies above
are not satisfied by these tests.

## Quality-gate closure for this semantic group

| Repository gate | Evidence and result |
|---|---|
| QG1: assumptions | I1-I4 reconciled against implementation, guest probes and source evidence; native profiles retained explicitly |
| QG2: coverage | All six acceptance criteria map to direct evidence above; whole-objective completion is not asserted |
| QG3: reproducibility | Pointer/int/page widths, checked arithmetic, exact commands, seed, watchdog, tool/source hashes and baseline identity are recorded |
| QG4: contradictions/edges | ARM legacy binding and compatibility-shim conflict resolved; lazy faults, retries, abandoned frontiers, nesting, early error and width boundaries tested; unknown native cases labeled |
| QG5: provenance | Complete 38-input archive, licenses, pinned upstream/installed byte replays and five reused ABI hashes verified |
| QG6: bounded expansion | High/medium/low findings recorded; no adjacent startup/termination/backend/dependency mutation |
| QG7: worktree integrity | 109 exact owned paths; reviewed frozen implementation/input hashes; baseline tracked/index clean; unrelated untracked material preserved |
| QG8: behavior | Unfiltered library and Windows binaries passed in portable and feature selections; 68 red/green PE observations, no fixture skips/filters; ignored tests separated |
| QG9: consistency | Current registration, bindings, API-set routing, manifests, local links, consumer compilation and public Rust source-break notice agree |

The personal seven-gate contract is also satisfied for this group: no normative
judgment is required; the full assumption register and stress probes are present;
bounded requirement coverage is explicit; widths/calculations are reproducible;
contradictions and unknowns are separated; primary provenance is verified; and
adjacent impacts are bounded. No claim is made that the full Windows objective's
completion audit has passed.
