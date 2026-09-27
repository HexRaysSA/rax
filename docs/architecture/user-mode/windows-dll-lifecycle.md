# Windows DLL lifecycle integration

Date: 2026-09-27. Baseline HEAD:
`b6877559f7edbf306aaecea139854497f3d399f5`. Guest architectures: PE32 i386,
PE32+ AMD64 and PE32+ ARM64. Host: AArch64 macOS, Rust stable 1.98.1.
This semantic group implements a bounded Windows-personality profile, not full
Windows compatibility or a measured native-loader implementation.

## Implemented contract and acceptance evidence

The evidence table identifies reachable cases; execution results are recorded
in the frozen combined-run section below.

| Requirement | Implementation | Direct evidence |
|---|---|---|
| Checked native LoadLibraryW/A | Dependency mapping, static TLS publication, TLS/PE-entry callbacks, checked BOOL, commit before handle return | Compiled dynamic PE on all three ABIs; infrastructure and continuation tests |
| Attach once and balanced release | Explicit counted references, independent import/forwarder graph edges, pins, actual ready-completion ledger | Repeat loads, shared dependencies, synthetic cycle and nested ownership tests |
| Native forwarded exports | Initialize freshly resolved targets before publishing function address; failed lookup rolls back its target/TLS/edge journal | Successful forwarding fixture; missing-export fixture and host ledger regression |
| Failed attachment and retry | FALSE detaches failed entry; prior ready dependencies detach as required by the selected profile; physical mappings/LDR/TLS ownership cleaned before failure return | Two consecutive failures, held/fresh dependency cases, DLL file replacement then successful retry |
| Unload | Reverse ready-native detach; unmap after callbacks; dead stable module indices excluded from lookup/unwind | FreeLibrary, final release, VirtualQuery MEM_FREE, cycle and tombstone units |
| Unload-and-exit | FreeLibraryAndExitThread emits normal thread exit without returning through the removed image | Cross-ABI API unit; normal exit scheduler tests |
| Borrowed/counting/pinned handles | GetModuleHandleW/A does not acquire ownership; GetModuleHandleExW/A implements PIN, UNCHANGED_REFCOUNT and FROM_ADDRESS | Flags, output clearing, counted/pinned/from-address and name units |
| Thread notifications | New threads notify ready modules before user code; no retroactive thread attach; normal detach precedes TLS/TEB destruction | Old/new workers and TLS isolation in compiled fixtures; lifecycle/scheduler units |
| Process notifications | ExitProcess stops peers without thread detach, then runs process detach on its live caller | Static executable fixture and scheduler units |
| Forced termination | Explicit forced outcomes skip guest notification stages and preserve exit status | Native/Win32 termination, fail-fast and failed-stack tests |
| Loader serialization | Reentrant per-thread lock, disjoint internal wait namespace; already attached ordinary threads remain schedulable | Nested lock, parked peer, forged guest wake and scheduler units |
| Abandoned continuations | Drop queues host cleanup; ordinary scheduler frontier cleans all receipts before further guest execution and reports explicit failure | Nested guards and abandoned native journal units |
| Executable image loading | LoadLibrary(EXE) maps data image without import binding, TLS startup or entry execution | Data PE with deliberately unavailable import and executable entry; compiled fixture |
| Finite history | Stable indices with a 4,096-slot historical-module admission ceiling; no index reuse | Boundary/unchanged-state loader units; repeat live lookups remain admitted |

The lifecycle ordering profile is TLS array order before entry on attach, entry
before TLS array order on detach, and reverse actual completion order for ready
native modules. Exact inter-category, cyclic and nested-loader native ordering
is unknown. DllMain static attach/process-exit Reserved is nonzero; dynamic
attach/unload Reserved is zero; TLS Reserved is always zero. The original
thread's TLS thread-reason notifications are excluded by the retained PE table
profile. Failure-path TLS detach is an explicit profile, not a native trace.
The executable and synthetic built-in DLLs are intrinsic ownership roots;
native startup imports are retained by their executable dependency edges, not
blanket permanent pins. Releasing a module with no explicit counted reference
is rejected by this profile; its precise native misuse status is unknown.
Counted/PIN GetModuleHandleEx upgrades for an unready native image reject with
ERROR_NOT_SUPPORTED; UNCHANGED_REFCOUNT lookup remains available. This avoids
promising permanent PIN retention for an image that a failed attach must remove.
Exact native reentrant behavior is unknown, not inferred from the return code.
The internal Data kind for LoadLibrary(EXE) follows the documented
DONT_RESOLVE_DLL_REFERENCES-style loading profile; it does not imply the
LoadLibraryEx LOAD_LIBRARY_AS_DATAFILE flag or its tagged-handle semantics.

Escaping an ordinary loader continuation is an explicit fatal personality
diagnostic after checked resource cleanup, not successful attachment or a
fabricated native exception status. Forced process termination instead drops
all guest frames and host receipts/journals without callbacks or private guest
rollback writes. Existing thread/handle resources are shut down; image/private
arena allocations remain process-owned for postmortem inspection until Proc
is dropped. Forced thread termination inside an active loader continuation
retains the explicit abandonment diagnostic profile.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| D1 | Personality execution/mapping changes are serialized on one host thread | Scheduler/AddressSpace contract | Preflight then TLS/LDR/output publication | Protected last destination; suspended/extracted caller; peer callback scheduling | Concurrent mapping mutation through a retained AddressSpace clone invalidates this contract; protected-TEB/LDR tests exercise admitted failures | confirmed within profile |
| D2 | Personality-private heap allocations are not guest-freed and recycled | Existing TLS/LDR ownership restriction; host address ledgers | Physical teardown ownership | HeapFree of private block followed by allocation at same address | Generation-reuse test demonstrating teardown frees a replacement allocation | retained; allocation generations absent |
| D3 | TLS-before-entry attach, entry-before-TLS detach and reverse completion order are selected profiles | Public sources do not establish all relative ordering | Notification ordering and FALSE cleanup expectations | Two TLS callbacks, shared/cyclic graph, nested completion | Ordered native traces per Windows build/ABI disagree | retained; native equivalence unknown |
| D4 | Import/forwarder ownership uses explicit graph reachability rather than native private reference internals | Separately owned reference roots and journaled edges | Shared dependency, cycle and forwarder unload | Failed missing forwarded export with a fresh TLS target | Native lifecycle/refcount/VirtualQuery trace disproves native ownership equivalence; guest/host rollback regressions probe this implementation | retained; selected profile verified |
| D5 | ANSI/Unicode/path handling remains the existing restricted profile | Lossy UTF-8/UTF-16, ASCII matching, configured drive mapping | A/W module lookup and controlled fixtures | Non-ASCII case aliases, malformed UTF-16, SxS redirection | Code-page/SxS/versioned-native search probes disagree | retained; exact native behavior unknown |
| D6 | All compiled fixture claims use existing direct CPU interpretation, not new JIT admission | WinCpu stepping and RAX_NO_JIT fixture switch | Three-guest execution evidence | Slices 1 and 4,096 instructions; ABI callback stack tails | A fixture path bypassing direct CPU execution would falsify the claim | confirmed |
| D7 | Native callback exception interception/status and forced-thread loader abandonment are not inferred from public API descriptions | No native Windows oracle available | Explicit diagnostic/restricted profile | Fault, NtContinue/longjmp, termination while guard held | Versioned native trace proves different containment/status; guard-drop units test RAX cleanup only | retained; native equivalence unknown |

Dependency tags: publication/physical-cleanup results depend on D1/D2;
notification and graph-policy results depend on D3/D4; A/W lookup coverage is
restricted by D5; compiled execution claims depend on D6; abandonment/status
claims retain D7. Profile conformance does not confirm native equivalence.
The existing NtTerminate* NULL/pseudo-handle admission is a restricted service
profile; complete native handle semantics are unknown. Normal last-thread
notification staging is tested as a profile, not inferred native ordering.

## Change-surface map

| Plane | Status and reason |
|---|---|
| Direct decode | Unaffected; no ISA encoding changes |
| Direct execute | Existing software cores exercised; no instruction semantics changed |
| CPU state | Affected through existing callback ABI marshalling/exit frontiers; no new architectural register fields |
| Memory/MMU | Affected through checked image/TLS/LDR ownership, publication, protection and release; MMU algorithms unchanged |
| SMIR lift | Unaffected; direct Windows CPU path |
| SMIR IR | Unaffected; no new operation |
| SMIR interpreter | Unaffected; no new interpretation contract |
| Optimizer | Unaffected; no optimized Windows admission |
| Native lowering | Unaffected; no lowerer changes |
| JIT runtime | Unaffected; no admission or runtime gates changed |
| Backend | Unaffected; no KVM/HVF/emulator adapter change |
| Machine/device | Unaffected; process-only personality |
| Oracle/analysis | Unaffected; no ISA analysis interface change |
| C ABI | Unaffected; Windows personality not exposed through C API |
| Public Rust | Proc gains loader state; Flow/Outcome gain explicit forced terminal variants; canonical ownership retained |
| Tests/docs | Affected; existing declared user_windows target reaches new lifecycle module; fixture generator/provenance and retained sources |

## Arithmetic and algorithm bounds

Pointer size p is 4 bytes for x86 and 8 bytes for x64/ARM64. TLS slot i occupies
`array + i × p` through `array + (i+1) × p - 1`; checked capacity is
`(i+1) × p <= heap_array_bytes`. N TLS indices therefore require exactly `N × p`
bytes per thread. Templates use checked `raw_size + zero_fill` bytes; an empty
template still receives a minimum 1-byte allocation for distinct ownership.
TLS index growth and all bounded allocation/address arithmetic reject overflow.
These integer bounds have zero numerical rounding error.

Load/unload ownership walks use O(H+E) time and O(V) visited space for V live
modules, E dependency edges and H historical slots, including the root scan.
H <= 4,096 is a RAX admission bound, not a Windows
module limit. Tombstone metadata remains O(H×L) for retained name/path bound L;
this does not prove a global host-allocation budget. Explicit reference counts
use u32: the maximum counted value is 0xFFFF_FFFE, while 0xFFFF_FFFF denotes a
pin. Count exhaustion rejects rather than accidentally converting into a pin.
The legacy u16 LDR count saturates at 0xFFFE; 0xFFFF denotes a pin.

Preparing TLS over T existing threads copies A=N×p array bytes and B template bytes
per thread: O(T×(A+B)) time and O(T×(A+B)) staged guest storage. New blocks and
arrays are staged before pointer publication; displaced arrays remain journal
owned until commit/rollback. Unloading clears only host-recorded module slots.
Shared array capacity may retain a peak index while another TLS module remains;
existing heap backing segments may remain committed after live blocks are freed.
Notification stepping is O(M+C); current Vec completion-ledger bookkeeping is
worst-case O(M²+C) for M modules and C callbacks. Guest callback CPU cost is
additional. Callback scans inspect at most 4,096 pointer slots including the
required NULL terminator, admitting at most 4,095 callback targets. This is an
explicit profile bound; internal loader wake key `1 << 65` is disjoint from u64 guest addresses
and condition-variable bit 64.

## Baseline and verification record

Before implementation, the previously built CLI with SHA-256
`19c1d54fa8b35d2e5acd1b737a20d7881a8561f8ebfcb7025595c1c6be8bcdc3`
rejected dynamic native initialization with exit 125 on all three guests;
static startup fixtures exited 23 for their reserved-pointer check. This was
an observed binary baseline, not an isolated fresh build of baseline HEAD.

The pre-correction lifecycle CLI with SHA-256
`e03c00d2df908eadc825e683729f267bd4d3b01e5dcdce047716277484ea1236`
ran the missing-forwarder regression on all three guests and exited 88 at its
live-uninitialized-target check. Each baseline run used slice 4,096, seed 1,
64 MiB configured arena, RAX_NO_JIT and a 30 s external watchdog.

The frozen portable combined run passed 6,490 library tests, ignored two optional
microkernel tests, and filtered none; all 41 Windows integration and all 10 CI
contract tests passed with no ignored or filtered cases:

```sh
cargo +stable test --locked --no-default-features --lib --test user_windows --test ci_actions_pinned -- --test-threads=4 --quiet
```

The library registry includes 218 Windows units. The lifecycle target contributes
11 integration cases, including nine CLI cases × two scheduling slices = 18
actual guest runs (x86/x64/ARM64 × dynamic/static/missing-forwarder × 1/4,096).
Each run uses a 64 MiB arena, seed 1, RAX_NO_JIT and a 30 s external watchdog.
All 81 service-reference manifest entries were hashed by the reachable test,
including the 23 lifecycle records. The lifecycle manifest checks 18 sources
and 30 PE artifacts totaling 98,304 bytes; its two generator runs were
byte-identical according to the fixture build audit.

The final serial Windows integration run also passed all 41 tests, with no
ignored or filtered cases. The feature-enabled library run passed 8,662 tests,
ignored the same two optional microkernel tests, and filtered none:

```sh
cargo +stable test --locked --no-default-features --test user_windows -- --test-threads=1 --quiet
cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --lib -- --test-threads=4 --quiet
```

Both workspace all-target builds and feature-enabled Clippy passed:

```sh
cargo +stable build --locked --workspace --all-targets --no-default-features
cargo +stable build --locked --workspace --all-targets --no-default-features --features x86_64-suite,smir-jit
cargo +stable clippy --locked --workspace --all-targets --no-default-features --features x86_64-suite,smir-jit
```

The feature-enabled doctest command exited successfully with zero executed
tests and five ignored tests; this is not evidence of example execution:

```sh
cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --doc -- --test-threads=4 --quiet
```

Repository formatting, maintained-source whitespace and fixture script syntax
checks passed. SHA-256 values for all 24 owned Rust files were unchanged between
the source freeze and final gate completion:

```sh
cargo +stable fmt --all --check
git diff --check
bash -n tests/fixtures/user/windows/lifecycle/build.sh
```

The final staged whitespace check passes for all 81 authored/generated owned
paths. The unrestricted staged check reports trailing whitespace in 17 retained
upstream source/license snapshots; those bytes are preserved for provenance,
not normalized or represented as a whitespace-clean archive. The snapshot
hashes still match the primary-reference manifest.

Cargo emitted the preexisting root/C API `librax.rlib` output-name collision
warning. Package/dependency layouts are unchanged; this warning is not a failed
build or a claimed proof that manually selected top-level artifacts are distinct.
Temporary narrow reversals also reproduced the two module-API defects: admitting
EXE/data handles to DisableThreadLibraryCalls and failing to clear a valid
GetModuleHandleEx output on invalid flags produced two failing units (6 passed,
2 failed), then exact source SHA-256
`c025562958e80d28819e6538101a62345f23d10823e235cb17bb0b57966721f0`
was restored. Reinserting the prior scheduler startup-owner freeze produced a
failing secondary-notification unit (`Some(8)` rather than runnable peer
`Some(12)`); the corrected unit previously passed all three ABIs. The exact
scheduler source was restored before final combined validation. These reversed
units stop at their first x86 failure; they are not red executions of all three
ABIs. Native NtTerminateProcess and NtTerminateThread were independently reversed
and failed their new unit, then restored and passed all three ABIs; commands are
retained in the primary-reference analysis.
The unready-native counted/PIN admission regression also failed before its
checked rejection was implemented (0 passed, 1 failed at the first x86 counted
upgrade). The existing protected-PEB integration expectation exposed an
incidental startup diagnostic change; ldr::init retains its prior
STATUS_NO_MEMORY contract and now preflights publication before allocation.
Two all-ABI units check rejection before heap zeroing/consumption and checked
heap-access failure. This compatibility status is not a native Windows claim.
Compilation and profile conformance are not native Windows differential
execution. Native Windows, Linux KVM/HVF runtime and Windows JIT execution were
not run for this process-personality group.

## Bounded findings

- High, full-goal boundary: raw NT numeric services, CRT/GUI/network/registry,
  FLS callback teardown, demand stack growth and modern private Windows layouts
  remain incomplete or unknown. This DLL group does not complete Windows emulation.
- High, retained D2/D7 restrictions: guest recycling of private loader heap
  allocations and native exception containment need generation-aware ownership
  or a versioned native oracle; current diagnostic/profile limits are explicit.
- High, adjacent preexisting limits: external host filesystem namespace mutation
  is not an atomic Windows transaction; synchronous console input can block the
  single guest scheduler. Neither is changed here.
- Medium, profile limits: finite historical module ceiling; no complete SxS,
  packaged-app or LoadLibraryEx search/flag policy; exact Unicode/code-page
  matching and native forwarder/cyclic ordering remain unknown.
- Medium, performance: completion-ledger bookkeeping is quadratic; retained TLS
  array capacity and tombstone metadata are bounded high-water storage.
- Medium, preexisting build artifact ambiguity: root rax and rax-capi library
  targets both produce librax.rlib in a workspace build. No package/ABI rename
  is included in this Windows-personality group.
- Low: native throughput and loader-lock fairness are unmeasured; no performance
  claim follows from correctness tests.

Primary contract/archive and seven-field lifecycle analysis:
[DLL lifecycle references](../../specifications/windows/services/dll-lifecycle/README.md).
Fixture provenance, source/artifact hashes, explicit profile assumptions and
reproduction commands:
[lifecycle fixtures](../../../tests/fixtures/user/windows/lifecycle/README.md).
No upstream revision or native result is fabricated.

Worktree baseline was tracked-clean with an empty index. Ownership is confined
to this Windows loader/HLE/process/SEH integration, its reachable tests,
generator-owned lifecycle fixture graph and documentation/reference group.
Preexisting untracked research/IDE/binary trees were neither staged nor modified.
Cargo.toml, Cargo.lock, feature defaults, CI workflows and C API are unchanged.

Final self-red-team: user QG1–QG7 and repository QG1–QG9 pass for this admitted
semantic group. The register is reconciled; the requirement and change-surface
tables identify direct evidence; arithmetic and commands are reproducible;
private/native unknowns and bounded findings remain explicit. Source/fixture
hashes, test reachability, formatting and combined-tree gates were verified.
The exact commit index is confined to the 104 owned files. Ignored tests and
unavailable native oracles are excluded from executed-coverage claims. This is
not a claim of full Windows completion.
