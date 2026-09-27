# Windows fibers, FLS and stack frontiers

Date: 2026-09-27. Baseline HEAD:
`28aa423b11beea024c5bebbcccdd5dcd1d0312b4`.
Guest ABIs: PE32 i386, PE32+ AMD64 and PE32+ ARM64. Host: AArch64 macOS,
Rust stable 1.98.1. This record concerns implementation/profile conformance,
not a native Windows differential result or completion of Windows emulation.

## Acceptance contract

| Requirement | Implementation and validation surface |
|---|---|
| ConvertThreadToFiber/Ex and ConvertFiberToThread | Checked identity publication, ownership transfer, FLS value retention and inverse conversion |
| CreateFiber/Ex | Separate reserved stack, requested/default initial commitment, guard when slack permits, start routine and parameter; no execution before selection |
| SwitchToFiber | Complete the old ABI return, then exchange CPU, stack/SEH metadata and callback frames; never return into the target through the old stack |
| Fiber data macros and IsThreadAFiber | TEB.FiberData points to a live identity whose first pointer is creation data; macros are not fabricated DLL exports |
| Synchronized migration | Dormant plain continuations move between threads; FLS/stack follow fiber, TLS/TEB/TID follow current thread |
| Floating-point and call-preserved state | Whole-core parked state, x86 flag-zero sharing and flag-one restoration; independent assembly and host state tests |
| DeleteFiber | Noncurrent FLS callbacks precede stack/identity release; current deletion follows normal ExitThread, retaining resources during callbacks |
| FLS APIs | Process-wide generation-tagged indices, disjoint thread/fiber value identities, NULL defaults and checked errors |
| FlsFree | All non-NULL context values captured and cleared; callbacks use guest ABI; closing index cannot recycle during its callback plan |
| Cleanup reentrancy | Live generation lookup after each callback; newly set values drained; stale destructor generations never invoked |
| Normal/forced exits | DLL stage then final caller FLS drain; forced peer/thread/process termination does not invoke FLS callbacks |
| Guard growth | One lower guard page committed per growth; StackLimit publication checked; hard bottom and commitment exhaustion fail explicitly |
| HLE/SEH stack setup | Checked descending guard probes precede callback and exception-record writes |
| Rollback and bounded host state | Failed creation/conversion does not publish or leak stacks/markers; no guest ownership words select teardown targets |
| Reachability/provenance | Existing declared user_windows target registers the new runner; source/PE/primary-reference hashes retained |

The portable source-frozen run executed all 66 Windows integration tests,
including 48 actual fiber/FLS PE executions across the three ABIs and two
scheduler slices. Source and generated fixtures alone are not execution evidence.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| F1 | Mapping changes and guest execution remain serialized on one host thread | Existing scheduler/AddressSpace contract | Preflight then TEB/marker publication | Protected final TEB field and commitment exhaustion | Concurrent retained AddressSpace mutation invalidates the contract; protected-publication tests check admitted failures | confirmed current contract; native equivalence not inferred |
| F2 | Private identity/stack allocations are not guest-freed and recycled behind host ledgers | Private Windows layouts/ownership are not public allocation APIs | Physical release ownership | HeapFree of live identity then address reuse | Generation-aware heap/VM ownership or native private-object probes falsify exact equivalence | retained restriction; collision admission checked |
| F3 | Whole parked CPU preservation is allowed beyond the call-preserved ABI subset; x86 target flag-zero inherits outgoing FP/SIMD state | Public API defines x86 flag semantics, not mixed-flag/XSTATE internals | Context switch and FP tests | Mixed flags, vector/nonvolatile registers and migration | Versioned native raw-state traces disagree with selected mixed-flag or extended-state profile | retained; native equivalence unknown |
| F4 | FLS cleanup ordering, closing-index admission and callback rearming use the explicit selected profile | Public sources define callback triggers, not all order/reentrancy details | Delete/free/normal exit cleanup | Callback frees/reallocates another slot, rearms itself or escapes | Native ordered callback traces disagree; generation and nonconvergence regressions probe RAX safety | retained; native ordering unknown |
| F5 | Unconverted FLS values survive conversion/reconversion without callbacks | Public FLS follows selected context and behaves like TLS without switches | Context-key transfers | Convert, switch, reconvert and repeat | Native conversion/value probe disagrees | retained; native conversion equivalence unknown |
| F6 | Controlled stacks can grow by one guard page while retaining a reserved bottom page | Windows stack/guard documentation; existing checked VM | Fiber initial commitment and guard retries | Exact bottom, skipped guard, protected TEB and quota exhaustion | Native page/StackLimit traces disagree with exact growth quantum/reserve profile | retained; native private granularity unknown |
| F7 | Fixture execution uses direct software CPU paths | Existing WinCpu stepping and RAX_NO_JIT fixture switch | Cross-ABI execution claims | Slices 1 and 4096 instructions, actual FP/context switches | A fixture path bypasses the interpreter or does not execute the tested service | confirmed for 48 executed PE cases; native equivalence unknown |
| F8 | New-fiber CPU/FP state starts as a creator clone | Engine requires a defined initial state; public APIs omit initial FP state | First fiber selection | Creator changes rounding/status/SIMD before creation | Versioned native first-entry raw-state probe disagrees | retained profile; native initial FP unknown |
| F9 | Dormant fibers retain transferred stacks after creator exit; thread-bound HLE continuations cannot migrate | Host stack ownership and unrebound loader/wait/cleanup receipts | Stack release and cross-thread switching | Exit creator then resume converted fiber; migrate parked startup loader receipt | Native teardown probe or proven receipt rebinding falsifies this profile | retained restricted profile; native lifetime unknown |

Dependency tags: publication depends on F1/F2; switch/FP on F3/F7;
cleanup on F4/F7; conversion on F5; stack bounds/growth on F1/F6;
initial state on F8; dormant lifetime and migration restrictions on F9.
Native unknowns are not inferred from implementation-derived tests.
AMD64/ARM64 park whole CPU state for either flag; native flag effects are unknown.

## Change-surface map

| Plane | Status and reason |
|---|---|
| Direct decode | Unaffected; no new instruction encoding |
| Direct execute | Existing CPU semantics exercised; no ISA semantic edits |
| CPU state | Affected: retained whole CPU/FP state and current thread TEB rebinding |
| Memory/MMU | Affected: stack commitment/guard frontier and checked TEB publication; translation algorithms unchanged |
| SMIR lift | Unaffected; direct process CPU path |
| SMIR IR | Unaffected; no operation addition |
| SMIR interpreter | Unaffected; no IR behavior change |
| Optimizer | Unaffected; no Windows optimized admission |
| Native lowering | Unaffected; no lowerer changes |
| JIT runtime | Unaffected; no new JIT gates |
| Backend | Unaffected; no KVM/HVF/backend state conversion |
| Machine/device | Unaffected; process-only services |
| Oracle/analysis | Unaffected; no ISA analysis API change |
| C ABI | Unaffected; Windows process personality not exported through it |
| Public Rust | Proc/Thread fields, canonical FiberState re-export, SwitchFiber Flow, checked stack helper; TlsState FLS helpers now use typed keys, Results and cleanup tickets instead of the raw per-tid map/immediate-free helpers |
| Tests/docs | Affected: unit/integration registry, generated PE inputs and retained source manifests |

## Arithmetic and algorithms

Pointers are 4 bytes for x86 and 8 bytes for x64/ARM64. The fiber identity's
first pointer contains creation data. Commitment uses checked
`(n + 4095) & !4095`, with a minimum of 4096 bytes. When this commitment is
at least the selected reservation, reservation promotes to a checked 1 MiB
multiple, `(commit + 1048575) & !1048575`; otherwise it rounds to a checked
64 KiB multiple, `(reserve + 65535) & !65535`. Zero arguments select PE defaults
(or a 1 MiB reservation fallback). These units are binary bytes, not SI megabytes.
The page size is 4096 bytes. Partial commitment adds a guard only when it fits;
exactly full commitment has no additional private guard in this selected profile.
For StackLimit L, the consumed guard is
`L - 4096 bytes`; growth commits a new guard at `L - 8192 bytes` and publishes
new StackLimit `L - 4096 bytes`. Growth refuses to consume the final bottom page;
an initially almost-full reservation may already lack that reserved margin.
Exact native full-commit layout and private reserve margins are unknown.
At growth exhaustion the consumed guard is still checked and published as an
emergency StackLimit frontier before STATUS_STACK_OVERFLOW dispatch; record and
callback setup can use that page but cannot descend into a reserved bottom page.
Overflow/underflow is rejection, not host wrapping. Integer arithmetic has zero
numerical rounding error beyond the specified page/granularity ceiling.

Guest callback setup uses x86 stack words of 4 bytes, x64 shadow/stack words of
8 bytes with a return address, and ARM64 eight integer registers followed by
8-byte stack words. Descending stack preparation costs O(P) for P pages crossed;
guest memory writes retain checked access. Fiber registry lookup costs O(log V)
for V live fibers. Whole CPU/frame exchange is O(1), excluding fixed-size FP
copy and bounded TEB publication; creation pays for initialized CPU state and
initial committed pages. FLS storage is sparse in non-NULL assigned values;
callback traversal includes registry lookup/ordering costs described in its
primary-reference analysis. A cleanup that rearms indefinitely terminates with
an explicit diagnostic at the profile's callback ceiling, not silent success.
An FLS callback's deliberate ExitThread/ExitProcess/TerminateThread retires its
own abandoned FLS host plan without replacing the terminal action or inventing
an API return. Separate loader receipts retain their checked cleanup contract.
Nonterminal NtContinue/longjmp abandonment remains a diagnostic.

## Baseline and verification

The previously built baseline CLI was copied before rebuilding this group.
Its SHA-256 is
`e076ccb04e77d92793f1e34effa31af7b83e4e720df92b2159aafc76064af222`.
Actual core PE fixtures on all three ABIs exited 125 at missing KERNEL32.FlsAlloc,
using RAX_NO_JIT, 64 MiB arena, slice 4096 and seed 1. This is an observed binary
baseline, not an isolated rebuild of baseline HEAD.

Adversarial review found that exhausted guard handling had consumed the emergency
page before SEH setup tried to consume it a second time. The regression
`exhausted_stack_guard_dispatches_veh_on_consumed_emergency_page_all_abis` was
executed with a temporary reversal of emergency-frontier publication: one test
failed (exit 101), stopping at x86 with ProcessTerminate(0xC00000FD) instead of
the VEH continuation. After restoration, all 245 Windows library units passed,
including the regression's three ABI cases, checked record/context contents,
unchanged saved PC/SP and reserved-bottom preservation. This is an observed
RAX regression, not a native private StackLimit oracle.

Source-frozen gates, all with Rust stable 1.98.1 (`48a229ceaefd4985c50990b14116b6d856af0985`)
on `aarch64-apple-darwin`:

| Command | Observed result |
|---|---|
| `cargo +stable test --locked --no-default-features --lib --test user_windows --test ci_actions_pinned -- --test-threads=4 --quiet` | 6517 library passed, 2 ignored, 0 failed/filtered; 66 Windows passed, 0 failed/ignored/filtered; 10 CI passed, 0 failed/ignored/filtered |
| `cargo +stable test --locked --no-default-features --test user_windows -- --test-threads=1 --quiet` | 66 passed, 0 failed/ignored/filtered |
| `cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --lib -- --test-threads=4 --quiet` | 8689 passed, 2 ignored, 0 failed/filtered |
| `cargo +stable build --locked --workspace --all-targets --no-default-features` | exit 0; existing librax.rlib output-name warning |
| `cargo +stable build --locked --workspace --all-targets --no-default-features --features x86_64-suite,smir-jit` | exit 0; same existing warning |
| `cargo +stable clippy --locked --workspace --all-targets --no-default-features --features x86_64-suite,smir-jit` | exit 0 |
| `cargo +stable fmt --all --check` | exit 0 |
| `cargo +stable test --locked --no-default-features --doc --quiet` | 0 executed/passed, 5 ignored, 0 failed; not executable doctest coverage |

The two ignored library cases are the optional full-microkernel lift/lower and
exact-byte roundtrip tests in `src/smir/lower/validation.rs`. No Windows test
is ignored or internally skipped. The library includes 245 Windows units.
The complete repository's other integration targets, native Windows oracle,
KVM/HVF, Windows JIT admission, and C API runtime suites were not run for this
process-only group; all-target compilation is not runtime backend evidence.
Two successive fixture builds were byte-identical; all 35 declared fixture
source/artifact checks passed. The manifest SHA-256 is
`ce7599500d1c25e795a5af88f48254740b3988bfa6b14eddf429f45d1b81b130`.
All 32 new retained primary-source/header-excerpt/notice checks passed; the
registered service-reference set has 113 entries across five groups. The source records separate
CC-BY-4.0 prose, MIT code samples and installed header ZPL-2.1 notices, plus
unknown exact commits and the Zig-header/release-tag byte distinction.
All 54 local links in the nine maintained Markdown files passed existence checks
after final documentation freeze. The reference counter follows the test's
`.sources` or `.files` schema selection: 32 + 9 + 17 + 23 baseline entries plus
32 new entries = 113. Treating the absent `.sources` field as zero would omit
the locks manifest; the registered test does not make that mistake.

## Bounded findings

- High: complete Windows CRT/GUI/network/registry and numeric NT services remain
  incomplete. Full Windows compatibility and native differential coverage are
  unknown; this semantic group does not redefine that goal as complete.
- High: native private fiber layouts, mixed-flag XSTATE, exception interception,
  callback rearming/order and private allocation generations remain profiles or
  unknown. Guest recycling of private blocks is outside admitted ownership.
- High: cross-thread migration of parked thread-bound HLE callbacks is not yet
  admitted; plain application/fiber-start continuations are supported. Same-thread
  continuation preservation is distinct from native cross-thread callback fidelity.
- Medium: live-fiber and FLS cleanup/index ceilings bound host state, not native
  Windows resource limits; exact native OOM/status and Unicode policies remain unknown.
- Medium: original thread creation retains its prior eager-commit profile;
  fiber stacks use requested/default commitment and checked growth. Demand growth
  must not be claimed for a stack already wholly committed by that older path.
- Medium: Rust personality FLS helper signatures/storage change for typed context
  and deferred cleanup; repository callers/all targets are validated, but
  untracked external Rust consumers are unknown. No C ABI change is made.
- Medium: the preexisting workspace librax.rlib output-name collision warning
  remains; package naming/dependency state is outside this group.
- Low: switch throughput and fairness are unmeasured; no performance claim is made.

Reference/provenance and detailed callback profiles:
[fiber primary sources](../../specifications/windows/services/fibers/README.md).
Fixture generation/reproduction:
[fiber fixtures](../../../tests/fixtures/user/windows/fibers/README.md).

Baseline tracked tree and index were clean; preexisting untracked research/IDE
inputs remain user-owned and excluded. Cargo dependency state, feature defaults,
CI and C API are not owned by this group. The exact owned inventory has 105
files: 49 authored/generated text files, 24 PE inputs and 32 retained reference
snapshots. The authored/generated staged whitespace check passes; the complete
check reports 188 diagnostics confined to retained upstream source/license/header
bytes. Their declared hashes are preserved, not reformatted. All owned Rust source files remain
under 1500 lines; the scheduler is 1440 lines. Exact source SHA-256 values were
frozen before final execution and rechecked unchanged afterward. Final Quality
Gates for this admitted semantic group:

| Gate | Evidence/status |
|---|---|
| User QG1: normativity | No ethical judgment or normative opinion required |
| Repo QG1 / user QG2: assumptions | F1–F9 reconciled; independent native unknowns retained rather than converted into claims |
| Repo QG2 / user QG3: coverage | Each acceptance row mapped to implementation, units and/or executed PE fixtures |
| Repo QG3 / user QG4: reproduction | Checked byte/page arithmetic, exact commands/versions/seed/slices, deterministic fixture/hash records |
| Repo QG4 / user QG5: edges | Emergency-page red/green regression, generation/receipt/publication tests; unsupported/private cases explicit |
| Repo QG5 / user QG6: provenance | 32 new primary/header/license checks; source facts, profiles and unknowns separated |
| Repo QG6 / user QG7: scope | Impact-labeled limits; no incidental ISA, Cargo, feature, C ABI or CI changes |
| Repo QG7: worktree | Exact owned inventory only; baseline tracked/index clean; unrelated untracked inputs untouched |
| Repo QG8: behavior | Unfiltered portable/feature libraries and Windows/CI targets; observed reversal failure and passing restoration; skip limits explicit |
| Repo QG9: consistency | Canonical module owners, registered runner, public Rust helper changes, documentation, licenses and manifests audited |

Owned scope is the Windows fiber/FLS engine and frontends, shared CPU/HLE/stack/
SEH/scheduler/loader/thread integration, the registered runner and its independent
fixture graph, the fiber primary-reference archive and linked current feature
documentation. Exact leaf paths are the staged/commit inventory; preexisting
research/IDE files are excluded. Staging uses exact paths; the requested
`red -m --staged --run` receives the identical path list. Its audited source
commits the complete index, so index equality and the resulting parent/path set
must be checked; no claim about binary/source byte equivalence is made. After
commit, the branch is pushed directly to origin and remote HEAD equality checked.
No commit amendment, session link or coauthorship trailer is authorized.
