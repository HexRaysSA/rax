# Windows dynamic UCRT termination

Implementation group against `02f28dbb4b6cc51e394987b7784ca34de965e2f5`
on `user-win`. The root worktree and index were clean before this group's
coordinated edits; unrelated untracked inputs remain user-owned. Full Windows
userland compatibility remains an active, incomplete objective.

## Acceptance criteria

1. Implement dynamic-retail desktop `exit`, `quick_exit`, `_exit`, `_Exit`,
   `_cexit`, `_c_exit`, and executable TLS callback registration on x86, x64
   and ARM64, with genuine UCRT/runtime API-set names and exact scalar ABI.
2. Preserve sticky termination-entered state separately from terminating
   cleanup completion. Returning cleanup remains repeatable and recursively
   enterable. TLS runs in the calling thread before the ordinary live queue;
   quick cleanup visits only the quick queue, minimal cleanup neither.
3. Maintain captured requests, selected targets, guards and continuation
   ownership across guest callbacks, faults, waits, nested cleanup and terminal
   abandonment. Release the acquired exit-lock guard before normal OS exit.
4. Offer the exact C++ exception filter (`0xE06D7363`) after callback-local
   exception search and before the original caller. Select and disable it
   before running available inner guest unwind handlers; invoke its selected
   handler only after that cleanup. Per-thread terminate handlers get their
   own any-SEH containment; disabled handlers cannot catch themselves. Reject
   unsupported cleanup dispositions and active-dispatcher faults diagnostically
   rather than inventing cleanup.
5. Implement duplicate TLS registration failure through actual terminate and
   abort behavior, including global software SIGABRT handling, masked 32-bit
   abort controls, default forced fast-fail and report-fault-disabled normal
   exit status 3. No invented `_is_c_termination_complete` DLL export.
6. Normal dynamic UCRT DLL detach flushes initialized streams at reverse
   initialization-completion order; returning CRT cleanup does not flush by
   itself. Forced process termination bypasses DLL detach. Preserve read buffers,
   visit later streams after host I/O errors, retain accepted prefixes across
   guest-memory faults, and do not close streams during retail terminating detach.
7. Verify independently compiled three-ABI PE witnesses, exact imports/source
   receipts, pre-feature observations and the broad relevant stable-Rust gates.
8. Exact-path stage, same-path `red -m --staged --run`, immediate origin push;
   no amendments, coauthorship or session-link metadata.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| E1 | SDK 10.0.26100.0 retail dynamic, unmanaged desktop, application-default state is the selected runtime profile | Exact publisher source/member receipts and genuine three-ABI DLL exports | Cleanup modes, normal OS exit, terminating DLL flush | Six APIs, returning repeats, recursive registration, raw/forced OS exit | Run identical probes under the pinned DLLs with different link/process policy | Retained; native equivalence unknown |
| E2 | The selected modern x86/x64 target has processor feature 23, PF_FASTFAIL_AVAILABLE | SDK abort branch; ARM64 is unconditional | Default abort forced status `0xC0000409` | Handler return/fault, enabled/disabled report-fault flag | A selected target without PF23 would require the report-fault fallback | Retained profile; pre-fast-fail hosts unsupported |
| E3 | Single scheduler execution serializes one host metadata operation | Existing process scheduler contract | Global signal action snapshot/reset and builtin publication | Reentrant handlers and callbacks; loader publication failure | Concurrent unsynchronized mutation of the retained process/address space | Confirmed for admitted execution |
| E4 | Successful builtin publication models its initialization completion | Transactional data initialization occurs before trap publication | Reverse-ready UCRT detach position | Native DLL dependencies, late builtin load, failed publication | Identified native loader-order witness contradicts this position | Retained personality profile; native exact order unknown |
| E5 | CRT-private allocation and callback storage ownership preconditions remain valid | Prior global queue register G4/G5 and stdio S2/S3 | Registry drains, flush identity checks | Raw-free/foreign close, equal-address ABA, repair-time reconfiguration | Allocation/HANDLE generation oracle | Retained; non-ABA failures explicit, identical metadata ABA unknown |
| E6 | Synthetic frame boundaries represent HLE ownership, not guest image unwind metadata | Checked callback entry SP and original caller state are captured by the dispatcher | Filter search position, available cleanup pass and transparent outer search | Nested exact/any filters, inner guest search/unwind handlers, VEH repair, fibers/pruning, terminal cleanup-data fault | A scope crosses before an inner handler, consumes the caller's cleanup, or an unmatched bridge fabricates a callback return | Confirmed for the admitted implementation; native language-personality equivalence unknown |
| E7 | CRT contexts remain thread-keyed rather than fiber-keyed in the existing personality | Existing thread-not-fiber error-cell contract; SDK PTD uses FLS wrapper bodies not present in inspected sources | Per-thread terminate-handler identity | Switching and retiring guest fibers/threads | Pinned native FLS-wrapper/PTD fiber witness contradicts shared thread state | Retained profile; native fiber identity unknown |

Dependent results are bounded by E1–E7. No native Windows execution is inferred
from emulator success. Managed CLR, Store/enclave process policy, static/debug
CRT startup and MSVCRT termination are separate unfinished execution planes.

## Change-surface map

| Plane | Assessment |
|---|---|
| Direct decode / execute | Unaffected; existing ISA cores execute the compiled probes |
| CPU state | Existing scalar ABI/context marshalling consumed; no architectural register change |
| Memory/MMU | Checked stack/heap/buffer fault consumers affected; no translation semantics changed |
| SMIR lift / IR / interpreter | Unaffected; no new instruction or operation |
| Optimizer / native lowering | Unaffected; no transformations or host opcodes changed |
| JIT runtime | Unaffected; Windows witnesses explicitly use `RAX_NO_JIT=1` |
| Backend / machine / device | Unaffected; process-level Windows personality only |
| Oracle/analysis | Unaffected; no decode/effect/analysis schema change |
| C ABI | Unaffected; no C header/layout/enum change |
| Public Rust HLE | Flow gains Protected; Frame gains owned exception and callback/caller metadata. No stable repr(Rust) layout claim |
| CRT | Six cleanup modes, TLS registration, per-thread terminate, software signal actions, abort controls |
| HLE / SEH | Owned filter scopes and synthetic caller bridging; checked callback/fault preservation |
| Loader / lifecycle | Transactional builtin ready ledger, dynamic UCRT terminating-detach flush |
| Tests / docs | Reachable all-ABI units and registered integration fixtures; reference/producer receipts |

## Bounded findings and conflicts

| Impact | Evidence / boundary | Blocks selected group? |
|---|---|---|
| High | Public `_cexit` wording includes flushing, but inspected dynamic `exit.cpp` omits static XP/XT cleanup; retail UCRT terminating DLL detach flushes instead | No under E1; blocks unqualified CRT equivalence |
| High | Public `_flushall` wording describes input clearing; inspected `fflush.cpp` returns early for ordinary nonflushable read streams | No under E1; source-version profile leaves input/read-ahead/pushback unchanged |
| High | Current executable PE TLS and FLS stages may execute after UCRT detach | No for selected ordering profile; no claim that one flush captures output produced afterward |
| High | Console and per-thread exception signals require their own delivery/filter infrastructure | Valid actions for SIGINT/ILL/FPE/SEGV/BREAK numbers fail explicitly before state effects; SDK invalid-action precedence is preserved; only runtime-global SIGABRT (22, alias 6) and SIGTERM (15) admitted here |
| High | SDK software raise's SIGTERM default is normal `_exit(3)`, conflicting with public raise documentation's ignored default | No under E1; source-version behavior selected explicitly |
| High | Native nested active-queue reset arithmetic is unknown; SDK uses raw pointers | Existing ownership-safe nested reset is retained and not claimed native-equivalent |
| High | MSVC VCStartup TLS destructor-list implementation is absent from inspected SDK | Registered guest producer callback executes; no fabricated internal destructor list or ordinary compiler-startup completeness claim |
| High | Genuine MSVC C++ language-personality and collided/nested cleanup restart state are not implemented by synthetic HLE filters | No for admitted custom handlers; unwind dispositions 0/2/3 fail explicitly, selected handler remains disabled, original operation remains owned until terminal disposal |
| High | Existing Win64 first-pass NESTED_EXCEPTION follows ContinueSearch without x86's EXCEPTION_NESTED_CALL update | No for this bounded group; full native nested-disposition semantics remain unknown and unchanged |
| High | Active DISPATCHER record/context/metadata/setup faults are terminal diagnostics after guard classification | No for the documented fail-closed profile; no claim of VEH repair or completed cleanup after these failures |
| High | SDK source redistribution grant is unknown | Raw proprietary SDK members remain ignored/local/temporary and excluded from staging |
| Medium | Fast-fail reason 7 is not separately exposed by current terminal-status API | Status-only personality; no debugger exception-parameter equivalence claim |
| Medium | Builtins stay permanently pinned; explicit UCRT unload is not admitted | Terminating process-detach flush only; no full unload/uninitializer claim |
| Medium | Workspace all-target builds warn that root rax and rax-capi both produce unnamespaced librax.rlib | No; both package targets compile. Existing package naming is unchanged; a future Cargo hard-error policy is outside this group |

## Algorithms and dimensional checks

Status and mask values are exactly 32 bits; `code as u32` preserves the C int
bit pattern (e.g. −19 becomes `0xFFFFFFED`). x86 TLS arguments occupy
3 × 4 bytes = 12 bytes and the guest stdcall producer removes them. x64/ARM64
use 8-byte pointer slots and retain a 32-bit detach reason equal to zero.

Without queue mutation a drain visits N slots in O(N) time, O(1) continuation
state besides its O(N) guest registry; live insertions can restart scanning.
The prior +512-slot growth ceiling retains O(N²) aggregate moving-copy work.
For N virtual guest walk steps, F retained HLE frames, H synthetic scopes,
T function-table entries and U total metadata decoding work, table search is
O(N(F + H log(H + 1) + log(N + 1) + log(T + 1)) + U); selected unwind is
O(N(F + log(N + 1) + log(T + 1)) + U), with O(N + F + H)
receipt space. N and H each have a 4096 personality cap, not a native limit;
function tables have no new size ceiling or complete-table scan. x86 selected
cleanup visits checked inner registrations and removes completed links only.

For S streams and K bounded transfer chunks, captured detach metadata uses
O(S) host space; Vec-based identity lookup incurs O(S² + K S) metadata work.
Accepted host output prefixes are not rolled back or repeated during guest
memory repair. No finite bound is claimed for guest callbacks or repair loops.

## Evidence and quality gates

The selected implementation group is validated on `aarch64-apple-darwin`,
macOS 27.2 (26B5091g), stable Rust 1.98.1 and LLVM 22.1.8. These are local
observations, not a cross-host CI or native-Windows execution claim. Exact
command logs are retained locally in `/tmp/rax-crt-exit-gates.8x9Gzi`.
The pre-feature CLI was preserved at
`/tmp/rax-crt-exit-baseline.zmJmwp/rax-user`, SHA-256
`b3e53f095c865ebc4435f1ac1cd71739ea4fc8c95097d92f0f693b43fb70fcaa`.

| Gate | Observed result |
|---|---|
| Portable workspace all-target build | Passed; 27.85 s |
| `x86_64-suite,smir-jit` workspace all-target build | Passed; 72 s (Cargo reports 1 min 12 s) |
| Portable library | 6775 passed, 0 failed, 2 ignored, 0 filtered; 140.39 s |
| Portable Windows integration / CI tooling | 449 / 10 passed, 0 failed/ignored/filtered; 43.60 s / 0.01 s |
| Feature-enabled library | 8947 passed, 0 failed, 2 ignored, 0 filtered; 1145.55 s |
| Feature-enabled Windows integration / CI tooling | 449 / 10 passed, 0 failed/ignored/filtered; 51.57 s / 0.00 s reported |
| Selected CI-profile Windows library | 503 passed, 0 failed/ignored, 8446 filtered; 3.30 s |
| Selected CI-profile Windows integration / CI tooling | 449 / 10 passed, 0 failed/ignored/filtered; 38.67 s / 0.00 s reported |
| Documentation tests | 0 passed, 0 failed, 5 explicitly ignored; no execution coverage |
| Workspace all-target Clippy | Passed; 36.25 s, repository warning policy unchanged |

Reported durations are Cargo's wall-time observations, not benchmarks; a
reported 0.00 s is below its display precision, not evidence of zero elapsed
time. The two ignored library tests are existing microkernel lift/lower and
byte-roundtrip checks requiring the absent `microkernel/microkernel.bin`.
They are outside the affected Windows planes. No skipped or filtered cases
are counted as behavioral evidence for this group.

Commands for the build, library and integration gates:

```sh
cargo +stable build --locked --workspace --all-targets --no-default-features
cargo +stable build --locked --workspace --all-targets --no-default-features --features x86_64-suite,smir-jit
cargo +stable test --locked --no-default-features --lib --test user_windows --test ci_actions_pinned -- --test-threads=1 --quiet
cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --lib --test user_windows --test ci_actions_pinned -- --test-threads=1 --quiet
cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --doc
cargo +stable clippy --locked --workspace --all-targets --features x86_64-suite
```

The selected CI-profile reruns use the same eight environment settings as
the applicable `.github/actions/setup-rust/action.yml` runtime profile:

```sh
env CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_OVERFLOW_CHECKS=false CARGO_PROFILE_TEST_OVERFLOW_CHECKS=false CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=false RUST_BACKTRACE=1 cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --lib user::windows:: -- --test-threads=1
env CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_OVERFLOW_CHECKS=false CARGO_PROFILE_TEST_OVERFLOW_CHECKS=false CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=false RUST_BACKTRACE=1 cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --test user_windows --test ci_actions_pinned -- --test-threads=1 --quiet
```

This is a selected Windows repeat, not the complete workflow's core-target
matrix. Native Windows, Linux/KVM, HVF, C API runtime consumers, standalone
microkernel/ASL packages, unrelated integration binaries and cross-host JIT
execution were not run: none is an affected implementation plane. Workspace
builds compile C API targets but do not establish C API runtime coverage.

The compiled corpus contains 12 physical PEs (56,320 bytes), 126 independent
case cells and 252 executions per complete integration run. It uses ordinary
compiler-produced C unwind metadata plus explicit guest search/unwind scopes,
not substituted compiler startup or `__C_specific_handler`. Real callback
return PCs remain inside each scope body, before its recognized epilog.
Three fixture builds reproduce the manifest, all PEs and all independent
llvm-readobj observations byte-for-byte. A separate replay reproduces the
complete preserved-CLI receipt. The observed baseline is 228 exact unresolved
exports (84 TLS registrar, 96 set_terminate, 48 signal), 12 normal OS exits with
DLL notification but missing pending output, and 12 unchanged forced exits;
no watchdog expired. The unchanged forced exits are negative controls, not
fabricated pre-feature failures.

Primary provenance is retained in
[the source archive](../../specifications/windows/crt-exit/README.md).
Its 32-input manifest SHA-256 is
`d23cc52016aafb016c284050b0fc66ac0b16ef50089670fc345c501fe4d22d31`.
Root offline verification checks 16 retained hashes/sizes, 16 publisher-member
receipts and three observer tools; root network verification additionally
replays 21 publisher inputs and three genuine DLL export observations.
The reused full-package SHA-512 is not counted as a new whole-package replay.
NuGet signature authentication and native Windows execution remain unknown;
raw SDK members are excluded from the tracked archive. All three new Ruby
retrieval/producer/observation scripts pass syntax checks.

The ordinary unmodified main fixtures still stop at `_set_app_type` on all
three guest ABIs in the current engine (status 125). That separate startup
frontier and the additional imported language-personality/formatted-I/O/locale
dependencies are not implemented by this termination group.

## Acceptance audit and self-red-team

Forty-four new reachable library tests cover 17 termination/signal cases,
13 stdio/loader/lifecycle cases and 14 owned exception-boundary cases. These
execute all three guest ABI variants except one deliberately x86-specific
partial-formal stack-fault test. The compiled runner adds 126 named case
tests plus one independent integrity test; every case runs both slice sizes.
The 127-test diagnostic run passed before the final broad reruns. The complete
portable and feature runs exercise the final frozen source, including the
last rejection test for unwind dispositions 0/2/3.

| Acceptance criterion | Implementation and direct evidence |
|---|---|
| 1–2: exports, ABI, cleanup state/order | `termination/{exit,fatal,signal}.rs`, exit tests; PE modes 0–7 and 14–15 |
| 3: retained ownership/fault/lock behavior | Checked calls, lock guards, HLE continuations, detach phase receipts; library setup/target/repair/reentry and terminal-disposal tests |
| 4: search then selected cleanup/containment | `hle/exception.rs`, x86/table unwind support, all 14 boundary tests; PE modes 16–20 including actual second-pass U trace |
| 5: actual terminate/abort/TLS duplication | Fatal/signal implementation and PTD failure tests; PE modes 8–15 |
| 6: dynamic DLL-detach flush | Stdio detach phases, transactional ready ledger, lifecycle filtering; 13 tests and every PE pending-byte/detach observation |
| 7: independent corpus and gates | Exact fixture/source/IAT integrity, byte-identical builds, preserved-CLI replay, provenance replay and the gate counts above |
| 8: Git delivery | Checked against the created commit and origin ref after validation; test success alone cannot establish stage/commit/push or metadata compliance |

Adversarial review found no remaining in-scope defect. It checked exact/any
filter selection and disabling, caller frontiers, unsupported cleanup
dispositions, terminal dispatcher-data faults, stream identity/reentry,
partial host writes, initialization rollback, handler reset and masked flags.
Two ambiguous documentation statements were corrected: filter selection
precedes second-pass cleanup; invocation of its selected handler follows it.
All 33 authored local Markdown links resolve. The known high/medium limits
are retained above; no additional low-impact item was found.

Repository QG1–QG9 are supported respectively by the reconciled E1–E7 register,
acceptance mapping, exact commands/receipts and dimensional checks, explicit
conflict/edge boundaries, primary provenance, bounded findings, exact owned
file inventory, admitted all-ABI execution, and reachable test/path/feature
consistency. No normative judgment is required. Before delivery, formatting,
diff whitespace, unchanged frozen-source hashes and the exact staged/committed
path set are checked again. Unrelated pre-existing untracked content remains
untouched. Full Windows userland support remains incomplete.
