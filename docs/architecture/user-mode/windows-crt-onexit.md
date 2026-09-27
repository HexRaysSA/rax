# Windows CRT explicit on-exit tables

Dependency group against baseline `3efe07a63ab935815d84ea4a48958282672a9059`.
The entire Windows userland objective remains incomplete: ordinary compiler
startup, full CRT termination/stdio, locale and floating-point dependencies
require subsequent implementation and verification.

## Acceptance criteria

1. Admit the genuine UCRTBASE and CRT-runtime API-set explicit table triple on
   x86, x64 and ARM64. Do not manufacture local compatibility shim exports.
2. Implement initialization, failure-preserving registration/growth, real guest
   callback execution, public invalid-until-reinitialized lifecycle, and
   independent nested generations without a process-global traversal cursor.
3. Preserve captured formal inputs, selected callback and storage ownership
   through checked guest faults; explicitly retire abandoned continuations
   without fabricating successful execution or calling skipped callbacks.
4. Verify all-ABI units and independently compiled guest images, both scheduling
   slices, retained baseline failures, exact inputs/provenance and relevant gates.
5. Stage only exact owned paths; run `red -m --staged --run` with those same
   paths, verify the resulting unamended commit, then immediately push origin.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| O1 | Guest representation is three plain pointer-width fields; host ownership is not derived from guest values | Retained MinGW declaration; Microsoft explicitly calls representation opaque | Interoperability profile and checked ownership | Corrupt/copy fields; detached future-slot mutation | Pinned native UCRT layout/encoding probe | Retained profile; native representation unknown |
| O2 | Reverse order and NULL-slot skipping are selected | Retained MinGW implementation; public explicit-table page does not settle either | Drain order and NULL handling | Sparse table and lazy mutation | Pinned native UCRT order/NULL probe | Retained comparison profile |
| O3 | Executing detaches/invalidate current generation; explicit reinitialize admits an independent generation | Public mandatory reinitialize rule, plus explicit engine reentrancy policy | Nested same-address execution and outer completion | New pending generation survives outer return | Pinned native reentrant table probe | Retained; native reentrancy unknown |
| O4 | NULL/uninitialized/malformed ownership representation returns negative without freeing arbitrary pointers | Public success/failure convention plus opaque representation boundary | Safe invalid-input profile | Aliased/corrupt fields and guest-width overflow | Pinned native invalid-input probe | Retained; native invalid-input handling unknown |
| O5 | Single host thread prevents mapping changes between preflight and checked publication without a guest callback | Existing checked heap/personality contract | Failure atomicity | Read-only/guard table, copy-source faults, first/growth OOM | All-ABI ledger/cell snapshots; concurrent mapping invalidation would falsify | Confirmed for serialized dispatch and tested faults; concurrent embedder invalidation outside this contract |
| O6 | Caller does not externally free/resize/destroy CRT-owned private buffers | Public table representation is opaque, unlike caller-owned `__dllonexit` arrays | Private heap identity and cleanup | Raw HeapFree/destroy; same-address same-size reuse | Heap allocation-generation probe; present allocator has only address/size identity | Retained ownership precondition; non-ABA violation detected, ABA unknown |

## Layout and algorithms

Pointer width P is 4 bytes on x86 and 8 bytes on x64/ARM64; the table occupies
3P = 12 or 24 bytes. All pointer arithmetic and size multiplication must be
checked against guest pointer width. C int results occupy 32 bits. Registration
uses geometric capacity and fresh candidate ownership; growth copies N*P bytes
and initializes C*P candidate bytes, where N is live length and C is new
capacity. Since P is fixed and C doubles, this is O(N) growth and amortized
O(1) buffer-copy work per registration. Each
operation also scans T table entries and B owned buffers for alias validation:
O(T+B) validation time and O(T+B+active generations) host ownership space.
Draining costs O(N) checked
reads and O(1) host cursor storage per detached generation. Host receipt queues
are reserved before admission so continuation Drop does not allocate or access
guest memory. Heap release removes live blocks, not retained committed capacity.

Checked callback frame bytes are `align16(4A)+4` on x86,
`align16(8*max(A,4))+8` on x64, and `align16(8*max(A-8,0))` on ARM64,
where A is the number of integer arguments and all lengths are bytes. Zero-
argument callbacks therefore require 4, 40 and 0 bytes respectively below the
aligned cursor. Capture precedes callback-stack preparation; repaired setup
must not reread a mutated callback slot or completed formal input.
The HLE cursor starts at `align_down16(entry_sp.saturating_sub(32 bytes))`
before additional checked allocations; call-frame subtraction is checked.
This private 32-byte frame gap keeps a valid ARM64 leaf
callback below its waiting API frontier even when callback argument bytes are
zero. Restoring the API-entry SP is therefore an escape for a checked call,
but not for a suspended wait restored by an APC.

## Change-surface map

| Plane | Assessment |
|---|---|
| Direct decode/execute; CPU architectural state | Unchanged; existing ISA cores execute compiled probes |
| Memory/MMU | Checked buffers/tables and callback stacks; no translation change |
| SMIR lift/IR/interpreter; optimizer; lowerers/JIT | Unchanged; no new native admission |
| Backend/machine/device; oracle; C ABI | Unchanged; process-level personality only |
| Public Rust/HLE | New checked callback flow and Frame discriminator; downstream exhaustive Flow matches and Frame literals require updates. Tracked consumers updated; original unchecked Call setup behavior retained |
| CRT/scheduler | Explicit table ownership, genuine exports, detached cleanup receipts |
| Tests/docs | Reachable units/PE runner, primary archive, this audit |

## Bounded discoveries

| Impact | Evidence/boundary | Blocks this group? |
|---|---|---|
| High | Dormant public `CrtState.atexit` is not a module-local complete termination registry; real stdio/exit/unload integration remains absent | No; blocks whole-goal completion |
| High | Read-only startup dependency review found no `__C_specific_handler` implementation/export in `src/user/windows`; generic guest language-handler invocation is not that personality | No; blocks ordinary compiler-image graphs that require this import |
| High | Original `Flow::Call` drops an unpublished continuation on setup fault | Addressed for checked on-exit calls; original contract retained for unrelated callers |
| High | Equal-height `Flow::Resume` originally pruned retries but not waiting callbacks; ARM64 return leaves SP unchanged | Corrected waiting-frontier pruning; exact owner-drop regression |
| High | Indiscriminate equal-height callback pruning discarded blocked waits restored after APC delivery | Checked-call discriminator preserves wait resumption; direct APC/wait and full services regressions required |
| High | Normal process cleanup must retain initialized tables through DLL detach | Only abandoned drains retire early; all table storage retires after normal lifecycle callbacks |
| Medium | Native opaque representation, reentrancy and private invalid-input/fault order are unknown | No; explicit profiles and falsification probes above |
| Medium | Private heap retains committed capacity after free | No; exact live-block cleanup is measured, not exact decommit |
| Medium | Guest raw-free plus same-address/same-requested-size reuse is not distinguishable by the existing heap metadata | No for valid opaque-table ownership; invalid private-lifetime native behavior and ABA recovery unknown |
| Medium | Invalidated table-address records remain until process teardown; the registry's O(T+B) scans and O(T+B) residency grow with distinct caller table addresses | No; explicit complexity and fallible reservation, no constant-time scalability claim |

## Provenance and verification

Primary inputs and architecture-filtered binding evidence are retained in the
[onexit archive](../../specifications/windows/crt-onexit/README.md), including
the referenced frozen initializer/startup inputs. Its 26 checked inputs contain
182599 bytes, including 2324 bytes of newly retained primary text; 24 inputs are
reused without edits. Five owning license/disclaimer entries are retained.
Archive manifest SHA-256:
`cd97c6f3556795b19602d02cf4405f3a03a4d56eaff2e88afe5e59d79ac1cd8c`.

The [fixture bundle](../../../tests/fixtures/user/windows/crt_onexit/README.md)
contains 36 custom-entry EXEs and six guest DLLs, totaling 118784 bytes. Two
final builds reproduced all manifest/PE bytes; the description correction did
not change any PE byte. The manifest checks 22 source/provenance inputs.
Final manifest SHA-256:
`630c26612dcb11f2bfe70c60c185c5ff551033cf4e13ecd065cff8e7da1c1cf1`.
Final baseline receipt SHA-256:
`c29618574b6e6fe63e82ae4b2a8e47a73348a840b984d1414d18d6f6f572327f`.

Before any current-group compilation the baseline CLI was preserved at
`/tmp/rax-crt-onexit-baseline.M11Io5/rax-user`, SHA-256
`422d7a6a0178c1a3a249c109f1138ed71e2b1ec5ffd1377573b1dcfa2f31c93f`.
All 72 final-input baseline runs, using slices of 1 and 4096 guest instructions,
returned shell status 125 at the missing UCRT table initializer. Inputs and
companion dependencies were copied into isolated directories and rehashed.
Timeout, signal and missing receipts are failures, not baseline successes.
These compiled probes are not ordinary linked CRT startup or recorded native
Windows differential execution.

## Ownership

The baseline tracked tree and index were clean. This group owns 83 exact paths:
11 existing tracked files and 72 new files. Existing ownership is confined to
`docs/architecture/user-mode/windows.md`, `tests/README.md`,
`src/user/windows/dll/{crt.rs,crt/tests.rs,mod.rs}`,
`src/user/windows/hle/{dispatch.rs,mod.rs,retry_tests.rs}`,
`src/user/windows/process/{sched.rs,fiber/tests.rs}` and
`tests/suites/user/windows/main.rs`. New ownership is this audit, the four
`crt/onexit/` Rust files, the five-file primary archive, the 61-file fixture
bundle and the registered `tests/suites/user/windows/crt_onexit.rs` runner.
The exact expanded list is used both for staging and the `red` invocation;
the complete index must equal that set before committing. Neither command uses
a directory glob or repository-wide staging.

All unrelated untracked content remains user-owned and untouched, including
`.idea/`, `_ref/`, hardware inputs, `iboot/`, `linux-aarch64/vmlinux`, `rax/`,
`tmp/`, `triage/`, `yolo.sh` and the other baseline untracked directories.
No dependency, lockfile, workflow, feature default, toolchain or prior source
archive is changed. The largest touched source is `process/sched.rs` at
1495 lines; each new Rust file is below 2000 lines and 150 kB.

## Executed validation

Host: AArch64 macOS, Rust stable 1.98.1, host triple
`aarch64-apple-darwin`, LLVM 22.1.8 in rustc. Fixture compiler/linker producers
and exact executable hashes are separate and pinned in the fixture manifest.
Commands below ran from the root with the unchanged lockfile. Local full
receipts are in `/tmp/rax-crt-onexit-gates.ChHZBX/`.

| Command | Observed final result |
|---|---|
| `cargo +stable test --locked --no-default-features --lib -- --test-threads=1` | 6648 passed, 0 failed, 2 ignored, 0 filtered; 134.39 s |
| `cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --lib -- --test-threads=1` | 8820 passed, 0 failed, 2 ignored, 0 filtered; 968.53 s |
| `cargo +stable build --locked --workspace --all-targets --no-default-features` | Passed, including root and C API compilation |
| `cargo +stable build --locked --workspace --all-targets --no-default-features --features x86_64-suite,smir-jit` | Passed |
| `cargo +stable test --locked --no-default-features --test user_windows --test ci_actions_pinned -- --test-threads=1` | Windows 229 passed, 0 failed/ignored/filtered; CI policy 10 passed, 0 failed/ignored/filtered |
| Same integration command with `--features x86_64-suite,smir-jit` | Windows 229 passed, 0 failed/ignored/filtered; CI policy 10 passed, 0 failed/ignored/filtered |
| `CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true cargo +stable test --locked --no-default-features --lib user::windows -- --test-threads=1` | 376 passed, 0 failed/ignored, 6274 intentionally filtered; 2.72 s |
| `cargo +stable clippy --locked --workspace --all-targets --features x86_64-suite` | Passed; no emitted Clippy warning |
| `cargo +stable fmt --all --check` | Passed; non-mutating |
| `cargo +stable test --locked --no-default-features --doc`, also with `--features x86_64-suite,smir-jit` | Each command: 0 executed, 0 failed, 5 ignored; no executed doctest coverage |
| `ruby -c docs/specifications/windows/crt-onexit/acquire.rb`; both fixture scripts with `bash -n` | Passed |
| Primary-input independent SHA-256/size audit; owned-text whitespace audit | All 26 inputs verified, 182599 bytes; no trailing whitespace in owned text |

Each complete Windows target reaches 38 new tests: 36 executable cases with
two slices each (72 actual guest runs), plus two complete input-integrity
tests. The final portable and feature-enabled commands used the final manifest
and refreshed baseline receipts. Guest runs explicitly set `RAX_NO_JIT=1`;
they establish direct Windows personality execution, not native/JIT parity.
The 25 new onexit library tests, three new checked-call tests and one new APC
wait-restoration test are present in both complete library runs. No current-
group test has a host/oracle self-skip. Broad library pass counts are not a
blanket statement that every unrelated host-specific oracle executed.

The two ignored library cases are the existing full-microkernel lift/lower and
exact-byte roundtrip diagnostics. Native Windows comparison was unavailable.
KVM/HVF runtime, other-host native JIT, standalone microkernel/ASL packages and
C/C++ ABI consumer execution were not run: no corresponding execution plane,
package, public C header or ABI is changed. The unrelated broad integration
inventory was compiled, not completely executed. Existing Cargo warnings about
the root/C API library output-name collision remain; this group does not rename
either package or artifact.

## Acceptance evidence and self-red-team

| Criterion | Direct evidence |
|---|---|
| 1: genuine binding subset | All-ABI export/exclusion unit; exact six-way PE IAT matrix and retained DEF/archive evidence |
| 2: lifecycle, growth, callbacks and epochs | 25 onexit units; basic/mutation/nested/OOM guest families, 1024-registration growth and reentrant generation sentinels |
| 3: exact fault/ownership frontiers | Saved-formal/slot units, checked-call setup/escape tests, actual VEH slot repair, worker termination and phase-guarded guest DLL detach |
| 4: reachable all-ABI reproducible evidence | Complete unfiltered Windows targets in both feature configurations; final 72-run baseline, hash/matrix tests and whole-library/build gates |
| 5: exact Git delivery | Exact 83-path ownership set and same-path staged `red -m --staged --run`; live commit and immediate-origin-push receipts are verified in the handoff |

Intermediate failures were not treated as final successes. Synthetic setup
tests initially supplied an unterminated ARM64 unwind chain and insufficient
x64 repaired-stack span for nine arguments (88 bytes); both fixture defects
were corrected without changing architectural expectations. Indiscriminate
same-height pruning caused all three existing service programs to lose the
APC-interrupted wait; the new checked-call discriminator and preservation test
corrected that regression. A stale source/baseline metadata pair was refrozen
together. The terminal fixture's earlier unconditional status override could
mask a forbidden callback; explicit shared phases now distinguish correct
normal exit, prior failure, forbidden callback and fallthrough before allowing
forced success. Missing DLL detach retains status 88 and fails.

Stack-setup repair is a dispatcher-level test of captured ownership/arguments;
compiled guest VEH tests repair the pending table slot. Neither is mislabeled
as a native Windows stack-fault oracle. Opaque layout/order/reentrancy/invalid-
input behavior remains explicitly profiled, with native falsification probes
in the register. No new unsafe block, ISA semantic change, optimizer transform
or native admission is introduced. Unsupported global CRT registration,
termination and stdio exports remain unsupported.

Artifact quality gates are satisfied: assumptions reconciled (QG1), acceptance
coverage mapped (QG2), reproducible dimensions/inputs/commands (QG3), visible
contradictions and edge profiles (QG4), primary provenance/unknowns (QG5),
impact-bounded expansion (QG6), preserved worktree ownership (QG7), executed
affected-plane evidence (QG8), and consistent source/test/public-Rust/docs
surfaces (QG9). No normative judgment is required. Git delivery is verified
after the commit/push; the entire Windows-userland objective is not declared
complete by these artifact gates.
