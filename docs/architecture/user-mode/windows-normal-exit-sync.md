# Windows normal-exit synchronization lifetime

Semantic group against `2c9d2075321195d7f22f99d6c51af9411acd4425`
on `user-win`. The tracked worktree and index were clean before this group's
edits. Pre-existing untracked content remains user-owned. Full Windows
userland is still an active, incomplete objective.

## Acceptance and primary contract

1. Preserve initialized critical sections and SRW ownership through genuine
   `DLL_PROCESS_DETACH`/FLS callbacks on normal `ExitProcess`.
2. Retire every other thread's parked registration, wait-object pin and
   waiter count once before callbacks, without writing possibly inaccessible
   guest lock storage. An already completed wait must not consume its lock
   count twice.
3. Permit only the exact pre-retirement synthetic SRW word until the first
   successful live mutation reconciles guest storage; reject arbitrary guest
   changes. Preserve dead-thread lock ownership, including a possible
   callback deadlock, rather than manufacturing an unlock.
4. Keep forced `ProcessTerminate` and final shutdown terminal, callback-free
   where specified, and able to drop host-only synchronization state. Do not
   enter guest detach callbacks after a failed peer teardown.
5. Verify unmodified compiler-selected `main`/`wmain` PEs on x86, x64 and
   ARM64 with slice 4096, plus x86/x64 with slice 1. Do not attribute ARM64
   slice-1 liveness to this separate lifecycle change.
6. Complete exact-path commit with the requested `red -m --staged --run`
   invocation, no amendment/coauthor/session metadata, then push directly to
   `origin` and verify the remote ref.

The retained [Microsoft `ExitProcess` page](../../specifications/windows/services/thread-sync/exitprocess.md)
specifies termination/signaling of peers before `DLL_PROCESS_DETACH`, and
explicitly notes that a peer-held lock can deadlock a detach callback. The
current [scheduler](../../../src/user/windows/process/sched.rs) previously
called the terminal `sync::on_process_exit` at the start of normal exit; that
erased initialized critical-section admission before the callbacks. The
preserved pre-change CLI `/tmp/rax-bootstrap-cs-frontier.Et15f3/rax-user`
has SHA-256
`a9bfba30c9f02a6053c88772124192c722f916b3a41bf107dfe2c741f60c7b24`.
An independent x64 ordinary `main` run at slice 4096 exited 125 with
`uninitialized/deleted critical section`; earlier six-ABI/entry traces
showed the same frontier after successful `InitializeCriticalSection`.
These are baseline failures, not passing postcondition tests.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| N1 | Guest threads in one process execute serially on one host scheduler thread | `process::sched::run` selects/runs one thread per slice | Host wait-map and ownership transition needs no host mutex | Multiple peers, completed polls, callback reentry | Observe simultaneous guest `run` calls mutating one `Proc` | Confirmed for current scheduler |
| N2 | RAX's synthetic SRW/critical-section words are an internal profile, not a native Windows private layout | `sync.rs` encodes host ownership/waiters and validates its own SRW word | Exact old-word allowance and lazy reconciliation | Read-only/unmapped storage, hostile changed word, new shared acquirer | A claimed native-private-layout API exposes a conflicting required word | Retained; native word-layout equivalence unknown |
| N3 | Peer-held lock ownership survives peer termination for detach callbacks | Microsoft `ExitProcess` deadlock remark and current guest storage contract | Do not unlock dead owners | Caller acquisition while terminated peer owns CS/SRW | Selected native reference shows required owner release | Confirmed contract; native private representation unknown |
| N4 | The selected ordinary PE fixtures have genuine compiler-selected startup and unchanged binaries | Retained fixture producer/IAT/entry receipts and immutable image check | Ten integration acceptance cells | `main`/`wmain`, three ABIs, 1/4096 slices | Rebuild/IAT/entry differs or image bytes mutate | Confirmed producer/guest evidence; native Windows execution unknown |
| N5 | Each object ID in a registered object wait retains one reference until cancellation or terminal retirement | `on_block`, `poll`, `on_cancel` and object manager source | Exactly-once peer-pin release | Completed wait and repeated retirement/cancel | Reference persists after final handle closes, or double release occurs | Confirmed for the single-object witness in all-ABI tests; multi-object path follows the same per-ID loop |

## Change-surface map and algorithm

Direct ISA decode/execute, CPU register state, SMIR lift/IR/interpreter,
optimizer, native lowering, JIT admission, backend, machine/device,
oracle/analysis and public Rust/C ABI are unaffected: no instruction, state
layout, symbol or interface in those planes is changed. Windows process
scheduling and synthetic address-keyed synchronization are affected;
guest-memory permissions are observed through existing checked access, not
changed. The registered Windows integration runner and audit are affected.
The touched scheduler test group was moved without changed assertions to
[a 68-line sibling](../../../src/user/windows/process/sched/tests/exit_tests.rs),
bringing `sched.rs` to 1,494 lines below the approximate 1,500-line soft
ceiling; both extracted test functions execute and pass.

`on_normal_process_exit` snapshots peer registrations, counts only uncompleted
critical-section and exclusive-SRW waits, and validates host counts before any
mutation. It releases object pins, removes address queues and completion
receipts, decrements host waiter counts, and retains lock initialization and
owners. It does **not** read or write guest lock storage. For a touched SRW,
the exact old synthetic word is recorded. `srw_state` accepts the current
expected word or that one old word; `commit_srw` or reinitialization removes
the exception only after a successful checked guest write. A live critical-
section operation publishes the current waiter count; `cs_spin` now does so
as well. Final shutdown still drops the entire state. Peer thread destruction
and signaling precede guest detach, and teardown failure stops before guest
callbacks.

The synthetic SRW calculation is fixed-width guest pointer storage (4 bytes
on x86, 8 bytes on x64/ARM64). For one shared owner plus one waiting writer,
`(1 << 4) | 0x1 | 0x2 = 0x13`; retirement leaves guest `0x13` while host
waiting count becomes 0. The next successful second shared acquisition writes
`(2 << 4) | 0x1 = 0x21`; its release writes `0x11`. A held critical section
with one waiter has a synthetic signed 32-bit LockCount of
`-2 - 4*1 = -6 = 0xFFFFFFFA`; retiring the waiter leaves storage unchanged,
and the first live spin/enter/leave mutation writes
`-2 - 4*0 = -2 = 0xFFFFFFFE`. The old-word exception is exact, not a bitmask
admitting other guest writes. Retirement is O(P + L) time and O(P + L)
auxiliary space for P peer registrations and L touched locks, plus the
existing object-manager release costs.

## Bounded findings

| Impact | Evidence and boundary | Blocks this group? |
|---|---|---|
| High | ARM64 user adapter clears the exclusive monitor on every budget yield, so ordinary startup's `LDAXR`/`STLXR` loop at slice 1 does not progress | No; distinct CPU/scheduler contract requiring direct CLREX and actual-switch tests |
| High | Shared direct x87 decoder treats a 32-bit absolute ModR/M displacement as EIP-relative without checking `CS.L` | No; separate ISA correction; ordinary fixtures here do not depend on that addressing form |
| High | General Windows language personality, NLS/math delivery and full stdio are unfinished | No claim of full userland or arbitrary programs |
| Medium | Detach-time `CreateThread` admission and native private lockword layout are unknown; freeing/remapping a live lock is unsupported aliasing | No; do not infer native behavior or enable fake lock operations |
| Medium | Workspace all-target builds report the pre-existing engine/C API `librax.rlib` output-name collision | No; both builds pass, and no package/ABI rename belongs to this group |
| Low | Historical CRT stdio fixture README/manifest retains pre-feature ordinary observation classifications | No; baseline receipts intentionally remain immutable; new acceptance runner is separate |

## Validation and self-red-team

Focused tests: five `sync::exit_tests` functions each exercise all three ABIs;
the extracted forced and new normal scheduler exit tests both pass; ten
independently named integration cases run the unchanged ordinary PEs through
actual compiler startup and normal exit. The latter comprise
`3 ABIs × 2 entry forms = 6` slice-4096 executions and
`2 ABIs × 2 entry forms = 4` slice-1 executions. Direct root CLI runs also
returned shell status 0 for all six slice-4096 PEs and all four x86/x64
slice-1 PEs, with empty output. ARM64 slice 1 is not counted as a pass.

All completed Cargo gates used stable Rust with `--locked`, and actual test
summaries—not just command exit status—were inspected:

| Gate | Actual result |
|---|---|
| Portable library (`--no-default-features`) | 6,808 passed, 2 ignored |
| Portable Windows/CI integrations | 526 and 10 passed |
| Feature library (`x86_64-suite,smir-jit`) | 8,980 passed, 2 ignored |
| Feature Windows/CI integrations | 526 and 10 passed |
| Release-equivalent Windows units/CI integrations | 532, 526 and 10 passed with debug assertions and overflow checks disabled |
| Portable and feature workspace all-target builds | Both passed, with the bounded output-name warning above |
| Feature and default-feature all-target Clippy | Both passed; repository lint tables allow warnings |
| Formatting, tracked diff check, doctests | `cargo fmt --all --check` and `git diff --check` passed; doc result 0 passed, 5 explicitly ignored |

The two ignored library tests are
`smir::lower::validation::tests::test_lift_lower_full_microkernel` and
`smir::lower::validation::tests::test_roundtrip_exact_bytes_microkernel`;
they are not claimed as executed. The five ignored doctests are likewise
not claimed as executed. The intermediate feature run was deliberately
interrupted for the scheduler test-file split and is not counted as a gate;
all figures in the table are from a fresh final-layout run. Feature
compilation on macOS ARM64 does not imply native KVM/HVF or x86-64-host JIT
runtime execution.

Self-red-team: QG1 no normative judgment is required. QG2 N1-N5 above
include stress/falsification. QG3 acceptance criteria 1-5 have direct source,
all-ABI tests and compiled-PE evidence; criterion 6 is a post-artifact Git
delivery operation and is not asserted in this precommit document. QG4
guest pointer widths, 32-bit critical-section count encodings and exact SRW
word calculations are reproducible above. QG5 completed polls, hostile
word tampering, unreadable and unmapped storage, dead owners, forced exit
and failed peer teardown were tested explicitly. QG6 retained Microsoft
contract and original fixture receipts provide primary provenance, with
native private-layout equivalence bounded unknown. QG7 adjacent high/medium
findings remain classified and unmodified. Exact-path commit, forbidden-
metadata check and origin-ref verification must be performed after staging.
