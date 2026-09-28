# Darwin AArch64 exclusive-monitor event boundaries

Semantic integration group on `master` after rebasing the Windows/AArch64
series onto `origin/master` at `c1207af95`. The tracked worktree and index
were clean at baseline. Pre-existing untracked paths remain user-owned.

## Acceptance and primary contract

1. A pure host instruction-budget yield followed by selection of the same
   Darwin arm64 guest TID retains the local exclusive reservation.
2. Selecting a different guest TID clears that TID's AArch64 local monitor
   before it performs guest or kernel-continuation work. A later reselection
   of the original thread cannot let its pre-switch reservation succeed.
3. Successful asynchronous arm64 signal-handler entry clears the interrupted
   thread's monitor after the frame is written and before handler PC/SP and
   argument registers are published. Failed frame construction does not
   acquire successful-handler semantics.
4. Preserve the existing Linux and Windows switch/signal behavior, direct
   A64 `CLREX`, SMIR interpretation, other ISA adapters, guest memory and
   public ABI. Update overview documentation that incorrectly says every
   adapter clears reservations on every guest exit.
5. Commit exact owned paths with `git add` then `red -m --staged --run` on
   the same paths, without amendment, coauthor or Claude session-link
   metadata, and push `master` directly to `origin` after required
   verification. Verify the remote ref equals the resulting local HEAD.

The primary [Arm *Synchronization Primitives in A64*, §3.2.4](https://documentation-service.arm.com/static/68c223238a337a2bc6645c0a)
describes clearing local exclusive state on a context switch, exception
return, or `CLREX`. The existing direct A64 adapter already retains its
monitor on a pure budget `Yield` and clears on synchronous exception exits.
Darwin must therefore identify actual scheduler/signal boundaries rather
than treating each host call to `run` as an architectural exception.
Arm permits a store-exclusive to fail without a conflicting write; exact
success assertions test RAX's deterministic software-monitor contract, not
a guaranteed outcome on physical Arm hardware.

Reversible pre-fix RED control: after the four tests compiled, the two new
clear invocations were temporarily removed (without altering the test
fixture). The same-TID budget-yield case passed; the runnable-peer,
kernel-only-peer, and asynchronous-handler cases each failed because `STXR`
returned status `0` instead of the expected failure status `1`. The two
invocations were restored immediately and the same four tests passed.
The earlier first compile of the test fixture exited with status `85`
(`0x55`, the loaded data value) rather than the intended `0`; its guest
code was corrected to set the exit argument to zero before the syscall.
That fixture-only failure is not counted as an architectural red result.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| D1 | `DarwinProcess::last` records the previously selected guest TID before the next scheduler selection | Darwin scheduler source | Compare previous and selected TID before any selected-thread work | Same TID after budget yield; different TID chosen for kernel continuation only | A path selects a different TID without updating `last` or reaching the switch hook | Confirmed for tested scheduler paths |
| D2 | A completed `sendsig_arm64` frame write is the point after which handler-entry CPU state may be published | Darwin signal frame source | Clear reservation after frame write, before PC/SP update | Successful handler entry after `LDXR`; a faulting frame write remains a separate untested boundary | A successful handler entry bypasses this frame function or changes CPU state before the write succeeds | Retained; successful path tested |
| D3 | An intact RAX AArch64 software reservation succeeds deterministically absent a clearing event or conflicting write | `UserArmMemory` and direct A64 memory implementation | Exact `STXR` status assertions | `LDXR; STXR` across one same-TID slice versus a real switch or signal | Same address/width and no intervening event produces failure with an intact monitor | Confirmed for tested software paths |

## Change-surface map and bounded findings

AArch64 guest CPU state and the Darwin scheduler/asynchronous-signal adapter
are affected; the existing direct CPU monitor-clear primitive is reused.
The direct decoder/execute instruction set, memory/MMU and write-version
model, SMIR lift/IR/interpreter/optimizer, native lowerers/JIT, other OS
personalities, backends, machine/devices, oracle, public Rust/C ABI and
fixtures are unchanged. Focused Darwin tests and two user-mode overview
documents are the remaining affected planes. The switch check is O(1)
time and O(1) auxiliary space per selected TID; signal entry adds one
O(1) monitor-clear operation after the existing frame write.

| Impact | Evidence and boundary | Blocks this group? |
|---|---|---|
| High | A pure Darwin arm64 budget yield previously retained a reservation but the Darwin scheduler did not clear it on a different-TID selection or successful async signal entry | Yes; addressed by this group |
| High | Existing Darwin `posix_spawn` child cleanup leaves the old process bridge's `OwnedFd` kqueue live after host `fork`; an isolated arm64 spawn fixture reproducibly reports `IO Safety violation: owned file descriptor already closed`. This ownership chain is a source-backed cause candidate; the exact abort site is unknown without a stack trace | No for monitor semantics; separate descriptor-ownership group before claiming a green Darwin integration suite |
| Medium | Arm hardware may fail an uncontended store-exclusive, while RAX's local software monitor succeeds deterministically | No; the test contract is explicitly software-model-specific |
| Medium | `rax-user` reads a literal PROGRAM host path before Darwin's `--sysroot` resolution, so an overlay-only absolute Mach-O path can exit 127 before format dispatch | No; separate CLI/overlay semantics and tests are required |
| Medium | A parallel Darwin `procinfo_x86_64` comparison reported native thread priority `30` versus emulator `31`; the same test passed in isolation | No; load-sensitive native scheduling comparison, not the arm64 monitor path |
| Low | Root README's `rax-user` summary remains Linux-only after Darwin/Windows integration | No; documentation integration cleanup can be grouped with the CLI surface |

## Validation and self-red-team

The four focused portable regressions pass after restoring the two clear
calls and also pass with `x86_64-suite,smir-jit` enabled. They execute a
minimal static arm64 Mach-O under the real Darwin scheduler for same-TID,
runnable-peer and kernel-only-peer selection, and enter a real arm64 signal
frame after `LDXR`. The failing-frame boundary was reviewed in source:
`sendsig_arm64` performs `proc.space.write` with `?` before obtaining a
mutable arm64 core or clearing its monitor. No guest CPU state is published
on that error path. A direct failed-frame regression was not added.

Each guest A64 instruction is 4 bytes. The test's `LDXR X`/`STXR X` operand
is 8 bytes; `STXR` writes success/failure into a 32-bit `W` register. With
one instruction per host slice, same-TID selection leaves status `0` and a
real TID switch or successful signal entry leaves status `1` without the
exclusive store. The synthetic fixture explicitly zeros the Darwin exit
argument after the store-status observation.

| Gate | Actual result |
|---|---|
| Portable focused Darwin arm64 exclusive tests | 4 passed, 0 ignored |
| Feature-enabled focused Darwin arm64 exclusive tests | 4 passed, 0 ignored |
| Portable library suite | 7,229 passed, 2 explicitly ignored |
| Feature-enabled focused x87 regression after rebase | 7 passed, 0 ignored |
| Portable Windows user-mode integration | 528 passed, 0 ignored |
| Darwin user-mode integration, parallel harness | 84 passed, 3 failed, 0 ignored; not a green gate |
| Isolated Darwin `procinfo_x86_64` rerun | 1 passed |
| Isolated Darwin `spawn_arm64` rerun | Failed with the same IO-safety abort |
| Portable workspace all-target check | Passed; manifest warnings remain |
| CI tooling test target | 10 passed, 0 ignored |
| Workspace formatting and tracked diff check | Both passed |

The Darwin integration failures are recorded without being converted into
a passing claim. The isolated spawn failure is reproducible and affects
both arm64 and x86-64 in the parallel suite; its source-backed descriptor
ownership diagnosis is separated above. Native Darwin fixtures run on this
macOS ARM64 host, but no Linux KVM, macOS HVF, or x86-64-host JIT oracle
execution is implied. The full feature-enabled library corpus and C/C++ ABI
consumer were not rerun for this scheduler/signal-only change. All listed
Cargo gates used stable Rust and `--locked`.

QG1 requires no normative judgment. QG2 is the register above. QG3 covers
acceptance criteria 1–4 through real scheduler/signal tests and source
review; criterion 5 is checked after commit/push. QG4 has explicit 4-byte
instruction, 8-byte operand, 32-bit status and O(1) boundary dimensions.
QG5 checks same TID, two kinds of different-TID selection, asynchronous
entry, and the pre-frame-write error return; the persistent spawn failure
is a separately diagnosed ownership defect, not a monitor contradiction.
QG6 uses Arm's primary guide and executable tests. QG7 records out-of-scope
findings without silently mutating them.
