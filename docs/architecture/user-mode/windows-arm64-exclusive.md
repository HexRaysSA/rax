# AArch64 user-mode exclusive-monitor lifetime

Semantic group against `5a742f03ea1d212c0d8f146b9bd144ab395c0549`
on `user-win`. The tracked worktree and index were clean at this group's
baseline; pre-existing untracked files remain user-owned. This group does not
claim completion of the broader Windows userland objective.

## Acceptance and architectural contract

1. An AArch64 host instruction-budget boundary or completed EL0 WFI/WFE is
   not, by itself, a guest exception or guest TID switch: preserve the local
   exclusive reservation when the same guest thread resumes.
2. Clear the reservation on synchronous exception exits, actual Windows and
   Linux guest-thread switches, Linux asynchronous signal-handler entry and
   synthesized ptrace step traps.
3. Decode direct A64 `CLREX` with its four-bit `CRm` field ignored and clear
   the local reservation. Keep the fixed `Rt=31` constraint and ordinary
   barriers distinct. The existing SMIR lifter/interpreter must retain the
   same effect; no new native admission is implied.
4. Run the unmodified ordinary ARM64 `main` and `wmain` Windows PE fixtures
   with a one-instruction slice and status 0; preserve existing ABI/slice
   coverage.
5. Complete an exact-path `red -m --staged --run` commit, without amendment,
   coauthor or Claude session metadata, then push directly to `origin` and
   verify the remote ref.

The primary [Arm *Synchronization Primitives in A64*, §3.2.4](https://documentation-service.arm.com/static/68c223238a337a2bc6645c0a)
describes clearing exclusive state on a context switch and by `CLREX` or
exception return. The repository's retained Arm ASL archive
[`aarch64_system_monitors`](../arm/asl/arm_instrs.asl) specifies the fixed
`CLREX` encoding, ignored `CRm`, and `ClearExclusiveLocal(ProcessorID())`.
Arm permits a store-exclusive to fail without an intervening agent; tests
below verify RAX's deterministic software-monitor contract, not guaranteed
success on physical hardware.
The existing A64 SMIR lifter maps `Mnemonic::CLREX` to `OpKind::ClearExclusive`
and the interpreter dispatches that operation to `memory.clear_exclusive()`;
the direct handler now invokes the same memory contract. The x86-64-host
SMIR-native differential that includes `LDXR; CLREX; STXR` is target-gated
and is not claimed as run on this macOS ARM64 host.

The preserved pre-change CLI at
`/tmp/rax-arm64-budget-baseline.uhU526/rax-user` has SHA-256
`ef4fa0e67e44d9a098fbb1b866bc690db97d203047bdf8334bce35df8d3f45a2`.
Both genuine ARM64 ordinary entry forms exceeded a 10 s timeout at slice 1
with shell status 124 and no stdout/stderr. That binary was saved from the
preceding synchronization group's candidate build and demonstrates the same
pre-change AArch64 adapter behavior; it is not asserted byte-identical to the
baseline HEAD production binary. A separate direct-path red run before the
`CLREX` correction executed four tests: three passed, and the all-`CRm`
test failed at `CRm=0` because `STXR` returned status 0 instead of 1.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | A pure `run(1)` budget yield resumes the same guest thread without an architectural exception unless the OS personality selects another TID or delivers an event | Adapter and scheduler control flow | Retain monitor on `A64Exit::Yield` | `LDXR; WFI; STXR` in one-thread slices | Observe an exception/guest switch on every host budget yield | Confirmed for current schedulers |
| A2 | A selected peer continuation is a guest TID switch even if it does not execute an EL0 instruction | Scheduler `pick` and early blocked/ptrace branches | Invalidate the outgoing A64 monitor before peer continuation | T1 `LDXR`, T2 blocked-call continuation, T1 `STXR` | Trace proves the peer path never becomes selected | Retained for the scheduler model |
| A3 | Without a clearing event or conflicting write, RAX's software exclusive monitor succeeds deterministically | `UserArmMemory::check_exclusive` and direct memory implementation | Exact STXR status assertions | Same address and width, short budget, barriers | Intact monitor produces failure with no state/address change | Confirmed for tested software paths; not a hardware guarantee |
| A4 | The selected ordinary PE fixtures retain compiler-selected startup and original bytes | Retained fixture producer/IAT/entry receipts and integration image equality check | ARM64 slice-1 end-to-end acceptance | Both `main` and `wmain` | Fixture hashes, entry points, or IAT diverge; runner observes image mutation | Retained; native Windows execution unknown |

## Change-surface map

Direct A64 system-instruction execution and local monitor state are affected;
the direct decoder's existing fixed-field recognition is tested, not broadened.
User-mode AArch64 adapter, Windows/Linux schedulers, Linux signal/ptrace
boundaries, and unit/integration tests are affected. Memory/MMU addressing,
shared-memory versioning, direct non-A64 ISAs, SMIR IR/optimizer, native
lowering/JIT admission, backend adapters, machine/devices, oracle/analysis,
public Rust/C ABI and fixture bytes are unchanged. The existing A64 SMIR
`CLREX` lift and interpretation already clear exclusives; their behavior is
checked against the direct-path correction, with no new native claim.

The local monitor is one `(address, size)` reservation, with an 8-byte access
in the `LDXR X`/`STXR X` tests. A one-instruction budget executes one 4-byte
A64 encoding before yielding; the reservation remains between consecutive
calls for the same TID. A real switch, explicit `CLREX`, or delivered
exception clears it before the next `STXR`, which writes status `1` to its
32-bit `W` result and leaves the 8-byte memory value unchanged. In the intact
software-monitor case, status is `0` and the 8-byte store occurs. The added
boundary checks are O(1) time and O(1) auxiliary space per selection/event.

## Bounded findings

| Impact | Evidence and boundary | Blocks this group? |
|---|---|---|
| High | Shared direct x87 decoder's 32-bit absolute ModR/M displacement handling lacks a `CS.L` distinction | No; separate ISA semantic group |
| High | The broader Windows language/runtime personality and arbitrary PE execution remain incomplete | No claim of full userland |
| Medium | Physical Arm hardware can fail a store-exclusive without an intervening write, while RAX's deterministic software reservation succeeds in that case | No; documented model distinction |
| Medium | `UserArmMemory` stores a per-thread `(address, size)` tuple, not a shared write-version; a future out-of-scheduler host writer would need a shared invalidation contract | No; current guest CPU scheduling is serial and this group does not add an external writer |
| Medium | Workspace all-target builds can report a pre-existing engine/C API `librax.rlib` output-name collision | No; compilation result must still be inspected |

## Validation and self-red-team

Focused receipts after source freeze: all four direct `CLREX` tests pass
(including all 16 `CRm` values), all four CPU-adapter exclusive tests pass
(including both WFI and WFE), three Windows scheduler tests pass and four
Linux scheduler/signal/ptrace tests pass. The 12 ordinary PE integration
cases pass: 3 ABIs × 2 entry forms × 2 slice budgets, with original image
bytes unchanged. The earlier portable library run was interrupted after an
additional WFE test was added and is not counted as a final gate. Final-layout
portable receipts are:

| Gate | Actual result |
|---|---|
| Library, `--no-default-features` | 6,821 passed, 2 explicitly ignored |
| Linux integration, `--no-default-features` | 36 passed, 1 explicitly ignored |
| Windows integration, `--no-default-features` | 528 passed, 0 ignored |
| Library, `--no-default-features --features x86_64-suite,smir-jit` | 8,993 passed, 2 explicitly ignored |
| Linux integration, feature-enabled | 36 passed, 1 explicitly ignored |
| Windows integration, feature-enabled | 528 passed, 0 ignored |
| Feature-enabled CI tooling target | 10 passed, 0 ignored |
| Portable and feature-enabled workspace all-target builds | Both passed; known engine/C API `librax.rlib` collision warning |
| Feature-enabled and default-feature workspace all-target Clippy | Both passed; lint tables allow warnings |
| Workspace formatting and tracked diff check | Both passed |
| Feature-enabled doctests | 0 executed, 5 explicitly ignored |

All selected Cargo gates used stable Rust with `--locked`; test binaries ran
serially where applicable. A green feature build on macOS ARM64 does not imply
Linux KVM, macOS HVF, or x86-64-host JIT execution. No new C ABI or package
interface was changed, so the C/C++ ABI consumer gate is outside this group.

QG1 requires no normative judgment. QG2 is the register above. QG3 is
audited against the focused CPU, direct `CLREX`, Linux, Windows and PE tests;
the exact-path commit/push criterion is audited after this precommit artifact.
QG4 verifies 4-byte instruction/32-bit status/8-byte memory dimensions above.
QG5 checks same-TID vs switched-TID, synchronous vs asynchronous events,
`CLREX` legal/reserved forms and ordinary barriers. QG6 uses the primary Arm
guide, retained ASL and executable source/tests; native Windows execution and
x86-64-host differential execution remain unknown on this host. QG7 records
adjacent non-blocking findings without changing them. The postcommit audit
must verify the exact path set, absence of forbidden commit metadata, and
`origin/user-win` ref equality.
