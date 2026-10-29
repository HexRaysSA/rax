# Precise AArch64 Undefined retirement and continuation

The shared AArch64 executor now returns `CpuExit::Undefined` at the original
instruction PC, preserves BTYPE and increments neither instruction nor emulated
cycle counters. Direct Rust callers retain that return variant. System stepping
translates it through the existing uncategorized exception path (EC=0), while
diagnostic stepping returns `ArmError::UndefinedInstruction` at the fault PC.
The software backend reports a typed invalid-instruction fault to diagnostic
embedders. No new instruction, native lowering or public ABI is introduced.

The fetch/execution-boundary methods moved from `cpu/exec.rs` into
`cpu/instruction.rs`. The added branch has O(1) time and auxiliary space and
allocates no state copy. Invalid helpers must still reject before data effects;
the complete private-state and RAM checks here establish that property for the
62 retained cases. This component does not establish whole-ISA admission.

## Primary evidence and observed parent failure

`provenance.json` pins the local Arm ASL source. `UnallocatedEncoding()` invokes
`AArch64.UndefinedFault()`, which saves `ThisInstrAddr()` and constructs an
uncategorized exception. The imported ASL's upstream revision is unknown.
The unchanged primary source remains at
[`arm_defs.asl`](../../architecture/arm/asl/arm_defs.asl).

`corpus.json` identifies 62 actual parent failures by word, original oracle
index and encoding names. The six retained QEMU captures contain the original
4,144-word FPEN=3 observations, with all selected words classified undefined on
A53, A76 and A710 at EL0 and EL1. The expected events were not generated from
RAX. Complete source/tool hashes and raw current/parent runs are retained in
the task evidence directory named by the ledger.

The parent regression ran against unchanged production source at
`1f1d33e4c628ed9fa0662d5b0cf4632aea2a99de`. All 496 cases
(62 words × 2 execution levels × 4 BTYPE values) advanced PC by 4 bytes,
incremented instruction/cycle counts from 17/29 to 18/30, and cleared BTYPE.
The corrected test compares every represented private CPU field and RAM.
Repeated failures also preserve counters at `u64::MAX`; a replacement ADD then
executes once at the original PC. This does not claim valid-instruction counter
overflow behavior beyond the tested fault path.

A fresh kernel replay compares the actual original and corrected engines with
QEMU using exact retained ELF/raw guest inputs. The original engine aborts on
the first Undefined exit at `0x40300004`. All 372 corrected comparisons
(62 words × 2 execution levels × 3 represented models) match QEMU and check
saved mode, syndrome, precise fault PC and an unchanged denied-instruction X0.
The original engine hash matches the earlier independent parent capture.

## State, API and scheduler coverage

The direct and system tests retain BTYPE and the fault SPSR, preserve registers
and prove zero retirement. The existing system-attempt timer still advances
16 modeled ticks for a fresh attempt. A synthetic already-produced native error
survives private serialization/restoration, completes once without another tick
or retirement, and then allows one handler instruction to retire. This is
continuation coverage, not proof of a newly native-lowered Undefined instruction.

The backend tests cover all 62 cases in architectural and diagnostic modes,
zero and nonzero budgets, retired virtual time, and private contexts saved before
and after delivery. The user-mode test checks repeated exceptions, pending-event
restoration and replacement execution with coherent public/private accounting.

The four fixture pairs in `fixtures/` were exported by the actual unmodified
parent library. Their manifest records source, producer and byte hashes.
They contain zero/one retired prefix instructions and one/three failed attempts,
including the old user's compensation for the core's false retirement count.
The corrected reader retains their historical counts and pending event, accepts
another fault without consuming a unit, and retires the replacement once.
The files are original outputs, not hand-constructed private records.

The public C API test covers 124 mode/encoding combinations, a retired prefix,
fault stop, complete context restoration and exactly one replacement instruction.
The documented public observation counter resets to zero after context restore;
the restored backend history remains intact. An initial assertion expecting the
public observation count to retain its old value was corrected against the
existing README, implementation and other architecture tests. Its failed run
is retained; no runtime counter contract was changed to satisfy the test.

The actual VMM coordinator test uses two and four software CPUs. It saves and
loads six file checkpoints before, during and after a round of faults, preserving
each CPU's frontier, the scheduler cursor and zero retired units. Each resumed
handler's ADD and WFI then retire once: two units per CPU, without replaying a
faulting instruction. This does not establish bounded native/hardware SMP.

## Qualification

Full library: 11235 passed, 0 failed, 2 ignored.
Affected integration targets: 47694 passed across 22 binaries.
C API: 223 passed. Formatting, workspace Clippy, all-target build, interpreter-only compilation and exact source-hash checks passed.
Selected Rosetta interpreter checks: 9 passed across five targeted runs. The full VMM file matrix ran on the native Apple Silicon host.
Doctests: 5 ignored. Physical Intel HVF and physical A32 runtime were not established on this Apple Silicon host.
The independent parent Darwin transport failures remain unresolved; a passing current run does not establish a fix for that unchanged source.


## Assumptions and remaining scope

| ID | Assumption and basis | Stress test and falsification probe | Status |
|---|---|---|---|
| UR1 | The direct `CpuExit::Undefined` variant is an existing observable contract, as shown by callers and exact-match tests. | All 496 state comparisons retain the variant; a changed variant, PC/BTYPE/data effect or retirement falsifies the result. | confirmed in the tested scope |
| UR2 | Fresh system attempts and already-produced synchronous completions have distinct existing timer behavior. | Check 16 attempt ticks versus zero repeated completion ticks, private restore, retired-clock budgets and following handler execution; an extra tick or retirement falsifies it. | confirmed in the tested scope |

High impact, still open under the original goal: wider unallocated-neighbor
FP-access priority; complete AArch32/SVE/SME, security/virtualization and debug
profile controls; complete backend/private/platform state outside this tested
continuation; remaining bounded native SMP and physical Intel HVF validation.
Other helpers that return Undefined still require instruction-specific admission
and data-effect verification. The recorded full neighborhood is not reported as
passing from this 62-case result. All four active full findings remain partial.
