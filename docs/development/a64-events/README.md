# Software AArch64 event delivery and checkpoint publication

`SEV` synchronously sets the event latch of every configured processing element
in a software ARM cluster. `SEVL` sets only the executing PE's latch. Repeated
signals coalesce into one bit, and `WFE` atomically tests and consumes that bit.
The ARM and Thumb bridges publish these effects only when their instruction
predicate succeeds. ARM and 16-bit Thumb now recognize their existing `SEVL`
aliases; 32-bit Thumb already recognized the instruction.

Each CPU and its platform share a stable atomic latch handle. Fanout acquires
the existing cluster control lock, which also excludes cohort capture and
restoration. It takes no GIC lock and invokes no guest callback. Failure to
acquire that lock precedes all event effects and instruction retirement. The
single-PE memory interface has a default successful no-op platform hook; the
CPU still publishes its own local latch. Fanout takes O(N) time and O(1)
auxiliary storage for N configured PEs; the platform owns O(N) latch storage.

The direct CPU keeps waiting until an event completes its existing `WFE`.
System entry consumes a pending event and proceeds to the next instruction.
Without an event, system entry retains its existing single-yield spurious-wakeup
policy. Powered-off PEs do not execute. Their subsequent CPU startup/reset
clears their local latch while preserving the platform handle.

## Classic A64 wait traps

For A64 `WFE` with an empty event latch and `WFI` without a pending modeled
physical or HCR_EL2 virtual IRQ or FIQ, the software CPU checks the effective
EL0 SCTLR, then eligible HCR_EL2 controls, then SCR_EL3. HCR_EL2.TGE redirects an EL0 trap
from EL1 to EL2 when EL2 is enabled. VHE host EL0 uses SCTLR_EL2. The trap
records EC 0x01 and the WFx selector in ESR, records the instruction address in
ELR, and leaves retirement and the wait latch unchanged. A ready wakeup
allows the hint to retire. A ready WFI still yields to the coordinator and
keeps the PE runnable. EL0 process adapters continue to expose these
hints as yields while retaining their instruction budgets and exclusive
monitors.

The detached two-PE file test sets TWE on CPU 0 and TWI on CPU 1. The real
VMM coordinator resumes both CPUs, checks their distinct ELR and ESR values
and verifies that only their EL2 handler instructions retire. The control
registers already travel in each PE's saved state. Trap selection takes
O(1) time and O(1) auxiliary space for each hint.

| Assumption | Falsification probe |
| --- | --- |
| Effective SCTLR and eligible HCR/SCR determine the route. | Exercise EL0 through EL3, Secure EL1 and VHE host EL0. A mismatched target, exception syndrome or saved PC falsifies the route. |
| A ready event or a pending masked physical interrupt completes the hint before a trap. | Arm the trap controls and supply an event or timer interrupt. A trap, a set wait flag or an unconsumed event falsifies completion. |
| Each PE retains its selected controls through detached restoration. | Resume two PEs with different controls, opcodes and vectors. An incorrect CPU index, syndrome, address or retirement count falsifies restoration. |

The pinned [Arm pseudocode](../../specifications/arm/pauth/shared_pseudocode-2025-12.xml)
defines `Hint_WFE`, `Hint_WFI`, `AArch64_CheckForWFxTrap`, and
`AArch64_WFxTrap`. LLVM MC 23 assembled a bare-metal guest that set TWE
and TWI. QEMU 11.1.2 consumed the first WFE's event, then reported ESR
0x07e00001 for the second WFE and 0x07e00000 for WFI, with ELR pointing to
each trapping instruction. Baseline, test and independent oracle evidence is
recorded under `/Users/int/dev/rax-audit-work/four-findings-a64-classic-wfx-traps-2026-11-24`.
The six complete ARM, oracle, retirement and checkpoint integration binaries
passed 47,528 tests and ignored two tests that require entitled Apple Silicon
execution. The Linux process binary passed 43 tests with its Docker oracle
ignored. All 12 interrupt-delivery unit tests passed, including IRQ and FIQ
arrival before or after WFI. The library compiled with and without SMIR JIT.

High impact coverage still open includes timed WFxT, delayed WFE trapping,
EL3 halting-debug priority, virtual GIC wake sources, and mixed-state
AArch32 trap routing. This change qualifies the software path for these
classic A64 instructions. The HCR_EL2 cases have a separate
[qualification](../a64-gic-interface/README.md#hcr_el2-software-virtual-interrupts).

## Restoration and native helpers

`CoreCheckpoint` retains its serialized Boolean event field and field order.
The platform checkpoint and existing execution-extension tags are unchanged.
Preparation installs the saved bit into a detached CPU's private latch, then
records the existing target handle separately. Obtaining a publication permit
binds the detached CPU to that target handle without writing the live value.
The no-fail admitted commit publishes the saved value before marking the CPU
active. Cancelled permits and failed cohort admission preserve live values.

A publication scope is thread-confined by its controller guards and `RefCell`
state. Multiple permits for one prepared activation may exist, but only the
first can publish it. This prevents stale event, reservation and owned-controller
state from being replayed by a second permit.

Typed native PAuth instructions cannot consume an event. Their return path
therefore merges a set event without clearing a new signal received during a
memory helper. The native regression injects a signal during an actual LDRAA
helper after frame export and checks the loaded value, retirement and native
entry count. SEV, SEVL, WFE and WFI continue to reject ordinary native admission and
execute at the CPU boundary. No new standalone SMIR event topology is claimed.

## Primary provenance

The repository's unchanged [Arm instruction ASL](../../architecture/arm/asl/arm_instrs.asl)
identifies `aarch64_system_hints`, `aarch32_SEV_A` and `aarch32_SEVL_A`.
The AArch32 definitions use conditional execution. The unchanged
[Arm shared ASL](../../architecture/arm/asl/arm_defs.asl) defines `SendEvent`,
`SendEventLocal` and `IsEventRegisterSet`; `SendEvent` signals all PEs, while
`SendEventLocal` sets the current PE's Event Register. Their SHA-256 values are:

- `arm_instrs.asl`: `3c91ece6d0509f7ce9e8b2d8fa623787d7c7acb4cb24040a75cec5aa2789e611`
- `arm_defs.asl`: `1ade68e5dacfff1b63a42ad3ee1c426aae5d36ed5dfcbf39de4baab478a190f8`

LLVM MC 23 independently assembled A64 SEV/SEVL/WFE, conditional ARM hints,
and 16/32-bit Thumb forms. Exact inputs, output, source hashes, baseline failures,
terminal receipts and byte comparisons are retained under
`/Users/int/dev/rax-audit-work/four-findings-aarch64-cluster/a64-shared-events`.
The unchanged implementation failed seven of twelve event tests. A separate
baseline failed after a duplicate permit restored an invalidated reservation.

## Assumption register

| ID | Assumption, basis and dependent result | Stress test and falsification probe | Status |
| --- | --- | --- | --- |
| EV1 | The ASL distinguishes broadcast SEV from local SEVL; stable per-PE latches implement that distinction. | 2/4 PEs, BSP/AP senders, coalescing and a waiting peer. A fresh peer waiting after SEV or consuming a peer SEVL falsifies it. | Confirmed within the recorded software-cluster and predicate cases. |
| EV2 | Failed A32 predicates suppress event effects while retiring and advancing IT normally. | ARM conditions and 16/32-bit Thumb IT; true/false predicates and failed fanout. Any skipped event setting a latch or failed fanout advancing PC/IT falsifies it. | Confirmed within the recorded software-cluster and predicate cases. |
| EV3 | Existing serialized Booleans and target bindings survive detached preparation. | Exact parent/current core and cluster bytes, cancelled permits, duplicate permits, rejected final CPU, 2/4-CPU file restoration and native load interleaving. A changed wire image, early publication, lost signal or detached restored CPU falsifies it. | Confirmed within the recorded wire, publication, native-helper and file cases. |

High impact: complete backend/in-flight state, all-writer quiescence, broader
wait/trap/startup profiles, debugger and full replay, hardware virtualization
entry and physical Intel HVF validation remain open. The control lock serializes
broadcast with whole-cluster capture/restoration; arbitrary independently running
CPUs outside that stopped-VM contract are not a newly qualified checkpoint model.
Medium impact: fanout is linear in CPU count, and no throughput claim is made.
All four full audit findings remain partially validated.

Final qualification: all 108 event-focused tests and all five complete publication
unit tests passed. The complete library passed 11,311
tests with two ignored; 47,745 integration tests across
24 complete binaries and all 223 C API tests passed. The three affected native
execution binaries also passed serially, matching CI. The complete static ISA
oracle binary passed as well. Workspace format/Clippy/build,
interpreter-only and x86-64 compile checks, documentation links and source freezes
passed. Doctests ran zero cases with five ignored. Three additional reversals
independently reproduced native-frame signal loss, WFE signal loss, and duplicate
activation; the production source was restored and requalified afterward. Physical
Intel runtime validation did not run.
