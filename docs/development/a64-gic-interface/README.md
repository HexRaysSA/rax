# Classic GIC CPU-interface and exception delivery

The classic single-Security-state GIC now keeps IAR, HPPIR and EOIR accesses in
their architectural groups. Wrong-bank reads return INTID1023 without consuming
the globally selected request; wrong-bank EOI writes preserve active state and
priority. A lower-priority request from another group cannot bypass that selection.

| Group | Acknowledge | Priority drop / EOI | Signal | PSTATE mask |
|---|---|---|---|---|
| 0 | ICC_IAR0_EL1 | ICC_EOIR0_EL1 | FIQ | F |
| 1 | ICC_IAR1_EL1 | ICC_EOIR1_EL1 | IRQ | I |

SGI register forwarding follows IHI0069H Table12-14, including its DS=1
exceptions. SGI1R can generate a configured Group0 request; SGI0R cannot generate
Group1. Secure/non-secure source state and absent EL3 are tested explicitly.
The unbanked public Gic convenience methods retain their existing interfaces.

The historical irq_line handle remains an aggregate interrupt-request handle.
A pending CPU path resolves the selected group under the GIC mutex before applying
masks. Ordinary no-request polling retains its atomic fast path. Direct ArmCpu
stepping reports InterruptPending without taking a vector; system interpreter
and bounded native entry take the corresponding IRQ/FIQ exception. EL2/EL3
routing, implicit lower-target masking, higher-target mask bypass, TGE independent
of E2H, and existing AArch32 Hyp delivery are covered within the represented profile.
This does not qualify every optional interrupt, virtualization or debug control.

WFI wakeup is independent of PSTATE.I/F; WFE can complete on an eligible
unmasked IRQ/FIQ without an event-register signal. Direct wait polling publishes
current timer outputs with zero counter advancement. The existing spurious-wakeup
policy and controller-less physical-timer fallback remain represented.

With E1NWF=0 and DPGS=0, an Any-routed SPI selects the first awake,
group-enabled PE. Exactly one participating PE receives the selection. WAKER
and group changes retarget it deterministically. Affinity routing retains the
previously qualified disabled-group exclusion policy.

GICD enable/pending clear aliases read their corresponding state. GICD and GICR
set-active writes preserve pending state; clear-active removes only active state.
These MMIO operations do not perform the CPU-interface priority drop. Word state
registers cover classic SPI32-1019 and private SGI/PPI0-31 respectively; reserved
INTIDs remain excluded. No broader MMIO-width or optional GIC profile claim follows.

## Checkpoint boundary

There are no new serialized fields or frame tags. Controller selection is derived
from the represented group, routing, WAKER, active and pending state. Restoration
publishes into target-owned aggregate handles and resolves the type from restored
state; there is no separately serialized IRQ/FIQ cache. Existing source-bearing
migration and rejection of ambiguous legacy pending sources remain unchanged.
The correction does not retain historical wrong-bank or Group0-as-IRQ behavior.

The six source-free files cover prepared 1/2/4-PE cohorts and both interrupt
groups with 128 MiB RAM. Guest code wakes each Redistributor, configures and pends
SGI7, enables both groups and waits with masks set. After capture/save/load, the
source kernel and checkpoint files are removed before constructing a fresh VM
from the loaded bundle. Re-restoration retains target-owned handle identity.

Both source and restored VMs then unmask the appropriate signal. Each PE's
exception-entry turn retires zero instructions and retains its saved ELR. Guest
handlers acknowledge through the correct bank, issue a wrong-bank EOI, inspect
RPR and active state, attempt a wrong-bank IAR, then issue the correct EOI and
return. Complete CPU state, counts, controller/coordinator state and the selected
Retired clock are compared before entry, at the entry boundary and after return.
Counts are nine retired instructions before entry and twenty after continuation
per PE. These are 28 post-snapshot handler executions across source and target.
They are prepared cohorts, not guest cold-start coverage.

## HCR_EL2 software virtual interrupts

The software AArch64 CPU considers HCR_EL2.VI and VF at EL0 and EL1 when EL2
is enabled and TGE is clear. IMO gates VI and FMO gates VF. Each level can end
WFI even with its PSTATE mask set. An unmasked level can also end a prior WFE
and causes an EL1 exception before the next guest instruction retires. Entry
keeps the HCR_EL2 level asserted for the hypervisor to clear. Process adapters
continue to execute without the system's virtual inputs.

The existing physical request has precedence when it can be delivered. The
software CPU selects IRQ when both virtual levels can be delivered. Selection
uses constant time and auxiliary space beyond the existing physical GIC query.
The existing checkpoint captures HCR_EL2 and PSTATE for each vCPU. A detached
file test restores an IRQ on CPU 0 and an FIQ on CPU 1 with distinct EL1
vector bases, and checks the saved ELR, SPSR and unchanged retirement count
before both handlers run through the VMM coordinator.

| Assumption | Falsification probe |
| --- | --- |
| Each HCR_EL2 level requires its own gate and targets EL1. | Vary EL, security state, TGE, and the PSTATE masks. Check the vector, saved PC, and that an eligible physical interrupt preserves its precedence. |
| WFI completion and exception masking are independent. | Enable TWI and mask a pending virtual level, then execute WFI. Also assert the level after WFI and verify that the retired clock admits the waiting PE without taking an exception. |
| The persisted HCR_EL2 level belongs to one PE. | Remove the source VM and reopen the checkpoint file. Each receiving PE must enter its own vector with the saved ELR and zero guest retirements. |

The pinned [Arm pseudocode](../../specifications/arm/pauth/shared_pseudocode-2025-12.xml)
defines `AArch64_InterruptPending` and the AArch64 and AArch32
`TakeVirtualIRQException` and `TakeVirtualFIQException` entry rules. A bare-metal
guest assembled with LLVM MC 23 passed 13 cases in QEMU 11.1.2. The cases check
EL0 and EL1 vector entry, independent masks and gates, simultaneous virtual
levels, the saved ELR and masked WFI with TWI set. RAX also tests its AArch32
EL1 vector entry, banked LR and mode transition through the mixed-width CPU.
The three original regressions failed on the baseline. All eight focused tests
passed with and without SMIR JIT. The eight complete integration binaries
passed 47,603 tests and ignored three. The runtime checkpoint binary passed
serially after the host killed the concurrent run. Clippy passed with SMIR JIT.
The unfiltered library run reproduced the existing Darwin codesign failure.
Evidence is retained under
`/Users/int/dev/rax-audit-work/four-findings-a64-hcr-virtual-interrupts-2026-11-24`.

High-impact open work includes the virtual GIC CPU interface, delegated
interrupts, and native backend delivery and migration.

## HCR_EL2 virtual SError

In the classic software Arm profile, an enabled EL2 supplies virtual SError
to EL0 and EL1 when `HCR_EL2.VSE=1`, `AMO=1`, and `TGE=0`. The pending
request can end WFI while `PSTATE.A` is set. Once unmasked, entry targets
EL1 and takes precedence over instruction retirement. An eligible physical
IRQ/FIQ or virtual IRQ/FIQ retains scheduler precedence. EL1 entry consumes
only `VSE`. AArch64 receives `ESR_EL1=0xbe000000`, and AArch32 reports an
asynchronous external abort using the appropriate long or short descriptor
DFSR encoding. The legacy implementation-defined ISS and ExT fields are zero.
The entry check takes constant time and space outside the existing GIC query.
[Arm exception-entry and interrupt-pending pseudocode](../../specifications/arm/pauth/shared_pseudocode-2025-12.xml)

The checkpoint uses the existing per-vCPU `HCR_EL2` and PSTATE fields.
Detached two- and four-vCPU files preserve `VSE` after the source VM is
dropped. Each PE with a pending request enters its own vector with its
saved PC and PSTATE and no retirement. The guest handler returns with ERET;
the original WFI then retires without a second delivery. Peers whose `VSE`
was clear reach WFI directly. The tests use prepared software vCPUs and the
retired-instruction clock.

| Assumption | Falsification probe |
| --- | --- |
| The classic virtual request is enabled only in the applicable EL2 regime and consumed on entry. | Vary AMO, TGE, EL, security, PSTATE.A, competing virtual IRQ/FIQ, and the EL1 stack selector. Verify ELR, SPSR, and HCR_EL2 before entry and after ERET. |
| The wake condition is independent of the SError mask. | Test a pending request with TWI armed and a request asserted after WFI. Check that the masked PE can retire and that unmasking consumes the retained request exactly once. |
| AArch32 entry uses the Abort bank and descriptor-specific DFSR. | Use ARM and Thumb input states and both TTBCR.EAE values. Verify the Abort vector, banked LR plus eight bytes, and DFSR. |
| The event belongs to one CPU through checkpoint restoration. | Reopen the bundle after dropping the source. Require each PE's own vector, saved PC, and zero entry retirements before allowing the guest to execute ERET and WFI. |

QEMU 11.1.2 with Cortex-A57 passed 14 independent cases, including
AArch64 entry and return, mask and routing controls, WFI, and both AArch32
descriptor formats from both ARM and Thumb. Four RAX regressions failed on
the predecessor and passed after the change. The routing and precedence
controls passed in both revisions.

Eight complete macOS arm64 integration binaries passed 47,603 tests with
SMIR JIT enabled. The Docker oracle was the sole ignored test. Clippy passed
for the JIT-enabled library. Qualification logs and the independent guest
sources are under
`/Users/int/dev/rax-audit-work/four-findings-a64-hcr-virtual-serror-2026-11-24`.

High-impact open work includes RAS syndrome registers and ESB deferral,
HCRX_EL2.TMEA, delegated and physical SError sources, halting-debug masks,
and native checkpoint delivery.

## Physical interrupt preemption and binary points

The physical software GICv3 CPU interface now applies each PE's
`ICC_BPR0_EL1`, `ICC_BPR1_EL1`, and `ICC_CTLR_EL1.CBPR` when deciding whether
a candidate can preempt an active interrupt. Candidate selection and PMR
filtering still use the full priority. `ICC_HPPIRn_EL1` can show the selected
candidate while `ICC_IARn_EL1` returns 1023 because the candidate cannot
preempt. Acknowledgement records the interrupt's group priority at that
point. Priority drop restores the previous active priority, and subsequent
binary-point writes affect the preemption comparison without changing the
stored active priority. These rules follow [Arm IHI0069H](../../specifications/arm/gic-ihi0069.pdf),
§4.8.3 and §§12.2.5–6, 12.2.20. The independent implementation reference is
the [QEMU GICv3 CPU interface](https://qemu.googlesource.com/qemu/%2B/108d99742af1fa6e977dcfac9d4151b7915e33a3/hw/intc/arm_gicv3_cpuif.c).

The checkpoint layout is unchanged. Restore derives the candidate's group
from the saved interrupt state and rebuilds the IRQ level. Legacy records
with BPR1 set to zero read back at the Non-secure minimum of one when CBPR
is clear. Legacy raw active priorities resume at their stored value, with
the current binary point applied for preemption and RPR bit 0 cleared for
active interrupts. The older format provides no independent record of the
binary point at the time of acknowledgement.

| Assumption | Falsification probe |
| --- | --- |
| Subpriority orders pending interrupts within the same group priority. | Acknowledge a lower-priority SGI, then raise an SGI with a better subpriority. Require HPPIR to report the new INTID while IRQ remains clear and IAR returns 1023. |
| The binary point belongs to each PE and CBPR selects its common register. | Boot two and four PEs with PSCI, alternate CBPR by PE, and read back both BPRs, RPR, HPPIR and IAR. |
| An active priority is fixed at acknowledgement. | Change the binary point with an active SGI and a pending SPI. Check the active rank, the IRQ level, and the rank restored after nested priority drop. |
| A detached checkpoint retains active and pending state on each PE. | Hold an active SGI and a blocked pending SGI on every PE at WFI, discard the source VM, restore from file, and observe priority drop and one delivery on each restored PE. |

QEMU 11.1.2 matched 31 boot-PE observations in each one- and four-PE
configuration and eight per-PE observations for all PEs in two- and four-PE
boots. Both sets ran on Cortex-A57 and `max`, for 220 observations in
total. The pre-fix RAX test reproduced an incorrect IRQ assertion when
only the subpriority improved. Source, expected observations and RAX logs
are in `/Users/int/dev/rax-audit-work/four-findings-a64-gic-binary-point-2026-11-24`.

Both controller regressions and the detached two- and four-vCPU checkpoint
test passed. All six owning integration executables passed 47,530 tests
with SMIR JIT enabled in the build. The initial parallel ARM suite ended
with SIGKILL. The completed serial rerun included all 46,850 ARM suite
cases. Clippy passed for the JIT-enabled library. The unfiltered library
run reproduced the earlier Darwin codesign failure in
`closed_dispatcher_copies_self_status_without_host_observation`.

The preemption comparison is O(1) after candidate selection. A BPR or
CPU-control write still uses the existing O(P(32+S)) routing update for
P participating PEs and S SPI storage entries. This group covers the
software physical CPU interface with a single security state. High-impact
open scope includes hardware GIC save/restore, complete security and
virtualization profiles, and other backend checkpoint and SMP paths.

## Physical active-priority registers

Each PE now exposes four 32-bit `ICC_AP0Rn_EL1` registers for Group 0 and
four `ICC_AP1Rn_EL1` registers for Group 1. For the represented eight-bit
priority interface, register `n`, bit `b`, represents group priority
`2 * (32 * n + b)`. Acknowledgement sets the bit for its group and rank.
RPR reads the highest priority across both banks or `0xff` when both are
empty. EOIR drops a priority, and DIR changes the distributor's active
state when priority drop and deactivation are split. Guest APR writes
change RPR and can change whether an interrupt can preempt. The
redistributor and distributor active bits belong to the interrupt itself.
[Arm IHI0069H, §§4.8.4 and 12.2.1–2](../../specifications/arm/gic-ihi0069.pdf).

The checkpoint stores all eight words per PE. Shared execution frames use
`RAXEXE15`/`RAXEXE16`, and owned-controller records use
`RAXA6409`/`RAXA6410`. Earlier tags remain readable. For old checkpoints,
the reader derives APRs from recorded priorities and each interrupt's saved
group. Older raw ranks are rounded down to the nearest even encoding.
Record admission rejects a discrepancy between the derived RPR and the
saved running priority, as well as an APR count that differs from the PE
count. The earlier source-latch admission rules still apply.

| Assumption | Falsification probe |
| --- | --- |
| An acknowledged rank is visible on its group's APR bank. | Nest four interrupts across both groups and all four bank indices. Verify each bit, reverse the acknowledgement sequence with EOIR, and test DIR separately. |
| A priority installed by MSR can exist independently of an interrupt's active state. | Block a pending IRQ with an APR-only priority. Verify that distributor active bits stay clear and clearing the APR republishes the existing IRQ line. |
| A same-version detached image can contain a priority with no acknowledged INTID. | Write a different APR-only rank on each of two or four vCPUs, discard the source, then read both banks and independently drop the acknowledged and software-written priorities. |
| Earlier checkpoint layouts contain enough information to reconstruct their represented priority active state. | Decode old shared frames with and without PL011 and both older owned-controller profiles. Compare the migrated state and reject a new frame whose APRs disagree with RPR. |

The baseline RAX guest acknowledged an interrupt and read a zero APR word
for both groups. The same transfer probe produced 26 matching observations
each on the corrected RAX software VMM and on QEMU 11.1.2 with Cortex-A57
and `max`. The guest derived its APR index from each model's reported
priority width and checked that clearing and restoring the bit changed RPR
and IRQ admission while preserving the interrupt's active state. The
controller and detached-checkpoint regressions passed, as did all 47,530
tests in the six owning integration executables. The C API suite passed
258 tests with 21 ignored, and the JIT-enabled library passed Clippy.
The unfiltered library process received SIGKILL after emitting 12,975
results, including the previously reproduced Darwin codesign failure.
All 16 execution-frame tests passed when run directly from that binary.
Logs, probe source and executable hashes are in
`/Users/int/dev/rax-audit-work/four-findings-a64-gic-active-priorities-2026-11-24`.
[QEMU CPU interface](https://qemu.googlesource.com/qemu/%2B/108d99742af1fa6e977dcfac9d4151b7915e33a3/hw/intc/arm_gicv3_cpuif.c).

RPR selection visits at most four 32-bit word pairs. APR writes reuse the
physical router's O(P(32+S)) update to republish the IRQ line, where P is
the PE count and S is the number of SPI entries. The per-PE wire payload
adds 32 bytes of APR data and the vector adds one 8-byte count. Native
controllers, AArch32 GIC CPU-system-register aliases, virtual or secure
APR banks, and GICv3.3 NMI behavior remain outside this validation scope.

## AArch32 physical CPU interface aliases

An AArch32 EL1 guest on a mixed-width PE can reach the shared physical
GICv3 interface through CP15. The A32 and T32 scalar transfers use the
same priority, acknowledge, deactivation, control and group-enable state
as the AArch64 accesses. The three SGI aliases concatenate the pair as
`Rt2:Rt`, preserving the 64-bit target and routing fields. The software
controller already includes these values in its checkpoints.
[Arm IHI0069H, Table 12-7](../../specifications/arm/gic-ihi0069.pdf).

The instruction predicate and architectural access checks precede the
GIC operation. The existing CP15 HSTR path owns syndrome generation for
intercepted transfers. EL0 and invalid transfer directions take the
undefined-instruction path. Transfers that require virtual GIC state or
higher-EL GIC routing traps report an unsupported execution state before
touching the physical controller. The system register interface retains
the software controller's always-enabled setting.

| Assumption | Falsification probe |
| --- | --- |
| The AArch32 and AArch64 aliases address the same physical PE state. | After an A32 or T32 acknowledge, check IAR, RPR and APR. Write a second APR, drop the first and read the resulting register state from the AArch64 CPU-interface path. |
| The bridge can reuse the existing predicate and HSTR policy. | Exercise failed A32 and T32 predicates and then take an HSTR trap at the same address. Check the pending INTID, destination register and retirement count. |
| The SGI operand pair preserves upper routing bits. | Set IRM in the high word and use an empty target list. Observe the pending bit on a peer PE and check that the source PE remains clear. |
| Unsupported routing can be identified before physical acknowledgement. | Apply IMO and FMO separately and probe common and bank-specific registers. Check that only a selected route prevents physical execution. |

The external probe entered AArch32 EL1 by ERET from AArch64 EL2. After
retiring a `CNTFRQ` read it attempted `ICC_RPR` at `0x40200038`. The
baseline RAX executable stopped with `UnsupportedExecutionState` and
14 retirements. QEMU 11.1.2 with Cortex-A57 and `max` each returned the
idle RPR and exited successfully. The RAX candidate also returned `0xff`
and retired the transfer as instruction 15. All five focused regressions
and 47,530 tests in the six owning executables passed, and the
JIT-enabled library passed Clippy. Probe source, per-step
observations and hashes are in
`/Users/int/dev/rax-audit-work/four-findings-a32-gic-aliases-2026-11-24`.

Alias decoding takes constant time and space. Controller effects retain
the AArch64 path's costs. Independent instruction-by-instruction coverage
of the remaining GIC routing traps, virtual registers and separate secure
banks remains open, as does native execution on physical Arm hardware.

## Evidence and limits for the initial CPU-interface group

qualification.json records the exact tested source and executable hashes,
commands, observed reds/greens, Assumption Register, host/toolchain and omitted
gates. No stopped or compilation-failed iteration is a passing gate. In particular,
a discarded TGE/E2H interpretation and a probe missing activation readback are
recorded as invalid evidence, with corrected independent probes retained.

The current host is Apple M4 Max, macOS 27.2, Rust 1.99.1, LLVM 23.1.1.
There are twenty-one new root test declarations and one new standalone
controller-less timer test. The final unfiltered root result is 12,073 passed, zero failed and 35 ignored.
The registered cluster target passes all 27 cases. The 23 owning executables
include one cfg-empty target; qualification.json contains every count and command.
The Linux-AArch64-only native suite is cfg-empty on this host. No new hardware
or QEMU GIC oracle, native Intel VM execution, or C/C++ consumer rebuild is claimed.

Selection remains O(P(32+S)) time for P PEs and S SPI storage entries, with
O(P) participation selection and constant additional target storage. Per-word
state reads inspect at most32 interrupts. No throughput benchmark is claimed.
Public C ABI identifiers/layouts and instruction encodings are unchanged.

Primary rules are retained in [Arm IHI0069H, ID020922](../../specifications/arm/gic-ihi0069.pdf),
sections2.2.1,2.3.2,4.1,4.6.2,12.1.10,12.2.11-14 and the GICD/GICR state-register
descriptions; [DDI0487B.a](../../specifications/arm/aarch32-fp-profile/armv8a-ddi0487ba.pdf),
D1.14 and D1.17, supplies interrupt mask/wakeup rules. The retained
[Arm XML2025-12](../../specifications/arm/pauth/shared_pseudocode-2025-12.xml)
TakePhysicalIRQException/TakePhysicalFIQException functions govern TGE routing.

The original A32-FP, C-STATE, C-SMP and C-HVF findings remain incomplete. Remaining
high-impact work includes full backend/private/in-flight and transactional state,
startup/clock/replay/debug and native controller profiles, native streaming FPSR
reentry and physical Intel qualification. The separately reproduced SPI discovery defect is corrected by the
[discovery/routing followup](../a64-gic-discovery-routing/README.md), which also
qualifies guest PSCI secondary startup and top-bank SPI file continuations.
Optional GIC/NMI/LPI and complete
security/virtualization/debug behavior are not established by this group.

Historical ax.trace preservation failed before this group; its writer/cause and
original-content recovery remain unknown. This group guards its present bytes,
the primary executable and the protected guest processes. It does not relabel
the earlier loss as successful preservation. Pre-existing untracked user files
and other checkouts remain outside the owned change set.
