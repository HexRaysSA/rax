# Per-CPU task-priority coherence

The attached local APIC owns its complete eight-bit task-priority register
(TPR). CR8 projects TPR[7:4] as a zero-extended four-bit class. An explicit
MOV-to-CR8 writes that class and clears TPR[3:0]. Public CPU-state import is a
projection operation: importing an unchanged CR8 class preserves the existing
subclass, including when `set_regs` changes only general-purpose registers.
Importing a different class clears the subclass.

Four actual baseline regressions exposed separate owners: a guest CR8 write did
not update its AP controller, a CR8 read missed a controller update, public CR8
import missed the controller, and native-style AP MMIO returned the BSP's APIC
ID. The initial regression set passed after connecting the owners. Broader
validation found and fixed the unrelated-register import/subclass loss above.

## Ownership and checkpoint publication

`devices/lapic/priority.rs` provides an explicit shared priority handle. CPU
getters read it without reacquiring the LAPIC mutex: coordinated capture already
holds every controller lock. Ordinary snapshot clones freeze the current value;
only explicit handle clones share identity. Serialization remains one `u32`,
preserving the previous positional TPR field in both local-controller codecs.
No host pointer, atomic representation or lock enters a checkpoint.

Controller replacement and INIT preserve the live handle while restoring its
value. Prepared CPU replacements keep the target controller binding; publishing
the captured controller subsequently supplies the captured full priority byte.
CPU public/private projections are captured from that same owner. Full bundles
reject disagreement between any CPU's CR8 and its controller's TPR before
publication. Inline private contexts and legacy BSP restore perform the analogous
check. An older contradictory CR8/TPR record is rejected rather than guessing
which value describes the intended architectural state.

Writers still require the existing stopped CPU/controller publication contract.
An atomic priority cell does not establish a complete concurrent checkpoint.

## Execution paths

Direct x86 control instructions and public CPU state use the attached owner;
standalone MMUs use their inline controller. Native x86 JIT writes update that
owner through the canonical helper. Reads use an append-only live-priority
callback in the native frame, so a preceding MMIO update in the same block is
visible. Standalone lowering frames with a zero callback retain their existing
register projection. A callback failure deoptimizes at the original instruction
without destination or flag publication. Existing native-frame offsets remain
fixed; the callback follows the previous retirement metadata. The runtime
verifier saves, restores, compares and adopts
the complete TPR, including its subclass. Standalone SMIR interpretation retains
its explicit architectural register state; it has no attached VMM controller.

Public hardware MMIO exits select the originating CPU's controller for reads,
writes and RMW. A scoped bus override retains the original mapping geometry and
restores the legacy BSP owner on success, error or unwind. The override ends
before CPU completion callbacks or checkpoint capture.

Intel HVF binds the same priority owner. CR8 transfers use it, and native entry
refreshes the SDK TPR mirror when it differs. Public state captures the canonical
class; import publishes the SDK before updating the owner. A failed native
priority write, including a possibly partial SDK write, permanently prohibits
guest entry through that CPU. Rebinding a controller or importing state cannot
clear this failure. SDK read failure before a write is retryable. This is a
publication fence, not a claim of SDK rollback or failure recovery.

Processor priority preserves the full TPR when its class exceeds the highest
in-service class. Otherwise this model returns the in-service class with a zero
subclass. Intel permits model-specific subclass behavior for equal classes;
this profile consistently selects zero.

## Evidence and remaining scope

The [qualification JSON](task-priority-coherence-qualification.json) records
exact current test counts, commands, source
hashes, QEMU observations and execution environments. Substituted SDK tests,
actual software guest execution, generated x86 code under Rosetta and physical
Intel VMX are distinct evidence classes. The QEMU reference retains its known
reserved-CR8-bit masking discrepancy; legal transfers and primary-source
reserved-bit requirements are assessed separately.

This component assumes the hardware local APIC is enabled. Full APIC_BASE
disable/relocation, advertised x2APIC/MSR behavior, interrupt source routing,
native SDK thread ownership, bounded native scheduling, private/in-flight
checkpoint state and physical Intel validation remain required work. The full
A32-FP/C-STATE/C-SMP/C-HVF goal remains open.

Primary source: Intel SDM revision 086, December 2024, Volume 3A sections 12.8.3.1
and 12.8.6.1 (pages 12-29 and 12-32), retained at
[`325462-sdm-vol-1-2abcd-3abcd-4-1.pdf`](../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf),
SHA-256 `6f6286056edad4ffdca8716e9039e9598e9e71ab029284facde6a786e1b65f73`.
Mixed direct-TPR/CR8 software needs architectural serialization when ordering is
required; these host-model tests do not establish physical ordering guarantees.

## Assumptions and probes

| ID | Assumption | Stress test or falsification probe |
|---|---|---|
| P1 | The attached per-CPU controller owns priority | All TPR bytes, CR8 classes, both guest directions, AP identity, unrelated state import and SDK mirror changes |
| P2 | Capture is quiescent and holds controller locks | Actual bundle capture/restore; CPU getters must not re-enter those locks; frozen snapshots and preserved live bindings |
| P3 | Existing TPR wire data is a `u32` | Compare exact primitive codec bytes across boundary values; retain versioned context regression tests |
| P4 | Native publication errors may have partial effects | Simulate SDK mutation followed by error and verify permanent entry exclusion and unchanged software publication |
| P5 | Physical Intel behavior is unverified here | Run signed native Intel VMX/guest qualification on a physical Intel Mac; target compilation and Rosetta do not satisfy this gate |
