# Software AArch64 CPU and interrupt ownership

The software VMM gives the configured processing elements one VM-owned GIC.
The coordinator starts with CPU 0 online. A valid PSCI `CPU_ON` queues the target
entry point, context ID and return execution state; the target remains
`ON_PENDING` until the coordinator installs that entry state. `CPU_OFF` parks the
calling PE. `AFFINITY_INFO` observes the same state machine, including aggregate
levels. These paths do not turn a secondary power-off into machine shutdown.

The flat topology retains the existing MPIDR affinity values `0..count-1`.
The device tree lists every configured CPU, its affinity and `enable-method =
"psci"`. Each PE binds its own ICC registers, IRQ mirror and timer PPIs. Shared
GIC distributor state is independent of CPU architectural reset. Resetting or
starting a PE therefore preserves the distributor and other PEs' interfaces.
External SPI levels supplied through the VM API reach the shared controller.

Redistributors use the existing low window until the UART boundary. Additional
frames occupy a separate region above both the low devices and guest RAM. The
GIC device-tree node lists the actual region count and stride. `GICR_TYPER.Last`
terminates each contiguous redistributor region (IHI0069H12.11.37), including
the low region when additional frames occupy the high region. Targeted SGIs use
all affinity fields and range selectors; all-other-PE requests exclude their
sender. An already-active SPI cannot be acknowledged again before deactivation.
RSS is advertised where range selectors are implemented.

The full-machine software profile resets into the Non-secure world and enables
the advertised HVC conduit. Its A32 and T32 HVC paths validate EL/enable controls
and retire exactly once on successful dispatch. Disabled calls remain at the
fault frontier. Conditional ARM HVC and Thumb HVC inside IT select UNDEFINED from
the documented constrained-unpredictable outcomes. Nonzero firmware immediates
do not dispatch PSCI. A32 callers receive `NOT_SUPPORTED` for every 64-bit
PSCI function identifier, including `AFFINITY_INFO` (DEN0022D5.2.1). Standalone and user-mode construction keep their existing
reset profile.

## Shared platform checkpoint

A software ARM cluster adds `RAXEXE02` to the existing execution extension. Its
bounded payload contains GIC configuration, distributor/SPI state, every PE's
private interrupt and CPU interface state, the power state machine and queued
requests, and the redistributor mapping. IRQ mirrors remain target-owned Arcs;
restoration republishes their levels rather than replacing their identities.
Other architectures retain the existing `RAXEXE01` encoding.

Admission checks topology, queue/state/online agreement and target mapping before
publication. Both platform locks are acquired before the VMM CPU/RAM commit;
the shared graph is published only after that commit succeeds. A failed commit
leaves the shared platform state unchanged. This does not make legacy fallible
CPU imports or every other device a whole-VM transaction. Software AArch64 SMP
restoration rejects records missing required shared interrupt/power state.

The graph payload complements architectural CPU projections. Complete CPU and
bridge private context, exclusive reservation persistence, all-writer
quiescence, debugger/AP selection, deterministic clock/replay, other native
tiers and hardware entries, and Intel Mac HVF qualification remain in the audit scope.
This change does not establish full C-STATE or C-SMP completion.

The subsequent [bounded AArch64 native tier](a64-bounded-native/README.md)
executes hot instructions through this software coordinator with one retirement
per native entry. Its actual 2/4-CPU VMM test checks fair quanta, native entry on
every CPU, cold-cache file restoration, and continuation against uninterrupted
execution. This is software scheduling with native JIT execution on Apple
Silicon; it does not qualify physical Intel virtualization.

## Validation and assumptions

`aarch64_cluster` exercises actual adapter instructions and public VM calls:
startup/pending/invalid/duplicate requests, 32-bit arguments, CPU_OFF/restart,
independent ICC/redistributor/timer state, masked WFI and active-SPI conservation.
Mixed-width cases execute ARM HVC and Thumb secondary instructions. Internal
unit tests cover graph publication, IRQ handle retention and framed admission.

`tools/checkpoint/aarch64_cluster_oracle.py` assembles the same guest for QEMU and
the real RAX CLI with 1, 2 and 4 CPUs. It checks secondary context IDs, per-PE
priority masks, SGI delivery and EOI, WFI and CPU_OFF. The 2/4-CPU runs also save
and resume in a new process after the source kernel path is removed. This is
execution evidence, not proof of every private CPU field or native scheduling.

| ID | Assumption / basis / dependent result | Stress test and falsification probe | Status |
| --- | --- | --- | --- |
| S1 | The board uses flat affinities, matching existing MPIDR construction; PSCI, FDT and SGI routing must agree. | IDs 0/15/16/122/123/254, absent affinities and reserved bits. Any disagreement between CPU identity and target selection falsifies it. | Tested within the represented topology. |
| S2 | The VMM coordinator owns guest instruction entry and power-request draining. | Pending startup, power-off and restoration at instruction boundaries. Any execution before entry installation falsifies it. | Software coordinator; native entry remains separate. |
| S3 | A CPU reset does not reset a VM-owned GIC. | Preserve BSP distributor/priority state while starting and resetting secondaries. A changed BSP bank falsifies it. | Covered by adapter and guest controls. |

CPU_ON target lookup takes O(1) time; queue insertion takes amortized O(1).
Aggregate affinity queries take O(N). Shared checkpoint time/storage is
O(32N + I + A + L + Q), for N PEs, I SPIs, A active-priority entries, L queued LPI
entries and Q power requests. No throughput claim is made.

High-impact remaining work includes complete private/reservation state and native
scheduling/runtime qualification. Medium-impact remaining work includes broader
GIC security/legacy profiles and measured high-CPU-count performance.

Primary references, archived under `docs/specifications/arm`, are Arm DEN0022D
(PSCI1.1), sections 5.1.3–5.1.5, 5.2 and 5.5–5.7; Arm IHI0069H, affinity routing
and ICC/GICR register descriptions; and the Arm A32/T32 ISA v2025-03 HVC A1/T1
entry. `cluster-provenance.json` records exact source URLs, hashes and notices.

Software reservation coherence for tracked RAM writers is described in
[aarch64-reservations.md](aarch64-reservations.md). Its writer and alias
boundaries do not establish complete checkpoint persistence or quiescence.

The [event-latch repair](a64-events/README.md) adds synchronous SEV broadcast,
local SEVL, atomic WFE consumption and conditional ARM/Thumb publication. It
retains the serialized Boolean and each target's stable handle across admitted
CPU restoration. Native PAuth writeback preserves a signal received in a helper.
Its event qualification does not close the remaining full audit findings.

## AArch32 CPU_ON data endianness

The software cluster includes the calling core's CPSR.E in the AArch32
secondary's requested PSTATE. The entry address still selects ARM or
Thumb independently. The existing pending CPU_ON record already carries
this PSTATE, so the same bit reaches the destination on direct startup
and after reloading a pending checkpoint. Older records retain the
endianness in their saved PSTATE. Setting the bit takes constant time
and adds no storage to the request.
[Arm DEN 0022D, section 6.4.3](../specifications/arm/psci-den0022.pdf)

| Assumption | Falsification probe |
| --- | --- |
| The pending request carries CPSR.E from the cold-start caller. | Queue CPU_ON from little- and big-endian ARM and Thumb callers. Restore the pending request from disk and run the target in the opposite instruction set. |
| The bit governs real memory access. | Have the started core execute LDR on bytes `01 23 45 67`. Require `0x01234567` with E=1 and `0x67452301` with E=0. |

QEMU 11.1.2 on a two-core Cortex-A15 model provides an independent
encoding and data-order check. Both instruction sets loaded the expected
value when the secondary selected its data order with SETEND. Its
firmware CPU_ON loaded the little-endian value even when the caller used
SETEND BE. Arm DEN 0022D specifies caller endianness for the inherited
state. The QEMU result establishes the data-order control and the model's
firmware divergence.

On physical Intel Linux, the software-cluster regression failed before
the fix with saved PSTATE `0x20` instead of `0x220` for the big-endian
ARM caller. It passed after the fix for all four combinations of caller
instruction set and byte order, along both the direct and restored
paths. All 68 tests across the unfiltered `aarch64_cluster`,
`runtime_checkpoint_bundle`, `checkpoint_resume`, and
`checkpoint_cpus` targets passed. These runs qualify the software
cluster. The focused and integration logs have SHA-256 digests
`9d071376493059e00c0e2323db3221cdf3246d6ae027e93bc9b222b7c18f6fe9`
and `855ce17d7ca5bbbb27d4072caa8af2c151c21c9000c53a34cde8fe91126001b3`.

## Admission of a saved CPU_ON request

The software AArch64 cluster now checks the address of each pending
CPU_ON before preparing replacement CPUs or opening restore resources.
Guest CPU_ON and checkpoint restore share the alignment and mapped
instruction RAM check, including exclusion of the GIC distributor,
redistributor frames, and PL011 UART. Restore validates each requested PSTATE, including the target PE's saved
execution controls and the effective PSCI settings for AArch32 requests. The snapshot representation is unchanged.
Validation visits each pending request once and uses bounded storage per
request.

| Assumption | Falsification probe |
| --- | --- |
| A saved CPU_ON targets instruction RAM and a representable PSTATE. | Reload source-free bundles with an unmapped entry, a GIC or UART entry, and an invalid saved PSTATE. Require rejection before publication. |
| Invalid admission leaves live ownership intact. | Compare the directly observed CPU, shared controller, RAM, clock, and scheduler state after each failed restore. |
| Valid pending startup still reaches the target PE. | Reload the unmodified guest-produced file, run the coordinator, and require the secondary's register marker. |

The baseline published a file with a pending startup at
`0xfffffffffffffffc`. The corresponding fixed-source test rejected
each malformed record and continued the unmodified file on physical
Intel Linux using the software backend. The failing and passing log
digests are
`989288f5405262c507fbf0c67e36e021cf45a4a22ccd7adec37297e040760228`
and `327c35663724e8af44a9ddce2d1820af80c951f4e4abf66a9316edb4059e705a`.

The four unfiltered cluster and checkpoint integration targets passed
all 68 cases in the isolated startup-admission build. Its Cargo log
SHA-256 is
`373526b96d66c1a0d3a49896143e2f6c652501fc402646c1d0ccdcbab3ce864d`.
The integrated source also passed both startup regressions together.
The startup-admission and AArch32 endianness logs have SHA-256 digests
`3f5b9bcfaa494cea237cbcb629bbce0818f04724fc502d2f556009df1ba8c0d4`
and `ba73d0f0f2102b83769cdf9a1d7b5cd01441da2bc00cd5345f6f238eab808b40`.
All 68 cluster and checkpoint integration cases passed again with
both fixes in the same build. That Cargo log has SHA-256 digest
`8144a5d5d07df0a0e3706e7e2958204d5f9e24535a48342825475b7cd9c02b1b`.
