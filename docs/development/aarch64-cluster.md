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
quiescence, debugger/AP selection, deterministic clock/replay, native bounded
entries, native SMP and Intel Mac HVF qualification remain in the audit scope.
This change does not establish full C-STATE or C-SMP completion.

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
