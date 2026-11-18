# Software AArch64 PSCI request acknowledgement

The software cluster drained its power queue before the coordinator installed
secondary CPU state. In the baseline probe, reading the queue returned two
CPU_ON requests. After a rejected entry installation, the next observation
returned an empty queue. A separate probe executed CPU_OFF and immediately
requested CPU_ON for the same secondary. The original backend reported OFF,
accepted the restart, and queued contradictory Off and Start requests.

Return a snapshot of the request queue. The coordinator acknowledges a start
after installing the entry state and acknowledges a stop after removing the
CPU from scheduling. A successful acknowledgement removes exactly the
matching request. The stop parks the CPU immediately, while firmware treats
it as ON until acknowledgement. A peer therefore receives ALREADY_ON during
that interval. Sections 5.7.1 and 6.6 of the Arm PSCI specification define
the status values and describe the CPU_ON/CPU_OFF transition race.
[Arm DEN0022D](../../specifications/arm/psci-den0022.pdf)

The checkpoint represents an in-flight stop with the existing Off state and
pending Off request. The coordinator bit may reflect either side of the
scheduling removal until acknowledgement. A pending start still requires an
offline target and its retained entry, context, and PSTATE. Old records that
already lost a pending entry contain insufficient information to recover it.

For a cohort of at most 255 CPUs, observation and each acknowledgement take
O(n) time. The observed request copy takes O(n) space and acknowledgement uses
O(1) additional space. The VMM's exclusive scheduler owns application and
acknowledgement. The cluster lock protects each firmware observation and
queue update. The lock is released before CPU callbacks.

| ID | Assumption and dependent result | Falsification probe | Status |
|---|---|---|---|
| P1 | The existing queue can retain the transition until publication. | Inject an invalid entry PSTATE, observe twice, then apply the first and second queued starts independently. Compare their exact entry states and remaining queue. | Confirmed by both integration-test modes. |
| P2 | Stop acknowledgement marks the firmware transition to OFF. | Call AFFINITY_INFO and CPU_ON from the BSP while the secondary is parked. After acknowledgement, issue a new CPU_ON and check the installed context. | Confirmed by both integration-test modes. |
| P3 | The existing wire layout represents both sides of scheduler removal. | Save and reload the same in-flight start/stop cohort with the stop target's online bit both set and cleared. Run the real coordinator and check that only the newly started secondary reaches its marker. | Confirmed in the AArch64 VMM library module. |

Sibling native and x86 interrupt-delivery paths retain their separate
qualification. Complete private/backend restore and configured SMP across all
platform profiles remain open.

## Validation

The two focused baseline regressions failed on the pre-fix library. The
complete AArch64 cluster integration target passed all 32 cases with JIT
enabled and all 32 with JIT disabled. The selected AArch64 VMM and backend
library modules passed 37 and 23 tests, respectively. These library runs used
module filters. [Qualification receipt](qualification.json)
