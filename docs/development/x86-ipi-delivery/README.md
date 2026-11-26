# Retry and checkpoint of xAPIC IPI delivery

The coordinator can receive a broadcast INIT followed by SIPI. If a target
rejects INIT, the previous implementation had already removed it from the
originating LAPIC FIFO. On retry, SIPI reached only the CPUs that had been
initialized before the failure. A fault-injected four-vCPU regression
observed INIT attempts from the coordinator to CPU 1 and CPU 2, with no further
attempts. The corrected sequence is CPU 1, CPU 2, CPU 2, CPU 3. All three
secondary CPUs accept SIPI vector 9 and reach CS selector `0x900`, CS base
`0x9000`, and RIP 0.

The coordinator owns one selected message until it finishes. It resolves the
destinations once, acknowledges each successful destination and keeps the
remaining destinations ahead of the original LAPIC FIFO. This matters when
INIT resets the destination's logical APIC configuration. If resolution itself
fails, the request remains available for selection on retry. Unsupported
interprocessor SMI still returns its existing terminal error.

A complete `.rxc` file stores the selected message separately from queued
LAPIC messages. The required `RAXEXE12` wrapper carries the source slot,
encoded request and ordered remaining target slots. A zero remaining count
identifies a request that has yet to resolve its destinations. Existing
quiescent frames keep their original bytes and restore with no selected
message. Older readers reject the required extension. Capture at this frontier
requires a complete bundle. Restore at this frontier requires a bundle with
execution state. A base snapshot or an extended bundle without a coordinator
record would drop the remaining destinations while leaving effects of the
delivery in the target. Restore rejects these projections before publishing
CPU, RAM or device state. The same legacy input can restore once the selected
IPI and queued SIPI have been dispatched.

The same admission rule applies before the coordinator selects a message.
The base format has a single historical BSP IPI slot. It cannot represent
the coordinator-owned IPI FIFO or pending level-EOI broadcasts. Legacy
capture and restore without execution state check every local APIC in CPU
order and hold those locks through publication. An incoming CPU set
alone does not carry those controller queues. Complete checkpoints carry
both queues in their execution record and keep their base projection
free of transient entries. The historical single-slot format remains
readable. Admission scans N local APICs in O(N) time and holds O(N) lock
guards through publication.
[Intel SDM, Volume 3A, APIC](https://cdrdv2-public.intel.com/835754/253668-sdm-vol-3a.pdf)

For N local APICs, resolution uses O(N) time and O(N) space. Acknowledgment is
O(1) per successful target. The wrapper adds 15 header bytes, up to 32 bytes
of encoded request, and up to 255 one-byte destination slots.

| ID | Assumption and dependent result | Falsification probe | Outcome |
|---|---|---|---|
| I1 | The coordinator retains sole ownership of delivery between vCPU turns. A returned backend rejection before application leaves that target outstanding. | Inject a one-shot error at CPU 2 after CPU 1 succeeds. Check the call sequence, final CS state and SIPI FIFO. | Confirmed by the modeled four-vCPU test. |
| I2 | A previously selected logical target remains a destination even when its LAPIC configuration changes. | Change CPU 3's logical ID before saving and give CPU 1 a new pending vector. Load the file into a fresh VM, verify CPU 3 still starts and CPU 1 retains the vector. | Confirmed using software x86 CPUs and a single fault-injected INIT. |
| I3 | The pending record can coexist with deadline and EOI wrappers without accepting malformed framing. | Round-trip all wrappers and queued SIPI together. Reject truncation, trailers, excessive sizes, repeated or out-of-range slots and inverted wrappers. | Confirmed by the execution codec tests. |
| I4 | Legacy restore keeps peer state that can already reflect partial delivery. | Attempt base and public CPU set restore after CPU 1 accepts INIT and CPU 2 rejects it. Verify the selected targets, queued SIPI, CPUs, RAM and UART survive rejection. Retry after delivery completes. | Four software CPUs with a fault injected at CPU 2. |
| I5 | Before selection, deferred controller work resides in the originating LAPIC. | Queue a fixed IPI or level EOI on CPU 0 and CPU 1. Attempt capture, base restore and CPU-set restore. Require the queues, CPU state, scheduler, RAM and UART to survive. Route the requests, then repeat the legacy operations. | Two software vCPUs exercise both origins and both queue types. |

The parent accepted the queued BSP IPI and secondary EOI captures. The
corrected build passed 21 focused tests, including full-file continuation,
base-file round-trip of the historical slot and the execution codecs.
Strict library Clippy and x86-64 macOS HVF and Linux KVM cross-checks passed.
The parent log SHA-256 is
`e026b156d9f8cfbdb6272512ca5f36a00cdb3eb85725d6a71f2435800a546143`.
The corrected log SHA-256 is
`d6690d39eb5057f904db1bed4f5e88acbe2860a33dd0a5bd10e885d78f6ccaa5`.

The four-CPU file test injects one error through a model. Real software CPUs
receive the successful INIT and SIPI operations. Native backend setter errors,
production HVF worker coordination, and interrupt delivery across the full
set of configured machines require their own evidence. This component
addresses the x86 coordinator and its checkpoint state under C-SMP and C-STATE.
[Qualification](qualification.json)
