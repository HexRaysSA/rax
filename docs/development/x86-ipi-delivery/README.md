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
requires a complete bundle. A successful legacy restore
discards any selected message owned by the old machine.

For N local APICs, resolution uses O(N) time and O(N) space. Acknowledgment is
O(1) per successful target. The wrapper adds 15 header bytes, up to 32 bytes
of encoded request, and up to 255 one-byte destination slots.

| ID | Assumption and dependent result | Falsification probe | Outcome |
|---|---|---|---|
| I1 | The coordinator retains sole ownership of delivery between vCPU turns. A returned backend rejection before application leaves that target outstanding. | Inject a one-shot error at CPU 2 after CPU 1 succeeds. Check the call sequence, final CS state and SIPI FIFO. | Confirmed by the modeled four-vCPU test. |
| I2 | A previously selected logical target remains a destination even when its LAPIC configuration changes. | Change CPU 3's logical ID before saving and give CPU 1 a new pending vector. Load the file into a fresh VM, verify CPU 3 still starts and CPU 1 retains the vector. | Confirmed using software x86 CPUs and a single fault-injected INIT. |
| I3 | The pending record can coexist with deadline and EOI wrappers without accepting malformed framing. | Round-trip all wrappers and queued SIPI together. Reject truncation, trailers, excessive sizes, repeated or out-of-range slots and inverted wrappers. | Confirmed by the execution codec tests. |

The four-CPU file test injects one error through a model. Real software CPUs
receive the successful INIT and SIPI operations. Native backend setter errors,
production HVF worker coordination, and interrupt delivery across the full
set of configured machines require their own evidence. This component
addresses the x86 coordinator and its checkpoint state under C-SMP and C-STATE.
[Qualification](qualification.json)
