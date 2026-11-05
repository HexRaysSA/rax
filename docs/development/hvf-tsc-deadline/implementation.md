# Pending native Intel deadline ownership and execution controls

The [audit candidate](../hvf-intel-candidate/candidate.patch) implements the
advertised Intel HVF deadline facility through the same LAPIC used by the PC
bus and checkpoint graph. A shared timer LVT owns its armed 64-bit deadline and
a bounded bitmap of raised vectors awaiting transfer into IRR. Native MSR
handlers never acquire the controller lock. Controller polling reads that
CPU's virtual TSC before acquiring the model; it cannot activate a pending
first-entry clock. Snapshot clones freeze values and restoration preserves
handles already attached to the destination CPU.

The instruction and mode semantics follow the [SDM and independent KVM controls](README.md).
The deadline uses unsigned TSC ordering, zero disarms, mode changes disarm,
initial-count writes are ignored in deadline mode, and current count reads zero.
Changing only the mask or vector retains an armed deadline. Masked expiry
follows the measured KVM profile: it clears the deadline and does not queue an
interrupt that reappears on later unmasking. This masked-expiry choice is not
presented as an additional guarantee from the SDM.

New native CPU records use `RAXHVI03`, retaining the prior bounded body and a
44-byte timer image: 4-byte LVT, 8-byte deadline and four 8-byte pending-vector
words, all little-endian. Earlier records remain readable as unarmed producers.
Complete execution frames add `RAXEXE11` only when a deadline or raised-vector
bitmap is nonempty. Its canonical nesting is deadline, optional EOI, base;
reverse and recursive nesting reject. An unarmed timer keeps the earlier
execution encoding. Complete bundle admission cross-checks the CPU and
controller copies before publication.

The original SDK-owner regression reads zero after writing `UINT64_MAX` in
deadline mode. The correction passes that regression, independent 1/2/4-CPU
private restore tests, and a halted-owner wake-request test. The wake test checks
that a pending event authorizes the next bounded native entry; SDK storage does
not execute an interrupt handler. SDM086 Volume 3C section 28.7.2 specifies that
a vectoring VM entry ends in the active state. Two initial test attempts used an
incorrect pre-entry activity expectation and then the wrong API-specific entry
counter; both are retained as harness failures, not successful qualification.

| Local check | Passed | Failed | Scope |
|---|---:|---:|---|
| Complete `hvf_intel_owner` | 65 | 0 | No ignored or filtered tests; SDK model |
| LAPIC library group | 129 | 0 | Count-down and deadline state, priority, IPI/EOI |
| Snapshot library group | 91 | 0 | Framing, graph admission and restoration |
| Intel context library group | 12 | 0 | Old/new records, malformed payloads |
| Runtime LAPIC library group | 15 | 0 | Controller/bus/checkpoint ownership |
| Complete Python tooling suite | 31 | 0 | Prepared artifacts, candidate admission and SDK observations |

Clippy passes for the library and affected Intel owner/control targets. The
expanded consumer compiles, links, signs and passes strict signature validation
against the same corrected library on Apple Silicon. Its temporary compiler
directory was removed. The unfiltered current Apple Silicon library run remains
in progress; the group checks above are not a substitute for its terminal result.

The [native consumer](../../../tools/hvf/intel_mmio_native_guest.rs) now registers
146 cases. Existing RAM/MMIO/PAT/reserved-MSR cases retain identifiers 0-129.
The added guest programs execute CPL0 MSRs, ordered xAPIC MMIO and actual IRQ
handlers, with this inventory:

| Case IDs | Controls |
|---|---|
| 130-140 | Eleven mode/readback/disarm/count/mask/expiry scenarios matching the independent control partitions |
| 141-142 | Armed deadlines restored into fresh CPU/VM owners |
| 143 | Timer IRQ wakes HLT; the guest handler increments RAM and issues EOI |
| 144 | The same wakeup after private CPU restore and a frozen controller clone |
| 145 | After WRMSR TSC, ordered guest RDTSC/RDMSR/RDTSC samples share one counter domain |

Case 144 transports the controller through a value clone; it is not a complete
serialized VM-file test. Each program must reach its exact HLT PC and marker.
Host servicing holds no controller lock across a CPU callback. A partial or
reordered observation stream cannot satisfy the driver's exact 146-case count.
These 16 added cases have not executed on native Intel yet.

The preceding [run 42006230493](https://github.com/HexRaysSA/rax/actions/runs/42006230493)
passes all 130 existing native cases, including fresh-owner private PAT restore
and guest reserved-MSR faults. It uses the same engine source as this local
deadline qualification, but its consumer lacks the 16 new programs. That result
proves the repaired native checkpoint frontier; it does not prove deadline
expiry, interrupt delivery or TSC-domain alignment. See the
[implementation qualification](implementation-qualification.json) for exact
source identities and limits.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| A1 | CPU and controller share exactly one timer owner | MSR/MMIO coherence and restore | Independent CPU arms, frozen clones, restored handles and CPU/controller graph mismatch rejection | Confirmed in model/library checks |
| A2 | Masked expiry follows the selected measured KVM profile | Mask transition semantics | Independent KVM repetitions; native RAX scenarios 9/10 | KVM reference confirmed; native RAX pending |
| A3 | SDK virtual TSC sampling agrees with guest TSC after rebasing | Deadline timing | Native case 145; ordered counter samples must enclose the emulated MSR read | Native verification pending |

High-impact remaining gates: complete unfiltered library execution and the
146-case native run. Native multi-CPU startup/scheduling, the complete KVM
producer and the remaining A32-FP/MMIO profiles remain separate parent-goal
requirements. Medium impact: the hosted Intel runner is itself a hypervisor
guest; no bare-metal qualification follows. Timer operations use constant
storage and at most 256 vector transfers per poll. Execution framing uses time
and storage linear in the CPU count plus its existing inner frame.
