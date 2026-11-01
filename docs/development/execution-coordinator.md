# Execution coordinator and checkpoint state

The software VMM selects online CPUs in ID order, with a rotating cursor. Each
turn admits at most 1,000 retired instructions or packets. A synchronous exit,
nonretiring state transition, or error returns control earlier. Device I/O is
completed against the CPU that produced the exit. Every software instruction
boundary drains outgoing interprocessor requests before another instruction is
entered. Each x86 CPU accesses its own shared local APIC. All CPUs receive the
same PCI bridge when PCI devices are configured.

The BSP begins online. x86 APs wait for startup. INIT resets architectural
control flow and the local APIC, preserving the FP/vector, XCR0, PKRU, timestamp,
and MSR state specified for INIT. SIPI installs the startup CS selector/base and
zero IP; a second SIPI does not restart an online CPU. The coordinator resolves
physical, flat logical, cluster logical, and shorthand destinations. Its modeled
lowest-priority selection chooses the online, enabled recipient with the lowest
processor priority, then APIC ID. The controller retains a FIFO of outgoing
requests. Accepted maskable interrupts transfer IRR to ISR; guest EOI clears ISR.

Native bounded execution, additional ARM profiles and RISC-V SBI startup, architectural topology
enumeration, complete backend/private/in-flight CPU state, and full writer
quiescence remain full-audit acceptance requirements. The current coordinator
prototype and its software tests do not establish those requirements.
The software coordinator uses instruction stepping. AArch64 now admits hot
instructions through a separate bounded native cache: each entry returns after
one original instruction, including a self-branch. Explicit access recording
retains interpretation and its exact observation stream. See
[AArch64 bounded native execution](a64-bounded-native/README.md) for native-entry,
independent physical AArch64, and 2/4-CPU checkpoint tests. Hardware backend
entries and other guest ISA native tiers remain separate SMP requirements.
Public software AArch64 system steps also use this instruction-sized entry.
The adapter publishes retirement deltas before exits, preserves separately saved
observation-counter phase, and bounds ordinary batches by their attempt count.
See [AArch64 public system entry](a64-system-entry/README.md) for the contract,
parent failures and qualification boundaries.
Cold A64 and mixed ARM/Thumb private retirement counters use explicit wrapping
addition, matching the native and budget contracts across restored maxima.
See [private retirement counters](a64-retirement-counters/README.md) for
instruction/cycle boundary, tagged-record, observation-phase and clock tests.
Software AArch64 system budgets also retain completed retirement when host
firmware completion returns an error. The original error is preserved; default
charged-attempt meters keep their existing nonretiring fault policy. See
[retirement before completion errors](retirement-errors/README.md) for the actual
HVC/SMC reproduction, internal policy and remaining transaction boundaries.

Debugger commands are serviced before guest interrupt injection. A stopped CPU
retains its registers, stack, and pending interrupt until execution resumes.
Internal breakpoints apply before attempted instructions; a halted CPU does not
attempt the instruction at its next RIP. Host single-step completion follows
PIO/MMIO completion, including input-register writeback, and can stop after a
retired HLT. Automatic checkpoints also follow device completion and outgoing
IPI routing. These host controls do not change guest RFLAGS.TF. The existing GDB
stub still selects BSP registers; AP thread selection remains an SMP consumer
requirement. Other CPUs may execute while the BSP actively steps, as permitted
by GDB all-stop mode.

Direct x86 attempts distinguish inline delivered faults from successful traps.
A fault changes handler state without retiring the faulting instruction. ICEBP
and successful software interrupts retire once. A fault evaluating a software
interrupt gate cancels that retirement and saves the restart address. The
attempt-local marker is overwritten before each direct attempt and adds O(1)
time and space. The existing host-reported `GuestEvent` error/nonretirement
contract remains unchanged.

## Ownership

| State or operation | Owner |
| --- | --- |
| Online/startup states, selection cursor, aggregate retirements | `src/vm/runtime/coordinator.rs` |
| Host console, device servicing, selected-CPU exit completion | `src/vm/runtime/execution.rs` |
| x86 INIT register/private-state transition | `src/isa/x86_64/cpu_startup.rs` |
| Direct x86 attempts and retirement-aware fault delivery | `src/isa/x86_64/cpu_step.rs` |
| Local APIC registers and outgoing FIFO | `src/devices/lapic.rs` |
| Local APIC timer-age capture/restore | `src/devices/lapic/checkpoint.rs` |
| Required execution checkpoint payload | `src/vm/snapshot/execution.rs` |

Controller locks are released before interrupt or INIT/SIPI CPU callbacks.
Snapshot restoration still requires the remaining full checkpoint transaction
and backend ownership work described in the audit ledger.

## Required execution checkpoint section

`SnapshotBundle` writes required section kind 13, schema 1. The base version-8
wire and public base `Snapshot` shape remain stable. The new section retains the
selection cursor, aggregate retired count, online states, every local APIC,
queued outgoing IPIs, and active timer ages. A loader must retain this section
through restoration. Base extraction rejects an unconsumed required extension.

All integers are little-endian. There is no implicit padding.

| Header field | Width in bytes |
| --- | ---: |
| Tag `RAXEXE01` | 8 |
| CPU count | 4 |
| Next selection cursor | 4 |
| Aggregate retired units, modulo 2^64 | 8 |

The following record repeats once per CPU in ID order:

| Record field | Width in bytes |
| --- | ---: |
| Online flag, 0 or 1 | 1 |
| Timer armed flag, 0 or 1 | 1 |
| Timer age in nanoseconds; zero when unarmed | 16 |
| Encoded controller-register length | 4 |
| Outgoing IPI count | 4 |
| Controller registers, fixed-integer Bincode encoding | Explicit length |
| Each IPI: one-byte length followed by typed Bincode payload | Explicit length |

Limits are 255 CPUs, 4,096 bytes per controller, 1,048,576 queued IPIs per
controller, 32 bytes per encoded IPI, and 64 MiB for the section. Decoding admits
counts, flags, lengths, and remaining bytes before reserving event storage, and
rejects truncation or trailing data. Execution state requires the complete CPU
set; the BSP controller must agree with the base checkpoint.

Timer ages use unsigned 128-bit nanoseconds and a fresh monotonic anchor.
Restoration rebases the anchor at publication, excluding load time from the
captured age. The software LAPIC uses its existing modeled 1 GHz source and
configured divisor. Its elapsed-time products use 128-bit arithmetic, and a
periodic expiry retains the fractional period. Retirement-clock integration and
TSC-deadline timer behavior remain separate acceptance requirements.

## Evidence and assumptions

The focused regressions call `Vmm::run()` with 1, 2, and 4 configured CPUs. The
guest sends INIT/SIPI and records per-CPU RAM progress. A bounded BSP loop reaches
shutdown even when APs do not execute. Checkpoint cases save and load a real file,
construct a new runtime through the public resume API, and compare subsequent
RAM and CPU state against uninterrupted execution. AP counter loops require
execution after restoration. Additional cases cover halted AP wakeup, guest
EOI/IRET, destination routing, duplicate SIPI, INIT-preserved state, FIFO order,
timer overflow, and malformed execution records.
Additional runtime regressions cover debugger input/output/HLT completion,
breakpoints at halted boundaries, stopped-CPU IRQ conservation, and fault/trap
retirement. The registered `x86_fault_retirement` target also covers selected
fault classes, successful traps, faulted software gates, retirement-clock
publication, out-of-step injection, host error reporting, and fetch failure.
Two library tests cover counter wraparound and marker reset.

| Assumption | Falsification probe | Evidence status |
| --- | --- | --- |
| The old execution loop omits AP progress | Run the actual VMM guest with 1/2/4 CPUs | Observed baseline: one pass, two AP-progress failures |
| Startup and interrupt expectations have an independent reference | Encode with LLVM 23 and execute QEMU 11.1.2 TCG guests | Retained 1/2/4-CPU startup and halted-AP interrupt witnesses |
| Protected-mode AP startup reaches the owned VMM CPUs | Run the actual VMM startup and resume cases | Five focused tests passed before the expanded cases |
| All independent backend/device writers can be quiesced | Inventory every constructor/writer and test capture/late failure | Remaining full checkpoint requirement |
| A physical Intel Mac is available | Verify host CPU, HVF, and nonempty native guest runs | Unknown |

The task retains raw inputs, binaries, command output, source hashes, tool
versions, and QEMU output under `rax-audit-work/four-findings-coordinator`.
Complete affected test binaries and broader gates are required before this
semantic group is committed.

## Complexity and remaining boundaries

For C configured CPUs, K instruction boundaries in a turn, and Q outgoing IPIs,
selection and routing take O(K*C + Q*C) time. Controller storage is O(C + Q).
Execution-section encoding and decoding take O(B + C + Q) time and space for B
encoded bytes, subject to the explicit format limits.

| Impact | Remaining boundary |
| --- | --- |
| High | Native entry must yield or be interrupted without starving another CPU |
| High | Full checkpoint completion requires all private/in-flight state and transactional writer quiescence |
| High | Physical Intel HVF execution remains a required runtime validation gate |
| Medium | External memory/device writers require coordination with the VMM owner |

Primary architectural expectations come from Intel SDM revision 086, Volume 3A,
Chapter 10 (MP initialization), section 11.1 and Table 11-1 (INIT-preserved and
reset state), and sections 12.4.7 and 12.6 (local APIC state and IPI delivery).
The pinned local source is
`docs/specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf`.
Fault/trap classification and restart semantics use Volume 3A sections 7.5 and
7.6 of the same revision. Debugger stop semantics use the GNU GDB manual,
[All-Stop Mode](https://sourceware.org/gdb/current/onlinedocs/gdb.html/All_002dStop-Mode.html).


## Software AArch64 platform

The configured software AArch64 cluster now shares one GIC, binds ICC/IRQ/timer
state per PE, and routes asynchronous PSCI CPU_ON/CPU_OFF through the same
coordinator. Its FDT describes each affinity and the actual redistributor regions.
The execution extension uses RAXEXE02 when shared ARM power/GIC state is present;
the bounded platform payload follows the existing CPU/controller records as a
little-endian u32 byte length and codec body. Other producers retain RAXEXE01.
See [AArch64 cluster ownership](aarch64-cluster.md) for admission, implementation
limits and actual 1/2/4-CPU validation. Full native scheduling and CPU/bridge
private-state closure remain separate audit requirements.

Software ARM [event delivery](a64-events/README.md) now distinguishes SEV fanout
from SEVL and consumes latches at CPU instruction boundaries. Cohort restoration
publishes saved latch values only after admission and retains peer bindings.
This does not extend the coordinator's existing spurious-wakeup policy into a
complete WFE trap or timer event-stream model.

Intel HVF now exposes an optional finite host-slice contract. The coordinator
selects it for opted-in non-stepping CPUs, preserving guest exit and
retirement boundaries. See [Intel native host scheduling](hvf-native-scheduling/README.md)
for separate coordinator/SDK-model evidence and physical/native-profile limits.
KVM and native Arm retain their existing entry contract in this component.
