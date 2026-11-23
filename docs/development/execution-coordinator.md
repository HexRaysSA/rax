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
IPI routing. These host controls preserve guest RFLAGS.TF. On software x86,
GDB enumerates application CPUs, selects their registers, and can step a
selected online CPU. When restoring prepared CPUs, the VMM rebinds the
current session's controls before publication. Compound resume requests may
run peer CPUs while the selected CPU steps.
[Software SMP debugger controls](software-smp-debugger/README.md)

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

## Native worker errors

When posting or collecting a native entry fails, the coordinator still joins
every posted worker. `Vmm::run` dispatches the exits returned by successful
peers through the normal round handler before returning the original worker
error. The ordinary terminal shutdown policy applies. A secondary dispatch
error is logged. Coordinator overhead is O(C) for C configured vCPUs, with
the existing round buffers.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| Work already collected from successful peers requires completion. | High | Force a post failure at CPU 2 in a four-vCPU `Vmm::run`. Require ordered input completions from CPUs 0 and 1. The predecessor collected their exits and completed neither. |
| A collection failure can leave valid exits from both earlier and later peers. | High | Return a collection error at CPU 2. Require collection of all four submissions, input completions from CPUs 0, 1, and 3, and the original error. |
| This evidence covers runtime orchestration. | Medium | Inject worker failures through a scripted vCPU adapter. Native SDK faults and device-dispatch failures have separate backend and endpoint boundaries. |

## Device completion within a round

A vCPU that reports failed entry has no device transaction to service. If
the shared backend admits a stopped boundary, the VMM still dispatches the
collected peer exits in order. It reports the original entry reason before
any subsequent guest entry.

A native CPU may fail to accept an I/O reply after the device operation and
its interrupt update have succeeded. The backend retains its incomplete CPU
transaction. The VMM verifies that the shared backend admits a stopped
boundary and continues dispatching the collected peers in order. It returns
the first CPU-local error when worker collection succeeds. INIT/SIPI routing
and end-of-round clock polling wait for the next execution boundary. A device
or interrupt publication error, a shared-owner failure, or a terminal exit
ends dispatch. Each collected exit gets at most one dispatch attempt within
the round. The CPU owner retains any staged reply for recovery.

Walking the exits takes O(C) coordinator work for C vCPUs. Each CPU-local
failure adds one stopped-owner check, which scans C CPU owners on KVM.
For F such failures, KVM dispatch therefore takes O(C + FC) work. Error
tracking uses O(1) auxiliary space.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| Failed entry leaves the healthy peer exits serviceable. | High | Report a failed entry on CPU 0 or 2 of a four-CPU round. Require the original reason, three serial replies in order, and a fourth byte still queued. |
| Device state was fully published before a CPU reply error. | High | Four CPUs read one serial FIFO. Inject the failure on CPU 1 and require all four replies in order and the fifth byte still queued. The predecessor dispatched only CPUs 0 and 1. |
| An endpoint service failure ends dispatch. | High | Change CPU 1's PIO width to zero. The request is rejected, CPUs 2 and 3 consume no bytes, and the FIFO head stays at CPU 1's original byte. |
| The native ARM64 owner can retain and retry the consumed input. | High | On two and four physical HVF vCPUs, fail CPU 0's register write after a PL011 read. Compare the staged byte and error in the private record, peer destination registers, and the remaining FIFO byte after retry. |

The signed Apple M4 Max run passed both parallel-round tests, including the
two- and four-vCPU injected MMIO reply failure cases. The host reported
`kern.hv_vmm_present=0`. All five native terminal-I/O tests also passed,
including both shutdown dispatch orders and file continuation. The complete
scripted scheduling module passed 15 tests. Its failed-entry regression uses
`Vmm::run` with an injected exit. The preceding code completed zero of three
collected peer reads when CPU 0 reported failed entry.

## Native Intel HVF startup and file continuation

The full 952-case standalone MMIO run exercised the production VMM with one,
two, and four native vCPUs. It verified each AP's startup flag, CPUID identity,
and two delivered fixed IPIs. A second guest phase was placed at the saved BSP
PC before capture. The probe saved the bundle, discarded the source VM and
kernel, rebuilt native CPU owners from the file, and confirmed equality of
their public CPU records before entering the guest.

| vCPUs | Cold IPI counts by CPU ID | Counts after file continuation |
| --- | --- | --- |
| 1 | `[0]` | `[0]` |
| 2 | `[0, 2]` | `[0, 4]` |
| 4 | `[0, 2, 2, 2]` | `[0, 4, 4, 4]` |

Each run reached the corresponding BSP success marker, and each restored AP
handled two new guest-generated IPIs and acknowledged them with EOI. The
consumer ran in an untranslated Intel process on virtualized macOS 15.7.9
with SDK 15.5. Bare-metal Intel macOS and broader IRQ/control profiles remain
unverified.
[Runtime observations and signed build provenance](hvf-mmio-exit-address/README.md#standalone-mmio-requalification)

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

## Software x86 NMI blocking and checkpoint continuation

A successful NMI delivery records a block on the selected software vCPU. A
later request returns false while the block is set, so the local APIC keeps
its pending NMI. IRET releases the block before reading the return frame.
This also allows pending NMIs after a faulting return. A host register edit
preserves the block, while RESET and INIT clear it. Intel specifies the
handler and faulting-IRET behavior in SDM revision 086, Volume 3A, section
7.7.1. [Pinned Intel SDM provenance](../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.provenance.md)

The private context emits `RAXX8607` or `RAXX8608` when the CPU is blocked.
Both reuse the existing `RAXX8605` body with its user-debug-shadow flag.
`RAXX8608` also requires the I/O APIC policy and matching PC controller
image. Existing tags and base projections import as unblocked. The LAPIC
record already contains the queued NMI. A complete VMM file retains both
owners alongside the handler's RAM and register state. The latch and its
admission check cost O(1) space and time per vCPU.

| Assumption | Falsification probe |
| --- | --- |
| Delivery establishes the block before the next event can enter. | Inject again after a handler NOP and compare RIP and RSP. |
| IRET releases the block even when the stack is inaccessible. | Fault the first IRET pop and verify the next NMI is admitted. |
| A complete file retains the handler block and the selected controller request independently. | Destroy the source VM, load files with 1, 2 and 4 configured vCPUs, offer the pending NMI before IRET, and verify both handler entries save the original guest PC. |

Both direct regressions and the detached VMM regression exposed the nested
delivery on the parent. On Apple Silicon, the complete library and eight
integration binaries passed 41,870 tests with eight ignored and none failed
or filtered. The feature-minimal library compile check passed. The software
witness covers retired-clock scheduling. Full native SMP interrupt ordering
and bare-metal Intel HVF qualification remain open.

```sh
cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit,debug \
  --lib --test x86_64 --test controller_checkpoint --test runtime_checkpoint_bundle \
  --test checkpoint_cpus --test checkpoint_resume --test restore_admission \
  --test x86_fault_retirement --test retirement_budget
cargo +stable check --locked --no-default-features --lib
```

## x86 PC interrupt arbitration

The coordinator offers pending controller events to the selected CPU. The
software wall-clock path offers them at turn entry, the retired clock at
each instruction boundary, and the native path before guest entry. An
eligible NMI takes precedence over a maskable IRQ. The bootstrap CPU then
considers the PIC before fixed local APIC vectors. A blocked NMI stays
pending while an eligible maskable IRQ may enter. Once a CPU accepts an
event, the controllers hold other requests for a later boundary. Intel SDM
revision 086, Volume 3A, section 7.9 and Table 7-2 specify the priority.
[Pinned Intel SDM provenance](../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.provenance.md)

The PIT still publishes edges to its controller routes. The selected local
APIC latches a timer expiration even if another event entered first. Event
arbitration takes O(1) time and space, excluding existing controller routing
across the configured vCPUs.

| ID | Assumption and basis | Dependent result | Stress test and falsification probe |
| --- | --- | --- | --- |
| A1 | The Intel priority applies when both events are eligible at the same boundary. | NMI is the single event delivered. | Use an NMI trap gate with IF set. The first handler instruction ends the VM. Require one 12-byte frame (3 x 4-byte slots) containing the interrupted guest EIP, plus the pending maskable vectors. |
| A2 | A shared controller queue can hold an event until its CPU is selected. | An off-turn CPU can take a single event before it executes. | Run the other CPU first in wall mode. Check the target's first handler and frame. Exercise both bootstrap and secondary CPU targets in both clock modes. |
| A3 | The software CPU returns false when NMI delivery is blocked. | The controller retains the NMI while an eligible PIC IRQ can enter. | Latch a second NMI while the first handler still has IF set. Require PIC acknowledgment and a retained NMI. |

The parent delivered two 12-byte frames before the bootstrap CPU
executed the NMI handler. The secondary CPU also received two frames
and entered the fixed IRQ handler first. Both tests reproduced on the
wall clock and the blocked-NMI control passed. The corrected regressions
passed on both wall and retired clocks. The native scheduling fixture
passed all eight cases, including selected CPU window ownership.

The owning portable validation command uses the full library target and
the x86, controller, timing, and checkpoint integration targets. The library
passed 13,214 tests with 5 ignored. The nine integration targets passed
28,670 tests with 3 ignored. All ten targets reported zero failures and
zero filtered cases. The feature-minimal library check, Linux x86-64 KVM
cross-check, and Intel macOS HVF consumer cross-link passed.

```sh
cargo test --locked --no-default-features --features x86_64-suite,smir-jit,debug \
    --no-fail-fast --lib --test x86_64 --test controller_checkpoint \
    --test vm_timing --test retired_clock --test checkpoint_clock \
    --test checkpoint_resume --test runtime_checkpoint_bundle \
    --test checkpoint_cpus --test retirement_budget
```

| Impact | Evidence boundary |
| --- | --- |
| High | The native scheduling fixture checks arbitration at the guest-entry API. Physical Intel HVF qualification of this scheduling path remains open. |
| Medium | Wall-clock software checks for controller events at turns. Retired-clock software checks at instruction boundaries. |

## Software VMM secondary execution replay

Five live software-VMM controls ran on physical Intel Linux using
revision `8be5c610f84c67b90aa893d2e1d3687321d27240` plus the AArch32
CPU_ON endianness change. The tests enter the production run loop and
inspect guest effects from each configured CPU.

| Guest | vCPU counts exercised | Required guest effect |
| --- | --- | --- |
| x86-64 | 1, 2, 4 | The BSP sets its RAM flag. Each application processor sets its own flag after guest INIT/SIPI. Unconfigured flags stay clear. |
| RV64 | 2, 4 | Each hart retires instructions, publishes a distinct register value, and contributes one increment to the shared RAM counter. |

All five controls passed. The test executable SHA-256 is
`ab91f85913c9031ddaa8195e633d475792fae28e025a5c35f0cb351371f998df`.
The combined log SHA-256 is
`0754642c50baed583c0ba4679e93fa64c5f8c3e3c5f3a86cc6f66dbc1b2330fa`.
The same build also passed the existing three-PE AArch64 continuation
case. The restored VM runs its pending PSCI start/stop through the
coordinator, leaves the stopped PE parked, and obtains the expected
register marker from the newly started secondary.
[Software AArch64 cluster results](aarch64-cluster.md)
