# PC device checkpoint state

The PC execution extension carries the nine mutable machine-owned devices that
were omitted from the stable PIC/PIT/UART/LAPIC projection: RTC, fw_cfg, IOAPIC,
DMA, system control, i8042, two IDE channels and FDC. The VMM retains the same
Arc owners registered behind their PIO/MMIO aliases. Restoration replaces model
fields under those owners and does not replay register writes or host output.

The additive Machine ownership and load hooks preserve existing implementers.
The VMM uses an explicit per-machine IDE binding during ISO boot. The historical
setup_devices/load_kernel pair retains its legacy global binding; this group
does not qualify that two-call API for concurrent use.

## Wire and resource admission

RAXEXE04 extends the execution record with a length-prefixed PC control image.
The current control tag is RAXPCD03. RAXEXE01/02/03 remain readable. Complete PC
execution restoration rejects an older execution image without PC state.
Historical base-only represented state remains a separate API and does not
acquire missing device state.

Small state uses the strict bounded legacy codec. The PC control image is limited
to 62,914,560 bytes within the 67,108,864-byte execution section. Dynamic collection
counts are admitted before allocation. Resource keys bind full owned disk, PIO,
ATAPI and floppy bytes; these bytes do not consume the small control budget.
The existing resource/RAM/media aggregate and decoder history bounds apply. A
resource dictionary requires a public CPU table and a preceding backend or PC
ownership record. Native private graph requirements are unchanged.
Kind 1 remains boot CD media, shared immutably. Kind 2 identifies PC snapshot byte
buffers and is copied into independently mutable target owners before publication.
Deduplication includes kind, size and SHA-256; identical content with a different
interpretation remains a distinct key.

Capture locks PCI, then the nine PC devices in documented inventory order, then
shared platform/legacy controllers, backend exclusion and physical RAM. Restore
admits all controls and resources offside, acquires the same owners and publishes
PC fields only after the inner guest/backend operation succeeds. The RAM/backend
publication guards outlive the device wrappers. No general claim is made for
uncontrolled external memory aliases or unsupported backend transactions.

For device bytes B, control bytes C, pending entries Q and resource count R,
preparation uses O(B+C+Q) work/storage plus O(log R) resource lookup per fixed
binding. The nine-device lock inventory has constant size. Media are copied
before publication; immutable CD Arcs are retained without mutating source owners.

## Assumptions and falsification

| ID | Assumption | Stress/falsification probe | Status |
| --- | --- | --- | --- |
| PC-1 | Complete resume recovers modeled device state. | Mutate CMOS, FW cursor and IOAPIC after capture; restore same VM and actual file into a fresh VM. Retained target/default values falsify it. | Confirmed within the recorded model and host scope. |
| PC-2 | Aliased windows refer to one logical target device. | Continue DMA byte latch, keyboard command and floppy parameters through their aliases; check Arc identity and failed/poisoned publication. Divergence or prefix mutation falsifies it. | Confirmed within the recorded model and host scope. |
| PC-3 | Media and transfer cursors are independent of source paths and mutable owners. | Resume partial ATA/ATAPI/floppy transfers; empty/missing CDs, shared immutable CDs, large buffers, separate writable disks and deleted source kernel. Cross-owner mutation or missing continuation falsifies it. | Confirmed within the recorded model and host scope. |

The resource framing also assumes that a public CPU table and a valid PC owner
can bind device resources when no opaque CPU payload exists (PC-4). Its stress
probe saves and loads that controlled producer, rejects orphan/reordered
resources, and preserves native private-context prerequisites. Acceptance of a
missing owner or failure of a valid owned dictionary falsifies this assumption.
See the complete register in [qualification.json](qualification.json).

## Evidence

Three unchanged-production regressions demonstrated retained target CMOS state,
lost fw_cfg cursor and retained target IOAPIC redirection. The first file test
failed its fixture's minimum-RAM admission; that is retained as a test setup
failure, not a fourth checkpoint defect. The corrected file test uses 128 MiB.
Final root library: 11,603 passed, 35 ignored. C API: 225 passed.
The current focused VM tests passed, including source-independent ATAPI file
continuation. Fresh native ARM 1/2/4-CPU file continuation passed as one test.
C/C++: 19 programs and 7 ABI objects; 10 unchanged real-mode software test bodies
executed through an explicit portable harness. See [qualification.json](qualification.json)
for commands, counts, feature selections, source hashes and limitations.

## Remaining scope

- High: full C-STATE/C-SMP/C-HVF/A32-FP closure remains tracked in the audit ledger.
- High: uncontrolled raw memory aliases and host mapping changes still require
  external coordination; this group does not supply that exclusion.
- Medium: Wall RTC reads retain host UTC. Retired calendars now follow the owning VM
  clock from UTC2000; idle/periodic scheduling and full replay remain separate
  requirements. See the selected-calendar follow-up below.
- Medium: IOAPIC queue transport is covered; complete interrupt routing,
  delivery-mode semantics and physical Intel execution are not established here.
- Medium: interrupted and odd-byte ATAPI command behavior is transported as
  currently modeled; this group does not qualify its complete hardware semantics.

The resource-only producer control originally failed the CPU/backend resource
prerequisite. Its repaired file path rejects missing owners and incorrect
section order, and retains the explicit absence of opaque CPU payloads. This
qualifies resource framing; it does not establish any backend private-state completeness.

The [selected-calendar follow-up](../rtc-selected-clock/README.md) qualifies
CMOS time/UIP/alarm clock binding,actual guest PIO continuation and explicit
RAXPCD01 Wall-only versus RAXPCD02 selected-calendar admission.

## RTC oscillator phase and IRQ8

RAXPCD03 prefixes the RAXPCD02 body with three little-endian 64-bit values.
They record the oscillator phase in units of 1/1,000,000,000 of one
32,768 Hz oscillator cycle, the last sampled VM nanosecond counter, and
the last sampled UTC calendar second. RAXPCD01 and RAXPCD02 contain no IRQ8
oscillator phase. Their imports start a new periodic phase and retain the
calendar admission described above.

On capture, the VMM polls RTC and publishes the pending IRQ8 level before
sampling the controller banks. On restore, the recorded Register C level
must agree with the saved I/O APIC input or native KVM GSI8. Software restore
rebinds the PIC input without generating an edge. Reading Register C clears
the RTC flags and lowers the line, including when checkpoint settlement
services a pending native PIO read. A failed native line update disables
guest entry because the RTC and native controller can have diverged.

The detached-file test requires no delivery at 976,562 ns and delivery
at 976,563 ns for the 1,024 Hz rate. Its second capture holds IRQ8 asserted
after both controllers accept it. Restore preserves the held state, and
EOI after Register C acknowledgement does not generate a second delivery.

The hosted Linux x86-64 KVM regression restored an asserted GSI8 from a
detached checkpoint. Settling the guest's stopped Register C read lowered
the kernel line. The resumed guest reported the expected `0xc0` byte.
[Hosted KVM run for `db443e45b`](https://github.com/HexRaysSA/rax/actions/runs/44750698131/job/136337513983)

## Software PIT speaker wiring

On PC VMMs using the software PIT, port `0x61` drives channel 2 GATE and
samples the live OUT signal from the model registered at ports `0x40`–`0x43`.
The system-control model retains the speaker-enable latch and refresh phase.
Current files retain the PIT countdown phase. If an older PC record saved a
port-B gate that disagrees with its PIT gate, restore applies the saved port-B
gate at the incoming clock epoch.
Base-only checkpoints derive the gate from their PIT image.

The file-restore regression destroys the source VMM and exercises both cases
with a retirement clock. A mode-0 countdown programmed for 100 ticks resumes
after 74 ticks. A repeated GATE write leaves that phase intact. The legacy case
starts the countdown at the incoming epoch. Both cases verify the next refresh
phase and speaker-enable readback. Native KVM PC construction still selects the
[kernel PIT and speaker](../kvm-pit-speaker/README.md).

The unchanged software VMM returned `0x03` after the restored countdown had
expired. The repaired VMM returned `0x23`. In a separate raw KVM UAPI replay on
Linux 6.8.0-138, restoring an expired mode-0 channel 2 restarted the countdown
in all five trials. `KVM_SET_PIT2` preserved the 65,535-tick divisor and
changed its load epoch. The fresh guest read `0x03` within 127 µs of restore
where the source had read `0x23`. The mask retains GATE, speaker-enable and
OUT. Linux 6.8's `kvm_vm_ioctl_set_pit2` calls `kvm_pit_load_count` for every
channel after copying the image. See the [retained kernel source](../kvm-public-state/references/kernel-x86-v6.8.c).

## Software PIT read-back

Each channel retains its first unread status byte independently of its pending
count. Reads return status first, then the count bytes selected by the
programmed access mode. A status read leaves the live count byte phase intact.
The order follows the Read-Back Command and Figure 13 of the
[Intel 8254 datasheet](https://www.scs.stanford.edu/25sp-cs212/pintos/specs/8254.pdf).

The detached file-restore regression reads channel 2 through the replacement
VMM's port bus. It covers capture with both count bytes unread and with only
the high count byte remaining. A separate file-format regression exercises
schema admission and the old count-only wire. See the
[PIT read-back device schema](../checkpoint-format.md#pit-read-back-state).

In five real-guest Linux KVM trials, reading a live low byte, then draining a
status-and-count latch, left the live high byte pending. The software PIT now
preserves this phase. The detached restore test saves with a status byte and
one latched count byte still queued in front of the live high byte.

## Software PIT modes 0 and 4

A completed count write transfers on the next oscillator tick, which leaves
the new count intact. Low GATE pauses decrements and high GATE resumes them.
The first byte of a two-byte write halts mode 0 and immediately drives OUT low.
In mode 4 the first byte leaves the current count and strobe in progress. Both
counters continue through zero and wrap at 65,536 binary or 10,000 BCD counts.
Mode 0 drives OUT high at its first terminal count. Mode 4 strobes low for one
clock at its first terminal count, and the channel 0 IRQ0 source observes
the rising edge at the end of that pulse. Advancing either channel takes
constant time and space regardless of the interval between samples.
[Intel 8254 datasheet, Figures 15 and 19 and Operation Common to All Modes](https://www.scs.stanford.edu/25sp-cs212/pintos/specs/8254.pdf).

A detached mode 0 test saves after the low byte of a replacement divisor while
the old counting element is stopped. It checks the saved count and port B OUT
on both sides of the replacement's transfer and terminal count. The mode 4
test writes ten at tick 0, saves at tick 11 with OUT low, and checks I/O APIC
delivery at tick 12, EOI, and a second load. Mode 4 OUT and count are also
sampled with GATE lowered during the strobe. The [device section encoding](../checkpoint-format.md#pit-software-loaded-state)
records these phases.

## Software PIT modes 1 and 5

After a complete count write, a GATE rising edge schedules transfer on the next
PIT tick. A falling edge preserves the scheduled transfer and any active count.
Mode 1 drives OUT low from the transfer until terminal count. Mode 5 drives OUT
low for one tick at terminal count. The count continues after terminal count
with a 65,536-count binary modulus or a 10,000-count BCD modulus. A later count
write supplies the next trigger while the current countdown continues. PC
channels 0 and 1 have hardwired GATE inputs, so programming them in either
mode leaves them waiting. These rules follow Figures 16 and 20 and the GATE
and Counter sections of the [Intel 8254 datasheet](https://www.scs.stanford.edu/25sp-cs212/pintos/specs/8254.pdf).

The detached continuation test uses port `0x61` to drive a full pulse and
then destroys the source VMM. It covers a pending transfer with GATE already
low, and an active count with a different reload queued for the next GATE
edge. See the [device section encoding](../checkpoint-format.md#pit-gate-triggered-state).

| Assumption | Basis and dependent result | Stress and falsification probe | Status |
| --- | --- | --- | --- |
| The VMM represents oscillator ticks at integer nanosecond boundaries. | The existing time conversion uses `floor(t_ns * 1,193,182 / 1,000,000,000)`. A GATE edge in tick `k` transfers in tick `k + 1`. | Latch a rising edge and drop GATE before the transfer. Compare OUT and count on both sides of that tick. | Retained. Sub-cycle pin setup and hold times are outside this model. |
| A valid trigger requires a completed count write. | The Intel timing diagrams program the counter before asserting GATE. Pre-programming edges have no scheduled transfer. | Program with GATE already high and observe that it stays armed before a fresh rising edge. | Retained. |

The native Linux KVM PIT still owns its countdown phase in kernel-managed PC
machines. That is a high-impact boundary for native checkpoint continuation.

## Software PIT modes 2 and 3

The first complete divisor loads on the next oscillator tick. While counting,
a replacement transfers after the rate generator's active cycle or the
square-wave generator's active half-cycle. NULL COUNT reports the wait for
transfer. An unfinished two-byte write leaves the previous complete divisor
and the live cycle intact.

GATE low forces OUT high and stops decrements. A rising GATE latches a restart
for the next tick. Mode 2 emits a low pulse at count one and raises IRQ0 on
the subsequent rising OUT edge. Mode 3 decrements the visible count by two.
An odd divisor has an extra clock in the high half during which the visible
count is zero. A programmed divisor of one is outside the specified range
for either mode. The model treats it as two.
[Intel 8254 datasheet, Figures 17, 18 and 22](https://www.scs.stanford.edu/25sp-cs212/pintos/specs/8254.pdf).

Advancement takes constant time and space. It resolves the first load or
replacement boundary and uses division and remainder to count subsequent
cycles. The detached VMM test saves a pending divisor in each mode, then
checks the active count, OUT, NULL COUNT, and IRQ0 through the I/O APIC after
the source VM is destroyed. See the [device section
encoding](../checkpoint-format.md#pit-periodic-state).

## I/O APIC NMI routing with LAPIC software disable

An I/O APIC NMI retains its destination and can transfer to the local NMI
latch with `SVR[8]` clear. Ordinary fixed and lowest-priority messages
continue to require an enabled local APIC. The detached test saves both
messages in the I/O APIC and destroys the source VM. With one, two and four
vCPUs, only the selected CPU accepts the NMI. Its handler records the
interrupted PC, executes IRETD and reaches the guest continuation once.
The fixed message remains queued at the I/O APIC.
[Intel SDM Volume 3A, sections 12.4.7.2 and 12.8.1](https://cdrdv2-public.intel.com/835781/325462-sdm-vol-1-2abcd-3abcd-4.pdf)

| Assumption | Falsification probe |
| --- | --- |
| Software disable permits messages in NMI delivery mode to reach the selected APIC. | Restore one NMI pulse and one fixed pulse targeting a software-disabled LAPIC. Check the destination latch, the guest handler's return address, the quiet peers and the remaining fixed pulse. |

The parent failed at the NMI transfer. All 35 PC interrupt tests passed
after the fix on Apple Silicon, exercising the shared software controller
and the software x86 guest backend. Native HVF event injection and the
separate global APIC disable control require their own validation.

## Local vector masks across LAPIC software disable

Clearing the software-enable bit sets every modeled LVT mask. LVT writes
while disabled preserve the mask, and re-enabling leaves the LVT masked
until the guest explicitly unmasks it. This applies to the shared controller
and the inline x86 controller. Restoring an older disabled controller also
sets its masks at publication. An armed TSC deadline that expires after
publication clears without creating a new pending vector.
[Intel SDM Volume 3A, section 12.4.7.2](https://cdrdv2-public.intel.com/835781/325462-sdm-vol-1-2abcd-3abcd-4.pdf)

| Assumption | Falsification probe |
| --- | --- |
| LVT masks survive disable, a write while disabled, and subsequent enable. | Read each modeled LVT across all three transitions. Repeat with a restored legacy image that contains unmasked entries. |
| A future masked deadline cannot generate an interrupt. | Bind the deadline handle before restoring, expire the saved deadline after publication, and require the existing IRR and ISR bits to remain intact without a new timer vector. |

The register updates use constant time and storage. Both mask regressions
failed on the parent. The corrected sources passed all 130 LAPIC tests,
six inline checkpoint tests, three deadline codec tests and 12 CPU checkpoint
integration tests. The 10 x86-64 real-mode boot tests passed under Rosetta
with the virtual-wire routing change also applied. The Intel HVF library and
owner target type-checked for `x86_64-apple-darwin`. Independent native
countdown phase and bare-metal Intel timing remain open.

The unfiltered Apple Silicon library run passed 13,277 tests with zero
failures and five ignored. It tested these source files over
`b8e1c9b8e0a3d0023187594616c06a0756210f42` with the virtual-wire and
AArch32 no-EL3 changes also applied.

## Legacy PIC routing through LAPIC LINT0

For a software-owned PIC, the BSP accepts its IRQ through unmasked LINT0
in ExtINT mode. In the userspace KVM profile, disabling the APIC globally
routes the PIC directly to the BSP. Intel HVF uses the same software
routing decision when deciding whether to request an interrupt window.
Checking the route leaves the PIC request pending. The controller
acknowledges it only when the BSP accepts the vector.
[Linux v6.8 KVM virtual-wire acceptance rule](../kvm-native-private-state/references/linux-lapic-v6.8.c#L2868)

| Assumption | Falsification probe |
| --- | --- |
| A pending PIC IRQ cannot pass masked or non-ExtINT LINT0 with the global APIC enabled. | Hold IRQ0 pending through both LINT0 settings and a detached restore. Unmask ExtINT and check the guest handler PC and the consumed PIC request. |
| The KVM direct route follows the live APIC base. | Toggle the native global enable bit and query the BSP route through the managed vCPU. |

The parent delivered IRQ0 through masked LINT0. The corrected source
passed all 36 PC interrupt tests and all 12 CPU checkpoint integration tests
on Apple Silicon. The Linux KVM tests and the Intel HVF owner target
type-checked. The 10 x86-64 real-mode boot tests also passed
under Rosetta. The unfiltered Apple Silicon library passed 13,277 tests
with zero failures and five ignored. It tested these source files over
`b8e1c9b8e0a3d0023187594616c06a0756210f42` with the software-disable LVT
masking and AArch32 no-EL3 changes also applied.

The hosted Linux x64 KVM job on
`e216d408230714d8a7b3023ca8fa221db39b1134` exercised the managed vCPU
with the hardware APIC global-enable bit set, clear, and set again.
The probe passed alongside all 18 KVM state tests. The job also passed
all 15 native minimal and 32 native SMP cases. The job log SHA-256 is
`0270d48adc189dc17740b868825055997164393ce17ed4656ba7c96efe6a472d`.
[Hosted KVM execution](https://github.com/HexRaysSA/rax/actions/runs/44902538835/job/136841268421)
