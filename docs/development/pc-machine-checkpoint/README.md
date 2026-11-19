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

RAXEXE04 extends the execution record with a length-prefixed RAXPCD02 control
image. RAXEXE01/02/03 remain readable. Complete PC execution restoration rejects
an older execution image without PC state. Historical base-only represented
state remains a separate API and does not acquire missing device state.

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

## Software PIT mode 4 strobe

With GATE held high, a mode-4 load produces one low pulse at terminal count.
The channel 0 IRQ0 source sees the rising edge on the next PIT clock. The
counter continues through zero and wraps at 65,536 binary counts or 10,000
BCD counts. Later wraps produce no additional pulse. A BCD reload of zero
selects 10,000 counts. These are the mode-4 and counter rules in the
[Intel 8254 datasheet](https://www.scs.stanford.edu/25sp-cs212/pintos/specs/8254.pdf).
The legacy controller recognizes the low-to-high transition in edge-triggered
mode. See the [Intel 8259A datasheet](https://www.scs.stanford.edu/25sp-cs212/pintos/specs/8259A.pdf).

With a divisor of ten, the model-level test polls at PIT ticks 10, 11 and
20 after the load and expects one IRQ request at tick 11. The detached
file test saves at tick 10 with OUT low, restores the clock and device,
and checks the I/O APIC route through delivery, EOI, subsequent wraps and
a fresh count load. Mode-4 channel 2 GATE transitions and the delay from
the programming write to the physical reload edge remain separate timing cases.

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
