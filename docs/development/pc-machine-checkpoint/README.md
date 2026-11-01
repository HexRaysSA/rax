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

RAXEXE04 extends the execution record with a length-prefixed RAXPCD01 control
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
- Medium: RTC reads retain the existing host-wall-time policy. Deterministic
  scheduling, replay and a guest RTC epoch are separate coordinator requirements.
- Medium: IOAPIC queue transport is covered; complete interrupt routing,
  delivery-mode semantics and physical Intel execution are not established here.
- Medium: interrupted and odd-byte ATAPI command behavior is transported as
  currently modeled; this group does not qualify its complete hardware semantics.

The resource-only producer control originally failed the CPU/backend resource
prerequisite. Its repaired file path rejects missing owners and incorrect
section order, and retains the explicit absence of opaque CPU payloads. This
qualifies resource framing; it does not establish any backend private-state completeness.
