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
Complete captures with a software PIC use RAXPCD05. With an in-kernel
interrupt controller, running machines use RAXPCD03 and machines stopped
by S5 use RAXPCD04.
RAXEXE01/02/03 remain readable. Complete PC
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
binds the saved PIC input bank, or reconstructs the IRQ8 input for older
records, without generating an edge. Reading Register C clears
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

### IRQ8 at guest PIO boundaries

The VMM samples the RTC before servicing a guest PIO access to either CMOS
port, then publishes the device's resulting IRQ8 level without advancing the
clock. Register C acknowledges the active flags through a read. Its IRQ8
deassertion reaches the interrupt controller before another clock sample,
including when the device read succeeds and the CPU reply fails. Sampling
before a Register A write accounts for any tick already due under the outgoing
rate. Stopped checkpoint settlement and normal guest execution use the same
port-width overlap check for scalars and fixed-port string input.
[DS12885/DS12887 datasheet, Control Register C and Table 3](https://www.analog.com/media/en/technical-documentation/data-sheets/ds12885-ds12c887a.pdf)

At 1,024 Hz the period is `10^9 ns / 1024 = 976,562.5 ns`. The retired-clock
tests sample the first period at the next integer nanosecond (`976,563 ns`)
and the second at `1,953,125 ns`. The scalar Register C read returns `0xc0`.
The two-element word read starts each element at port `0x70`, returning
`[0x0c, 0xc0, 0x0c, 0x00]`. Both paths require a new PIC vector `0x28` when
the next period elapses. A separate word output changes the rate to disabled
at `976,563 ns` and requires vector `0x28` for the tick already due. Before the
fix, the scalar acknowledgement test and the rate write both lost that
delivery. Both regressions pass through the normal VMM dispatcher with a
retired clock and the software interrupt controller. The local suite passed
40 PC interrupt, 34 RTC device, 5 PIO dispatch and 30 VM execution tests.
Native delivery for these exact cases is unverified.

| ID | Basis and dependent result | Falsification probe | Status |
| --- | --- | --- | --- |
| RTC-PIO-1 | The attached PC routes CMOS PIO at `0x70` and `0x71`, including the second lane of a word access. IRQ8 publication depends on detecting that lane. | Read two words at fixed port `0x70` across a failed CPU reply and inspect the returned bytes and deasserted IRQ8 before polling again. | Exercised locally |
| RTC-PIO-2 | The modeled periodic timer accrues time at the programmed rate. Delivery of an elapsed tick depends on sampling before the rate changes. | Disable the rate with an output at the first integer nanosecond at or after the period boundary and require an IRQ8 vector. | Exercised locally |

## Software PIC input levels

RAXPCD05 places three bytes before the existing RTC timing prefix. The first
is the S5 flag, encoded as 0 or 1. The next two are the master and slave input
bitmaps, with bit 0 representing input 0 on each controller. The master bitmap
includes its IRQ2 cascade level. The stable PIC record already carries the
interrupt request and in-service registers.

Capture samples the input bitmaps under the same PIC lock as the stable
record. Restore assigns both bitmaps directly before publishing the controller.
The assignment leaves the saved request and in-service registers intact.
The work and additional space are constant. The RAXPCD01 through RAXPCD04
reader continues reconstructing the inputs available from UART, i8042 and
RTC state. Those formats cannot retain other held inputs or exact IRQ2 history.
A target with a kernel-owned interrupt controller rejects a software PIC input
bank before checkpoint publication. Readers that predate RAXPCD05 reject the
new PC tag.

| Assumption | Falsification probe |
| --- | --- |
| A held input keeps its edge history across detached file restore. | Acknowledge IRQ3, save while its level is high, restore into a fresh VM, and publish high again. After EOI, the restored PIC must match the source PIC and deliver no new vector. |
| The cascade requires its own input bit. | Acknowledge i8042 IRQ12 while its output remains asserted. After file restore, raise a higher-priority slave request and send a master-only EOI. The source and restored PIC must both report no new delivery. |
| The software PIC prefix preserves S5 and admits only a complete software-owned image. | Round-trip both S5 values, reject a truncated prefix and an invalid flag, and reject admission to an in-kernel controller. |

The two detached-file tests on macOS arm64 reproduced extra vectors `0x23`
and `0x28` against `392341ed5`. The predecessor log SHA-256 is
`29b7d0c46bfa2fa366ae7699934cddd766d0d755fcd9efa64c00a1f59fa17fc2`.
Both passed with the fix applied to `744a9a636` using
`cargo test --locked --no-default-features --lib checkpoint_preserves_pic_`.
The rerun log SHA-256 is
`a2ffd83dc85d66e3f3ecece87000b3d62c005e1d65b60aca1c7fa94686735df9`.
The source PIC serves as the continuation reference for both tests.
The checkpoint, PC device, PIC, RTC clock and PC interrupt modules passed
5, 12, 24, 1 and 38 tests respectively on `392341ed5` with the fix.
An unfiltered library run on `392341ed5` with the fix reproduced the existing
Darwin `kern.hostname` test failure and hit its 12-minute limit. Hardware
8259 timing and native checkpoint coverage require separate evidence.

### Saved IRQ8 agreement across software controllers

The RTC Register C interrupt summary, I/O APIC input 8, and slave PIC input
0 describe one physical line in the software PC. ICW1 clears the PIC's
latched requests and retains the physical inputs. In edge-triggered mode,
an input held high across initialization needs a fall and a new rise to
create a request. [Intel 8259A data sheet, Initialization Command Words and Edge and Level Triggered Modes](https://www.scs.stanford.edu/12au-cs140/pintos/specs/8259A.pdf)

The earlier PIC model zeroed its input cache during ICW1. An existing
RAXPCD05 record can therefore contain a low PIC bit alongside an asserted
RTC and I/O APIC input. Restore binds the PIC bit to the RTC level without
changing the saved interrupt request or in-service registers. A high PIC
bit alongside a low RTC can suppress the next PIC edge. New capture and
decode reject that mismatch, and RAXPCD05 rejects an I/O APIC mismatch in
either direction. The comparisons take constant time and storage and use
the existing checkpoint layout.

RAXPCD01 through RAXPCD04 lack a saved PIC input bank. The VMM continues
to reconstruct the available inputs at software restore and to check
the native controller against Register C where it owns the RTC route.

The two checkpoint admission regressions failed on `6902c69f7`. The PIC
unit regression observed input 0 clear after ICW1 on the old controller.
The revised build passed 25 PIC tests, 13 PC device tests, seven VMM
checkpoint tests, and four RTC routing tests. The detached regression
restores the held level, reads `0xc0` from Register C to lower it, and
receives vector `0x28` on the following assertion. Physical controller
timing and native checkpoint coverage are separate validation requirements.

| Assumption | Basis | Falsification probe | Status |
| --- | --- | --- | --- |
| The VMM's RTC is the source for PIC IRQ8 and I/O APIC input 8. | RTC publication sets both routes from the Register C summary. Older ICW1 code could clear the PIC bit. | Hold Register C and the I/O APIC line constant and invert only the PIC bit. Require rejection with a deasserted RTC and normalization with an asserted RTC. Reverse the I/O APIC input separately. | Exercised by the wire regression. |
| Capture runs under the PC device and PIC ownership boundary. | The VMM samples the saved PIC inputs under the same lock as its request and service registers. | Inject a stale high PIC input with RTC interrupts disabled and require capture rejection. Clear the line and require capture to succeed. | Exercised by the VMM regression. |
| A held physical input survives ICW1 independently of its interrupt request. | The 8259A requires a fresh transition in edge-triggered mode. | Reinitialize the slave PIC after acknowledging an RTC request. Restore the file, require no new vector while the input stays high, then clear Register C and require vector `0x28` on the next assertion. | Exercised by the detached VMM regression. |

## Software UART IRQ4 checkpoint coherence

The PC board routes the 16550 OUT2-gated COM1 output to IRQ4 on the PIC
and input 4 on the I/O APIC. The coordinated RAXPCD05 image checks the
saved I/O APIC wire against the UART and rejects a high master PIC input
with a low UART. The check runs when validating the execution graph for
capture, save, load, and restore. Older RAXPCD05 records with a held UART
and a low PIC input can bind the input from the matching I/O APIC wire
and retain the saved IRR and ISR. RAXPCD01 through RAXPCD04 omit the PIC
input banks and reconstruct available inputs from their saved devices.
Each wire comparison and binding takes constant time and storage.

On `7c51e6b3e`, the bundle builder accepted a record assembled from an
idle UART and an asserted I/O APIC input. A detached checkpoint with an
acknowledged COM1 interrupt and a cleared PIC input latched another
vector `0x24` at the first interrupt-source refresh. The regression
reconstructs that file, retains the RX byte, confirms no extra interrupt
while the line stays asserted, reads RBR to drop the line, and requires a
new vector `0x24` on the next assertion. A second regression varies both
directions of mismatch and a separately stale high PIC input.
The four local test groups passed 69 tests in total. Formatting and library
Clippy with warnings denied passed.

| Assumption | Basis | Falsification probe | Impact |
| --- | --- | --- | --- |
| The managed PC's IRQ4 wire is the OUT2-gated COM1 level. | The board binding and software IRQ publisher route that source to both controllers. | Pair independently captured idle and asserted UART and I/O APIC states. Require each disagreement to fail execution graph admission. | High |
| A low saved PIC input can be rebound when the other two records agree that COM1 is high. | Older ICW1 code could clear a held input without introducing a new edge. | Acknowledge IRQ4, detach a file with a low PIC input, and check that a refresh leaves IRR quiet. Read RBR and assert the next input, then require one new vector. | High |

This validation exercises the portable PC models. Intel HVF execution and
the remaining native and platform checkpoint profiles stay open.

## Software i8042 IRQ1 and IRQ12 checkpoint coherence

The software PC controller routes keyboard output to IRQ1 and auxiliary
output to IRQ12. RAXPCD05 verifies both I/O APIC inputs against the gated
i8042 output latch and rejects asserted PIC inputs without a corresponding
device output. When both the device and I/O APIC show an asserted wire,
restoring an old low PIC input leaves IRR, ISR, and the cascade bit intact.

RAXPCD01 through RAXPCD04 can contain a byte saved before the output latch
drove the interrupt wires. Software restore reconstructs both input levels
from the saved latch during preparation. It preserves pending edge messages
and does not create an edge. A changed level-triggered I/O APIC input uses
the controller's normal level evaluation, including cancellation on
deassertion and withholding delivery while masked or awaiting EOI.
The operation handles two pins in a controller bounded to 24 pending
deliveries, so time and additional storage are bounded independently of
guest memory size. The on-disk format is unchanged.

On `3eb8dec24`, capture accepted a stale high I/O APIC input and detached
restore left a held IRQ1 PIC input low. Both regressions passed after the
change. The six local library groups ran 142 tests, covering VMM checkpoint
admission, PC IRQ routing, PIO, the PC machine, I/O APIC and i8042.

| Assumption | Basis | Falsification probe | Impact |
| --- | --- | --- | --- |
| The gated i8042 output latch is the source for both saved wires. | Normal and stopped PIO publish changes through the same VMM routing helper. | With each input in turn, alter the I/O APIC line in both directions and separately leave a stale high PIC input. Require capture to reject each discrepancy. | High |
| A low RAXPCD05 PIC input can be rebound from a consistent held source without changing delivery history. | Older ICW1 code could clear the PIC input cache after a request was acknowledged. | Restore detached IRQ1 and IRQ12 files with that input cleared. Refresh the held wire, consume the retained byte, and require exactly one interrupt on the next assertion. | High |
| A pre-routing image supplies a level through the latch but supplies no new edge. | The older records preserved the latch and controller independently. | Restore a RAXPCD03 file with an unbound AUX output. Require zero queued edges or one level delivery according to the saved route, then require successful capture as RAXPCD05. | High |

The software controller checks apply to PC configurations that use the
shared software interrupt controller. Native KVM interrupt banks and live
Intel HVF guest execution are outside the validation for this change.

## Native KVM i8042 IRQ1 and IRQ12 checkpoint coherence

Managed KVM captures the 8042 under the PC device boundary and samples
external GSI levels from the native interrupt owner. IRQ1 and IRQ12 must
match the enabled output latch at capture and before native restore
publishes CPU, RAM or device state. The check uses the line shadow because
a kernel PIC or I/O APIC request can outlive the edge that created it.
The two comparisons take constant time and storage after PC image decode.

The native wire format is unchanged. A checkpoint from before the 8042
router that retains an enabled output byte and a missing line fails native
restore admission. Its native controller banks cannot establish whether
generating an edge at import would duplicate an interrupt. Coherent files
continue to restore the saved controller banks and pending guest delivery.

On `38a55acd8`, both regressions reproduced on an Intel Xeon E5-1650 v3
host using Linux KVM `6.8.0-138-generic` with APICv enabled. Capture accepted
a contradictory IRQ state and restore accepted a mixed device/controller
checkpoint. Both regressions passed on the same host with the rebuilt
harness. Its target PC and RAM sentinels and the idle 8042 latch survived
each rejected restore. The real-mode IRQ12 guest resumed from a detached
file and reported the saved auxiliary byte once before reaching its
continuation marker.

| Assumption | Basis | Falsification probe | Impact |
| --- | --- | --- | --- |
| The two native GSI levels have the same source as the saved output latch. | Stopped and normal PIO call the same native line publisher while holding the controller. | Assert each route with no gated output, then clear it with a gated byte still held. Both contradictions must fail capture. | High |
| A native source graph can be checked before target publication. | Restore decodes the source KVM image before invoking native setters or committing physical RAM. | Combine each saved 8042 state with the opposite line state in an otherwise consistent graph. Restore must preserve the target PC, RAM sentinel and idle latch. | High |
| Pending requests are distinct from the external line. | KVM owns interrupt requests after an edge is delivered or acknowledged. | Restore through the existing native IRQ12 guest, then require the correct aux byte and one handler invocation. | High |

## Native UART IRQ4 checkpoint coherence

For the native PC interrupt controller, capture synchronizes GSI4 from the
16550 interrupt source before reading the controller banks. The source
includes the MCR.OUT2 gate. A synchronization submits only changed levels,
under the existing native line lock. Reissuing a held edge can clear the Linux
I/O APIC's `irr_delivered` bit, which `GET_IRQCHIP` uses to distinguish
delivered interrupts from pending ones. The UART and the saved GSI4 must agree
at capture and before restore publishes CPU, RAM or device state. A file with
inconsistent fields is rejected. Consistent files use the existing schema.
[Linux v6.8 I/O APIC implementation](../kvm-native-private-state/references/linux-ioapic-v6.8.c)

On Linux `6.8.0-138-generic`, a direct KVM probe enabled the BSP LAPIC,
routed I/O APIC pin 4 in edge mode to vector `0x41`, and sampled the native
controller. The first high level set `LAPIC.IRR[0x41]` and left the exported
I/O APIC `irr[4]` clear. Issuing high again set the exported `irr[4]`.
Deasserting the level cleared it. This is the native control for skipping
unchanged levels during capture.

Both production regressions fail at `b9db749aa` on the same physical Intel
Xeon E5-1650 v3. A detached restore retained the queued byte with the input
level low, and the stopped restore accepted mismatched controller and UART
records. The baseline log SHA-256 is
`9cadb96b70b6a96427cca0c587053d7584274237c25b9ef5c977e4129acc9555`.
The corrected build passes both native regressions. The restored PIC input
is high before RBR settlement and low afterward, and the guest echoes
`0x7b`. Rejection preserves the destination's PC, RAM marker, and UART FIFO.
The focused corrected log SHA-256 is
`66a8dc12b98bd8c185f8a1ce2217c79399eca8fad3c644b57d80c4b88642a43d`.
All 29 portable PC interrupt tests pass on macOS Arm64.
The unfiltered macOS Arm64 library run encountered a Darwin codesign test
failure and ended with SIGKILL before a final count. An isolated run of
`closed_dispatcher_copies_self_status_without_host_observation` returned
`EINVAL` where the test expects `EPERM`. The unfiltered log SHA-256 is
`47c0b192a8204e44f25d5ff02e2b8ecad8c3e10ac40288825a8980d331313e7a`.

The native owning `checkpoint_cpus`, `kvm_host_slices`, `kvm_minimal`,
`kvm_smp`, and `realmode_boot` binaries passed 13, 17, 15, 32, and 10 tests
respectively, with zero failures or skips. The log SHA-256 is
`6c560d2ae36494cb5743f9b16b2288e2c787c8ab1784053e23615062095b21a9`.
The native checkpoint-dispatch suite passed all 19 tests, including both
IRQ4 regressions. Its log SHA-256 is
`cd980e912b96e133f288140d4ab6a995c71536c786c15409c2c7a1ff6d402fe6`.
The hosted KVM job for `ffbf9ab90` passed all 13 configured test steps and
its release build. Its dedicated IRQ4 step requires both named test results.
The opt-in unfiltered step was skipped on this push.
[Hosted KVM job](https://github.com/HexRaysSA/rax/actions/runs/45307893313/job/138156097668)

An earlier run hit its timeout in the native checkpoint-dispatch suite. An
overlapping integration retry then lost its scratch checkpoint file during
cleanup. Two earlier host-slice runs also failed the raw-vCPU worker-identity
assertion. The fresh unfiltered `kvm_host_slices` run passed that assertion,
as did the unchanged base and six isolated base repetitions. The cause of
the intermittent worker-identity failure remains unknown.

The full Linux library build used `35024d3e6` plus the tested Rust changes,
with `x86_64-suite,smir-jit,kvm,debug` enabled. Its Windows LPC replay
initially failed with an incomplete fixture archive. The same executable
passed that replay after restoring the tracked fixture directory from the
tested revision. The isolated retry log SHA-256 is
`6edf77090fd104f23c7c807a9a8d361e5ab7c9e1047c13b5b1c23664183db552`.
The Linux run also reported the Darwin codesign failure seen on macOS. It
reached the 14,017 of 14,436 progress marker and timed out at 3,200 s while
running AArch64 cluster checkpoint tests. The library run has no final
test count. Its log SHA-256 is
`d5f0cb01d2a86b11dc1c5acb49e85924000fc90b4bfc16504b086c51ea842586`.

| ID | Assumption and basis | Dependent result | Stress test and falsification probe |
| --- | --- | --- | --- |
| UART1 | The managed PC's GSI4 is the COM1 wire and `has_pending_interrupt` includes OUT2. | Conserved IRQ4 input and FIFO state. | Queue one RX byte with its IRQ enabled. Write and reload the file after destroying the source. A cleared restored PIC input or a lost RX byte falsifies the mapping. |
| UART2 | An acknowledged UART read releases the source after the last RX byte. | No held IRQ4 after settlement. | Observe the native master PIC before and after settling the real guest RBR read, then check the guest's echo. A stale assertion or incorrect echo falsifies continuation. |
| UART3 | A valid native file has the same UART source and GSI4 level. | Restore admission before publication. | Combine the asserted UART image with an idle controller image. Acceptance or mutation of destination CPU, RAM, or serial state falsifies the check. |

Capture refresh and admission take O(1) time and space. Kernel LAPIC timer
phase and general in-flight owner completeness remain high-impact C-STATE
requirements.

### Held IRQ4 during live execution

The live console and port-output paths now share the managed UART level
publisher with capture and port-input settlement. On KVM, the comparison
and publication share the native line lock. An empty console poll or
unrelated UART register write therefore preserves the exported I/O APIC
state when the UART source remains high.

The native test uses a guest with IF clear, an enabled BSP LAPIC and an
edge-triggered pin 4 routed to vector `0x41`. The guest first reports
`LAPIC.IRR[0x41] = 1`. The exported I/O APIC then reports the edge
delivered. Two independent fixtures repeat the console input path and
settle a guest write to COM1's scratch register. Before the fix, both
fixtures reported the edge pending again. With the fix, neither does, and
the UART's source remains high in both.

The baseline log SHA-256 is
`4ba1ec819442728052bcc71c4fcccdba0bda8d9b2e30f2740a2c2662a679ba7c`.
The corrected live case log SHA-256 is
`33a42d3a31dd41f8c056e5858a2a6ffacfb1cd2060fca7f52bbe6130928102f4`.
All three focused native UART tests passed with zero failures or skips.

The same five unfiltered native integration binaries passed all 87 tests.
The native checkpoint-dispatch suite passed all 20 tests. Neither run had
any failures or skips. The log SHA-256 digests are
`7d4cb0ab10e62ef1000b8453a163939fc3b71defce3b9cb4446f3fad14a3fae9`
and `4fa7bf267ed109f28054c6e7884dd44b68943b37b20d2221f1d644c4f87bce8f`.

The unfiltered library run reproduced the Darwin codesign failure. The
Windows LPC replay passed with its tracked fixtures present. The run
reached the 13,993 of 14,438 progress marker and timed out at 3,200 s in
the AArch64 cluster checkpoint tests, without a final test count. Its log
SHA-256 is `38178076b55bf145eac53a32b2ef2e37c67e78acf65430f7f586dd1b8f58f25f`.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| The first assertion reached the intended LAPIC vector before testing the repeated operation. | High | Require guest readback of the LAPIC IRR bit and a clear native I/O APIC pending bit before each operation. |
| Console poll and scratch output leave the RX cause asserted. | High | Require the UART source high both before and after the operation. A new pending I/O APIC edge falsifies conservation. |

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

## Countdown expiry while the local timer is masked

The local APIC countdown advances while the timer LVT is masked. Writing
the LVT settles elapsed periods against the previous mask and vector.
An expired masked one-shot reaches zero. A masked periodic timer retains
the remainder of its current period. Expiries already admitted by an
unmasked LVT remain assigned to their original vector.
[Intel SDM Volume 3A, section 12.5.4](https://cdrdv2-public.intel.com/835754/253668-sdm-vol-3a.pdf)

| Assumption | Falsification probe |
| --- | --- |
| The LVT mask controls delivery at expiry. | Start a 100-tick timer at 1 tick/ns. Advance 125 ns with the mask set, unmask without an intermediate timer poll, and require an empty interrupt frontier. |
| Unmasking preserves periodic phase. | At 125 ns require the count to read 75. Sample at 199 ns and 200 ns and require only the latter to produce the periodic vector. |
| A detached inline checkpoint retains countdown phase. | Serialize the masked timer at 125 ns, destroy the source, and run the same unmask and boundary checks after import into a fresh clock. |

The shared and inline parent tests both returned stale vector 0x40.
Both corrected tests pass in one-shot and periodic mode. Independent
QEMU 11.1.2 controls on the PC and Q35 machines observed that a one-shot
expiry under the mask stayed absent from IRR after unmasking. The two
unmasked controls retained the expired vector in IRR across the LVT
write. Local phase advancement takes constant time and auxiliary space.

The unfiltered native Intel Linux KVM library passed 14,231 tests with zero
failures and 99 ignored. It tested these source files over
`e0c83ee4e6ae82f046638028e2e4e40f8650d741` with the other
checkpoint and exception-return changes applied. The raw log SHA-256 is
`f48aed218dd82309d1c21e32172419db29f73e214e282f9b31a2e1890a619e04`.
A deterministic mask-write test checks preservation of the original
request through acknowledgement, and a boundary test writes the
vector just before and at expiry. Only test-source line wrapping
changed after this build.

All 12 CPU checkpoint integration tests and all 10 x86-64
real-mode boot tests passed on both Apple Silicon with Rosetta and
physical Intel Linux with KVM. Native kernel countdown phase and
bare-metal Intel HVF still require separate qualification.

The unfiltered Apple Silicon library on the same frozen base and timer
and exception-return overlays recorded 13,279 passes, two failures, five
ignored, and zero filtered. Both failed GSC checkpoint tests lost their
first child to SIGKILL. The sender is unknown. Both cases passed together
on the same executable SHA-256
`c5b495a4e2cd7c0728b794c88cc2695ebbfe6d69a00de9ac946fdecc168a3f3d`.
The full and paired log SHA-256 values are
`15af91d13d2c28676bc6f13885cd0312afe1b0640ce968eebe56dbc7ce880cdf`
and `cc36d008ef47bea37c9ff557db315603921cbba331d81dbeee22871fea24d883`.

## PIT channel 0 on the PIC and I/O APIC

The VMM presents an elapsed PIT channel 0 edge to both PIC IRQ0 and I/O
APIC GSI2. The edge-triggered PIC latches IRQ0 regardless of its mask or
the current in-service IRQ. The VMM latches an elapsed PIT edge before
the PIC arbitrates maskable requests for the BSP. Non-maskable interrupts
retain priority. Latching the edge uses O(1) time and auxiliary space.
[Intel 8259A datasheet, Figure 9](https://flint.cs.yale.edu/cs422/readings/hardware/8259A.pdf)

| Assumption | Falsification probe |
| --- | --- |
| The edge latches on both routes while a different PIC request is active. | Target GSI2 at the AP. Save, destroy the source VM, reload the file, and require the AP's vector and IRQ0 in the PIC IRR with IRQ5 pending, in service, and in service with IRQ0 masked. |
| The master PIC uses its configured fixed priority at the BSP entry boundary. | Advance the one-shot to expiry with IRQ5 already pending. The BSP must enter vector `0x20`, leaving IRQ5 pending. |
| One expired one-shot reaches the PIC once. | After restore, unmask and acknowledge IRQ0, issue a specific EOI, and poll again. Require no second IRQ0 and preserve IRQ5's independent state. |

The predecessor restored IRR `0x20` where the pending case required `0x21`.
At BSP entry it selected IRQ5's handler at `0xa080` ahead of IRQ0's at
`0xa000`. Independent QEMU 11.1.2 QTest controls measured IRR/ISR/IMR
as `0x21/0x00/0xde`, `0x01/0x20/0xde`, and `0x01/0x20/0xdf`.
The masked control produced no poll result until unmask, and specific EOI
for IRQ0 preserved IRQ5. The test drove the PIT for 1 ms, beyond the
expiry of the 10-count one-shot at approximately 9.22 µs including the
load tick. The QTest record SHA-256 is
`e3923e49827d31d72deac867710f760274a64bce975a20108e92b09741575f48`.
[QEMU QTest protocol](https://www.qemu.org/docs/master/devel/testing/qtest.html)

Both RAX regressions passed on Apple Silicon with the fix applied over
`997f31499cced003ed9da8f6dbcc2b2a037d02bf`. All 170 PC interrupt,
controller, and native-scheduling model tests passed, as did the 13 CPU
and 16 clock checkpoint integration tests. All 10 real-mode boot tests
passed as x86-64 executables under Rosetta. The 170-test log SHA-256 is
`e7e9f477f92fbacdb6a4675208387b2a53868fac4a365bbf458c01d6f22f477c`.
The predecessor and corrected regression log SHA-256 values are
`73ad2993d0e58d00cc2a1d7f540def4dd0f2a1e8a595f7618e080344c759ce58`
and `8e30ed1791fd008981056e5022538443a8d951071f871a6354bbd7493b5311f7`.

These observations cover the edge-triggered software PIC route. The
kernel-owned IRQ chip, a PIC configured for level-triggered operation,
and physical Intel HVF guest execution require separate measurements.

## ACPI S5 power-off across restore

When the VMM accepts the PC's S5 power-off request, it records a VM-wide
terminal state before acknowledging the output. The stopped checkpoint I/O
callback records the same state. `Vmm::run()` checks it before dispatching
any CPU, including when a checkpoint taken inside the run loop settles the
output. ACPI defines S5 as the G2 soft-off state and describes how the OS
requests it through `SLP_TYP` and `SLP_EN`. UEFI Forum ACPI 6.6 §4.6
specifies that “Exiting the G2 soft-off state requires rebooting the system.”
[ACPI 6.6, The ACPI Hardware Model](https://uefi.org/sites/default/files/resources/ACPI_Spec_6.6.pdf)

RAXPCD04 has the same body as RAXPCD03. Its tag records acceptance of S5
and requires the RTC timing prefix. RAXPCD05 records S5 in a flag byte.
RAXPCD01 through RAXPCD03 carry no PC power-off record.
Restore publishes the latch only after the guest/backend
transaction succeeds. A complete bundle is required to capture S5. An
existing native backend terminal record still independently fences entry.
Recording and checking the latch take O(1) time and space.

| Assumption | Falsification probe |
| --- | --- |
| The accepted S5 request stops every vCPU. | Save after the BSP writes S5, destroy the source, reload the file, and call `run()` twice. Require both CPU program counters, both post-S5 RAM markers, and the retirement count to stay fixed. |
| A stopped I/O callback records only accepted S5. | Service a `0x0000` write and then `0x2000` to port `0x604`. Require the latch to stay clear after the first write and set after the second. |
| The terminal tag preserves admission and transactional restore. | Reject a truncated tag body, inject a failed restore into a terminal target, then publish an older running image. Require the failed restore to preserve the latch and the successful restore to clear it. |

The predecessor `48bd86a31` executed both post-S5 RAM stores after the
detached file restore. The pre-fix log SHA-256 is
`4d5d47d47a0cb5600914c32d44decdb79dc0b627e134c20d408c7c3930faa25e`.
The QEMU 11.1.2 QTest control used two vCPUs and
PIIX4 PM I/O configured at `0x600`. QEMU aligns the PCI configuration
field at `0x40` with `0xffc0` and enables the region with bit 0 at `0x80`.
`OUTW 0x604,0x0000` kept the VM running.
`OUTW 0x604,0x2000` produced the guest-shutdown event and moved the VM to
the `shutdown` run state. The QTest record SHA-256 is
`891e277256d6d30ec681670f9470424f6dc9661660cbab3aedb90273d9191d15`.
[QEMU 11.1.2 PIIX4 ACPI device](https://github.com/qemu/qemu/blob/v11.1.2/hw/acpi/piix4.c#L82-L93)

On macOS Arm64, all 13 PC device and S5 regressions passed with the fix
applied to `48bd86a31` and `x86_64-suite,smir-jit,hvf,debug` selected.
The log SHA-256 is
`205f67393307f42bb32b6294d6a8e8e0e2c9912ba0f368289add097f67c78efb`.
The complete CPU, configuration, and clock checkpoint binaries passed 13,
3, and 16 tests respectively. The first combined run was killed during the
clock suite without reporting an assertion failure. The standalone clock
retry passed all 16 tests. Its log SHA-256 is
`b93a992e0a74ec9408ebfd6fbe134088d27b35eb2c4c31bd96d06f2d75a74938`.
Under Rosetta, all 13 PC device and S5 tests and all 10 real-mode boot tests
passed in x86-64 executables. The log SHA-256 values are
`96a38fd8a9cf2c20c8170441d1de83a25b3bf47e4f4f272d5d5c16391e7c5742`
and `70d6c1a1d318799bd20e2d04e0a66f439d7a6c2685da0c54ea361511e6bf62b4`.
The Mac Arm64 library run reproduced the existing Darwin codesign failure.
`closed_dispatcher_copies_self_status_without_host_observation` returned
`EINVAL` where the test expects `EPERM`. The isolated failure log SHA-256 is
`a5aca766f13a7fd20502bacf65f55419fbf16066c7368807bff2c54ba17d0c4b`.
These measurements cover the software PC and the VMM's stopped I/O
callback. A stopped native Intel HVF file needs its own guest-level check.
