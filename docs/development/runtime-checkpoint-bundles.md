# Represented runtime bundle restore

`Vmm::restore_snapshot_bundle` restores the components represented by the bundle:
the ordered represented public/base-private state of every recorded vCPU,
PIC/PIT/UART/local APIC, the PCI bridge and typed optional
controllers/media, and either every captured physical region or the old reported
RAM projection, plus explicit timing state when present. A single-vCPU bundle with no extensions uses the original base restore path.
Multi-vCPU bundles without the required CPU set are rejected before mutation.
The source checkpoint remains borrowable for inspection/retry.

Version/config/architecture/count/topology/storage identity and access-policy
admission precede live mutation. Physical layout, projection and every digest
are verified into an immutable prepared checkpoint/target token. PCI/media are
constructed as detached candidates. Every legacy/PCI lock is acquired before
CPU/RAM commit. The bridge fully decodes and allocates its proposed state before
calling that commit; all bridge/endpoint publication afterward is infallible.
Bridge admission preserves the existing public PCI error conversion; caller
commit errors pass through unchanged. No controller handler is called, DMA command replayed or source file reopened by
restore. `Vmm::new_resume_bundle` and `--checkpoint` construct detached targets
without original sources; see `checkpoint-resume.md`. The older base constructor
retains its original source-opening contract.

Restoring a legacy RAM prefix checks write permission across all of its
regions before publishing CPU, device or timing state. On a target with a
writable first page and a read-only second page, both the base API and the
extensionless bundle API reject restore without changing RAM, architectural
or emulator-private CPU state, legacy devices, or the retirement and
checkpoint counters. Capture still reads the full reported prefix on that
target. The same archive restores into a writable target.

An RV64 bundle without a private hart record cannot replace a hart with an
issued UART MMIO write. A clock-only file exercises this admission path.
Rejection preserves the pending write, RAM, hart state, UART and checkpoint
counters. After ordinary VM execution dispatches the write, the same file can
restore the legacy projection.

### RV64 hart participation with a shared CLINT

The generic RV64 CLINT checkpoint requires at least one coordinator-online
hart. The per-hart private record holds a `WFI` wait independently. A CLINT
interrupt can wake a waiting hart that remains online. An all-offline mask
has no scheduler turn or hart-start transition. Capture and restore use the
same execution-section validation. The added check takes O(H) time and O(1)
additional space for H configured harts.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| An all-offline mask leaves no hart eligible for a CLINT wake. | High | Capture an otherwise complete bundle with every hart offline at each of one, two and four configured harts. Reject the same mask in a saved file. |
| Waiting harts retain their coordinator eligibility. | High | Capture actual `WFI` on all harts and resume from a file. Compare each timer wake, both coordinator frontiers and the private CPU records. |
| Kernel-free targets can have only the bootstrap hart online. | High | Save and restore the prepared multi-hart reservation fixtures with their existing sparse mask. Verify that private reservations and subsequent CPU results survive the file round trip. |

The parent captured an all-offline single-hart VM. Prepared multi-hart
fixtures established that a sparse online mask is valid when at least one
hart can be scheduled. This check applies to files with a shared CLINT
image. Other machine families and guest-driven hart power transitions are
outside this profile.

The Apple Silicon run passed 28 RV64 runtime tests, 107 snapshot unit
tests, 58 public integration tests and library Clippy with warnings
denied. A public-API probe saved real files at one, two and four harts,
removed the kernel source and checked cold and warm restore. Changing
only the stored online bits produced three all-offline load rejections
and four successful sparse-mask loads and restores. The probe and output
are under
`/Users/int/dev/rax-audit-work/four-findings-riscv-clint-coordinator-admission-2026-11-26/`.

### AArch64 PSCI power state

The software AArch64 base format carries the bootstrap CPU's public
registers. Register import makes that CPU runnable. Base capture and
legacy warm restore hold the cluster control lock and require a runnable
bootstrap CPU and an empty PSCI request queue. Base capture also requires
the VM to be powered on because the format has no `SYSTEM_OFF` latch.
A complete bundle can restore the CPU power flags, PSCI graph, outstanding
requests and coordinator eligibility together.

The coordinator can encode an offline bootstrap CPU only when the shared
PSCI record accompanies it. A shared record with a parked CPU requires the
corresponding private CPU state. Admission precedes device, CPU, RAM and
clock publication. Older base files that already omitted their source
power state contain insufficient information to reconstruct it.

| Assumption | Falsification probe |
| --- | --- |
| Guest `CPU_OFF` parks the CPU before coordinator acknowledgement. | Execute `CPU_OFF` and attempt capture and both legacy restore routes before and after acknowledgement. Compare the power flag, shared graph, queue, scheduler, RAM and serial FIFO after each rejection. |
| Coordinator, cluster and CPU state constrain the same power frontier. | Keep the offline scheduler bit and remove the shared cluster and private CPU state from the checkpoint. The legacy projection must reject. A complete running bundle must restore into the parked target. |
| A legacy base transfer cannot save `SYSTEM_OFF`. | Execute `SYSTEM_OFF` in the guest, check base capture rejection and verify that complete capture retains the latch. Restore a compatible legacy base into the terminal target and check capture works again. |

The baseline at `25a415533` accepted all three legacy operations during
the unacknowledged stop. The corrected macOS Arm64 run passed all four
targeted tests, including source-free continuation of queued multicore PSCI
requests. The baseline and corrected log SHA-256 digests are
`f7a178dc981b3aa809f87badf6f66f208692e12ce07a90179828796f5ae99efd` and
`ce734953e9e2b9e1b93169d93524633dc73e8d17bac757bd06eabb3dc3d1111a`.

### Private CPU records for the software AArch64 cluster

A software AArch64 bundle that carries both the shared GIC and PSCI record
and the PL011 image requires a private AArch64 record for every configured
vCPU. Bundle save, load, cold resume configuration and warm restore apply
the same check before publishing state. Admission scans the ordered records
in O(C) time and uses O(1) additional space for C configured vCPUs.

Early cluster bundles carried the shared record and a public CPU projection.
Commit `457c02a74` introduced the PL011 image and private records together.
The file API still reads the earlier cluster-only projection. Restoring its
shared GIC still requires the private timer source records. Commit
`1ad4231e3` later added the capture section inventory. The producer
requirement also applies to bundles without that inventory.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| Each CPU in the newer software cluster needs its own private record. | High | At one, two and four vCPUs, remove the private table while keeping the shared and UART images. At two and four vCPUs, retain the table and remove the final entry. Check save, cold configuration and warm restore rejection, and compare target RAM, shared state and coordinator retirement. |
| The PL011 image distinguishes this producer from the original cluster projection. | High | Save and load the cluster-only projection at each CPU count and check its existing restore error. Save, load and restore the complete bundle. The historical producer code establishes when both sections were added. |

The baseline at `f402c6bd5` accepted the one-vCPU incomplete bundle at save.
The regression and all 107 snapshot tests passed on macOS Arm64. The
baseline and regression log SHA-256 digests are
`f2b91216ff29f0a3fe000b6140df368b8e81a9399408b5a011af6c7d7aa8a00d` and
`10df977cd30cc33b64a930613d91738f0d376ea631c6b7fd6a48f99d6fc32dbe`.
The check covers the software AArch64 producer graph. The complete
checkpoint audit across all backends remains open.

### Shared GIC and PSCI state for software AArch64 UART checkpoints

A software AArch64 bundle with a PL011 image also requires the shared GIC
and PSCI record, including on a one-vCPU machine. Both records are needed
to validate that PL011 output agrees with the GIC interrupt line. The
shared record also owns the PSCI shutdown latch and pending power requests.
Save, load, resume configuration, and cold and warm restore all check the
record before publishing state. The check takes constant time and space and
does not change the file encoding.

At `6fc625beb`, save, load, and resume configuration accepted the incomplete
one-vCPU file with private CPU records. Cold and warm restore rejected it
later when the CPU replacement required the shared GIC.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| A software PL011 image identifies a producer with a shared GIC and PSCI record. | High | The producer in `457c02a74` captured both. At one, two, and four vCPUs, keep the UART image and remove the shared record, with and without the private CPU table. All five public admission paths must reject. |
| Rejection preserves the existing machine and permits a later complete restore. | High | Compare warm target shared execution state, typed vCPU registers and a RAM sentinel after rejection. Restore the complete file on warm and fresh owners and re-capture the PSCI shutdown latch and the PL011 FIFO. |

Projection files from before the PL011 section retain their existing
admission rules. Native AArch64 uses its own shared HVF image.
All 108 snapshot tests and 50 checkpoint integration tests passed on
macOS Arm64. The snapshot and integration log SHA-256 digests are
`9a46b235b1bc3be9d94f6a37231a34834ccf6707b1ada7e1869b10b3bd693591` and
`e4b7c148c21af41cb682d7983321fbc1d9ed3c77f6fea171e3b958b0fc9fb42d`.

### Intel HVF pending I/O

Intel HVF legacy capture checks every vCPU for pending I/O and holds the
stopped backend boundary through capture of CPU 0 and the reported RAM
prefix. A pending port or MMIO transaction on any vCPU requires a complete
bundle. The native pending-XMM regression checks both read and write exits on
secondary vCPUs and requires each transfer to dispatch once after bundle restore.

### Apple Silicon HVF legacy capture

Legacy capture on Apple Silicon uses the stopped HVF boundary for all
managed vCPUs and holds it through the bootstrap CPU and RAM projection.
Each owner checks for pending MMIO, a staged input reply, or a completion
error. The bootstrap owner also checks the shared PSCI graph. A queued
power request, a parked bootstrap CPU, or a `SYSTEM_OFF` latch requires
a complete bundle. For H configured vCPUs, the checks take O(H) time and
O(1) extra state before reading RAM.

| Assumption | Falsification probe |
| --- | --- |
| Each vCPU owns its in-flight transfer. | Stage an AP's byte read or write, including a consumed input reply with a failed SDK register write. Attempt legacy capture, compare the AP's private context, then restore the complete file and check continued device behavior. |
| The PSCI graph can contain work outside the public bootstrap registers. | Leave `CPU_ON` or `CPU_OFF` queued, acknowledge a bootstrap `CPU_OFF`, or signal `SYSTEM_OFF` on an AP. Require each legacy capture to reject and the full file to preserve the corresponding graph. |
| Resuming the VM releases the legacy terminal gate. | Explicitly wake the VM restored from a `SYSTEM_OFF` file, then capture the running projection. |

On an Apple M4 Max, the parent accepted legacy captures in five states
that each require the complete graph. The witnesses covered the secondary
read, queued start, queued stop, parked bootstrap CPU, and VM shutdown.
The revised signed build passed five native MMIO tests and seven native
PSCI tests. An independent reader checked eight complete files for the
saved PSCI or MMIO owners and the matching online CPU or instruction
state. The Intel HVF build was cross-checked for compilation.

### Native HVF device I/O before guest re-entry

On resume, the VMM services device exits retained by online HVF vCPUs
before entering a vCPU or delivering queued interprocessor requests.
ARM64 owners with a saved input reply or an acknowledged output finish
the register or PC update on the stopped owner. The device sees one
transaction. An already terminal VM preserves its pending transactions.
With GDB attached, the dispatch follows the current debugger resume mask.
The existing checkpoint records carry these states without format changes.
For H vCPUs and R device dispatches, the resume preflight makes at most
O(H × (R + 1)) owner probes with O(1) additional scheduler state.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| A retained peer transaction predates a new bootstrap instruction. | High | Cold-restore two native Apple Silicon vCPUs with a pending PL011 transaction on CPU 1 and a PSCI `SYSTEM_OFF` instruction next on CPU 0. Exercise serial and parallel scheduling. Check the AP's PC, UART contents, and terminal latch. |
| A staged reply or an acknowledged write already changed the device. | High | Inject the register-write failure on the original owner. Verify the next unread UART byte and an intervening control-register write survive resumption. Check that a saved read error is surfaced before CPU 0 advances. |
| Queued INIT and previously recorded terminal exits can coexist with device records. | High | Model an INIT broadcast with two pending inputs and check that both dispatch before INIT. Model a saved terminal exit on a higher-index Intel HVF owner and check that neither a device dispatch nor guest entry occurs. |

The signed physical Apple Silicon baseline at `c27b8125d` entered CPU 0
and latched `SYSTEM_OFF` while CPU 1's retained PL011 read remained pending.
The revised build passed all ten cold-resume cases on the same Apple M4 Max.
The stopped-owner path passes compilation and lint checks for Intel macOS.
A coordinator test covers Intel terminal ordering. Native Intel restore
remains unverified for this change.

### Checkpoint scheduling

With automatic checkpoints configured, the execution record ends with an
8-byte `RAXSCH01` tag and the little-endian, 8-byte retirement count of the
last successful automatic write. Manual capture records the current schedule
position. An automatic capture records the count of its own write, and the
live schedule advances only after that write succeeds. Warm and detached
restore use the saved count for interval and explicit triggers under the
target's configured schedule and output directory. Legacy execution records
use the coordinator's saved retirement count as the starting point. Base-only
records use the base header's instruction count. Files produced with scheduling
disabled omit the suffix. Readers from before this extension reject files that
carry the suffix.

For N physical bytes, R <= 128 regions, M media bytes and K controller-record
bytes, admission and restore are O(N + M + K), plus bounded region lookup O(ceil(N / 65536) log R). Scratch is
O(R + 65536) bytes plus bounded codec windows, resident compressed checkpoint
bytes, detached O(M + K) candidate media/controller state. A second streamed
memory pass commits verified content. Equal readable target chunks retain sparse
backing; dirty bytes are restored, including zero source bytes.

| ID | Assumption and dependency | Stress / falsification probe | Status |
|---|---|---|---|
| R1 | Checkpoint/target compatibility is admitted before mutation. | Wrong geometry/count/profile/private CPU state, malformed frames/bridge/late controller, or a read-only trailing RAM region. Compare every represented owner on rejection and run the same legacy archive against writable RAM. | Owning regressions and ledger receipts. |
| R2 | All live locks precede represented commit. | Four poisoned legacy locks and six PCI locks; exact state comparison and callback invocation count. | Owning regressions and ledger receipts. |
| R3 | Candidate publication has no post-callback validation/allocation. | Callback error leaves bridge/endpoints unchanged; success publishes exact proposed records. | Owning regressions and ledger receipts. |
| R4 | Media restore is detached. | Rename both image sources after constructing the target; compare all restored media/control bytes and original file bytes/protection. | Owning regressions and ledger receipts. |
| R5 | Independent CPU/DMA/mapping writers remain quiescent. | Explicit API contract; actual full-backing VM tests and separate future coordinator requirement. | Full SMP coordinator remains open. |
| R6 | Native setters/resource failures can fail after admission. | Native KVM/HVF transaction evidence is separate; tests do not claim failure rollback for those operations. | Unknown outside tested emulator domain. |
| R7 | A legacy RV64 projection carries no issued UART write. | Restore a clock-only file while a guest store to UART IER awaits dispatch. Rejection must preserve the queue and the live owners. Retry after dispatch must succeed. | RV64 runtime regression. |

High impact: additional backend-private/platform/scheduler state, per-VM clocks,
quiescence, replay and native transactions remain open. Medium impact: all media must fit admitted byte budgets in detached memory.
Low impact: future required components must extend explicit preparation and
publication rather than be silently dropped.

Clock mode/phase/frequency and base-time consistency are admitted before CPU/RAM mutation. A prepared timing object installs the validated fields after the represented data commit. Files without clock state retain the previous elapsed-base behavior. See `checkpoint-clock.md`.

### Halted RV64 harts in legacy projections

The legacy system RV64 backend can halt a hart after reporting a guest
debug exit. Its base checkpoint and projected CPU records now use the
existing emulator halt bit. Complete RV64 records carry the authoritative
halt, interrupt-wait and queued-event state in the private record. A
pre-existing projection with a default halt bit still restores a runnable
hart. The legacy projection format is unchanged.

| Assumption | Falsification probe |
| --- | --- |
| A halted hart stays stopped across file restore. | Execute EBREAK, save and reload both projection forms, and restore on a running or fresh owner. Require a halted exit at the same PC with no retirement. |
| A saved halt preserves the normal explicit wake operation. | Change the stopped PC to the following ADDI, wake the hart, and require execution to update the destination register. Restore the pre-EBREAK running projection and require the original debug exit. |

The base restore on the parent failed the halted-exit check. The regression
uses the legacy RV64 system profile with CLINT disabled. The 377 targeted
RV64 library tests and 67 boot, hart-ID, lift and physical-checkpoint
integration tests passed. Library Clippy passed with warnings denied.

### AArch32 guest waits and reservations in legacy projections

The standalone AArch32 engine and the S3C64xx and S5L8900 adapters use the
existing legacy halt bit for a CPU waiting after a guest wait instruction.
Restoring a projected CPU sets its wait state from that bit and clears the
local exclusive monitor. A false bit in a historical projection clears the
CPU wait flag. Complete checkpoint records carry the source wait state and
reservation in their private CPU data. Capture and restore take constant
time and space per CPU for these fields.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| The projected bit is sufficient to preserve the CPU wait with interrupts quiescent. | High | Execute a guest WFI, restore the projected state, and require no retirement at the following PC until explicit wake. Restore a runnable projection over a waiting target. |
| The destination's exclusive reservation is independent of the source projection. | High | Execute LDREX on the destination immediately before restoring the projected CPU. The following STREX must return failure and leave RAM unchanged. The S3C64xx complete-checkpoint control resumes with the captured reservation and returns success. |
| Historical private records retain authority over the wait state. | High | Restore a private AArch32 record saved during WFI with a default legacy halt bit. Check that the CPU stays stopped at the following PC. |

S3C64xx executes from a separate high RAM mapping. The base format carries
the zero-based RAM prefix, so the base restore test provisions the guest
code on the warm destination. The cold CPU-projection test includes a
physical-memory section. Full peripheral phase and coordinated replay
require the private CPU and platform records.

The parent `c717f9474` failed the wait and reservation probes in all three
backends. The corrected build passed all six regressions and 111 tests
across the three backend suites and the VMM checkpoint suite. LLVM MC
23.0.0git independently assembled the ARM and Thumb witnesses.
