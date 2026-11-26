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
