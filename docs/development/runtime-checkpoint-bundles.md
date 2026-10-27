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

For N physical bytes, R <= 128 regions, M media bytes and K controller-record
bytes, admission and restore are O(N + M + K), plus bounded region lookup O(ceil(N / 65536) log R). Scratch is
O(R + 65536) bytes plus bounded codec windows, resident compressed checkpoint
bytes, detached O(M + K) candidate media/controller state. A second streamed
memory pass commits verified content. Equal readable target chunks retain sparse
backing; dirty bytes are restored, including zero source bytes.

| ID | Assumption and dependency | Stress / falsification probe | Status |
|---|---|---|---|
| R1 | Checkpoint/target compatibility is admitted before mutation. | Wrong geometry/count/profile/private CPU state, malformed frames/bridge/late controller; every observed byte/record must remain unchanged on rejection. | Owning regressions and ledger receipts. |
| R2 | All live locks precede represented commit. | Four poisoned legacy locks and six PCI locks; exact state comparison and callback invocation count. | Owning regressions and ledger receipts. |
| R3 | Candidate publication has no post-callback validation/allocation. | Callback error leaves bridge/endpoints unchanged; success publishes exact proposed records. | Owning regressions and ledger receipts. |
| R4 | Media restore is detached. | Rename both image sources after constructing the target; compare all restored media/control bytes and original file bytes/protection. | Owning regressions and ledger receipts. |
| R5 | Independent CPU/DMA/mapping writers remain quiescent. | Explicit API contract; actual full-backing VM tests and separate future coordinator requirement. | Full SMP coordinator remains open. |
| R6 | Native setters/resource failures can fail after admission. | Native KVM/HVF transaction evidence is separate; tests do not claim failure rollback for those operations. | Unknown outside tested emulator domain. |

High impact: additional backend-private/platform/scheduler state, per-VM clocks,
quiescence, replay and native transactions remain open. Medium impact: all media must fit admitted byte budgets in detached memory.
Low impact: future required components must extend explicit preparation and
publication rather than be silently dropped.

Clock mode/phase/frequency and base-time consistency are admitted before CPU/RAM mutation. A prepared timing object installs the validated fields after the represented data commit. Files without clock state retain the previous elapsed-base behavior. See `checkpoint-clock.md`.
