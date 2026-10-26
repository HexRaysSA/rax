# NVMe and AHCI controller checkpoints

Both controllers provide additive `checkpoint()` and `restore_checkpoint()` APIs.
The result contains a small versioned control record and every logical media
byte. Guest RAM, CPU state, bus mappings and consistent VM quiescence belong to
the caller. These APIs do not themselves create a complete VM checkpoint.

Capture reads the controller's owned state and media. It performs no guest DMA.
Restore decodes and validates the whole record before replacing any live field.
Malformed tags, truncated/trailing input, invalid booleans, queue indices,
associations, profile sizes, alignment, interrupt levels or media metadata return
an error without altering the destination. Restore performs no DMA, queued
command execution, source-file open or host-file mutation.

Restored media are detached in-memory bytes. Guest read-only protection remains
set when captured. Previously persistent writable media become instance-local
until a VM owner explicitly rebinds storage after checking identity and its
external-effect policy. A checkpoint restore must not silently rewrite files or
reissue already completed operations.

## Wire records

All integers use fixed-width little-endian encoding. Boolean bytes are exactly
0 or 1. Each record's eight-byte tag identifies its format revision.

| Controller | Tag | Control bytes | Captured private state |
|---|---|---|---|
| NVMe | `RAXNVM01` | 353 | Base, media geometry/protection, CC/CSTS/INTMS/AQA/ASQ/ACQ, queue allocation/feature lock, both admin queues, five SQ/CQ array entries each, every head/tail/phase/CQ association and per-CQ IEN |
| AHCI | `RAXAHC01` | 112 | Base, media geometry/protection, GHC/IS, slot profile, interrupt level, CLB/FB, every represented port register, present/fatal/current/next slot and the retained task-file command/device/LBA/count |

NVMe has four allocated I/O queue IDs; index zero in the I/O arrays stays
inactive. Active admin sizes are 2..4096; active I/O sizes are 2..256. Active heads
and tails must be below queue size, bases are 4 KiB aligned, SQs refer to active
CQs and CQ identity is preserved. AHCI preserves stopped, running and fatal
engines, including pending CI while ST is clear and a fatal slot 31. Its sticky
interrupt layers remain distinct; global masking does not erase port status.

Media capture allocates a fallible exact-size copy, bounded by 64 GiB. Empty and
partial-sector in-memory media preserve the existing byte-vector constructors'
semantics. File-backed image admission remains stricter: nonempty, sector-aligned
raw files with an explicit limit. Restore moves the supplied media bytes into the
controller and does not allocate another media-sized copy.

For p captured media bytes, capture costs O(p) time and additional space plus a
constant control record. Restore uses constant control work and moves the media
allocation. It does not scan guest RAM. All pointer references in queues/FISes
refer to the caller's separately captured guest RAM; importing a record does not
validate those RAM contents by executing them.

## Continuation and malformed-input evidence

The complete `controller_checkpoint` owner runs 19 tests. They cover exact state
roundtrips, unread CQ/interrupt state, CQ backpressure with an unconsumed SQ entry,
phase/feature-lock/mask retention, AHCI stopped and fatal commands, task-file and
PRDBC state, readonly protection, detached host-file behavior, empty/partial-sector
media and every truncated prefix of both control formats. Corruption checks
verify failure leaves all destination fields and media unchanged and causes no
DMA. A queued write executes only after the appropriate CQ acknowledgement or
explicit AHCI start; a previously completed write is not replayed with newer RAM.

The independent parser runs after a current library build:

```sh
python3 tools/storage/controller_oracle.py --repo . \
  --work-dir /path/to/empty-evidence-directory \
  --target-dir /path/to/cargo-target
```

It parses nine actual captured/restored fixtures and checks three continuation
events independently. It compares 4,426 control bytes, 73,728 media bytes and
2,359,296 guest-RAM bytes. All raw records, source/library hashes, binaries and
outputs are retained. This checks the new state format and continuation contract;
existing QEMU storage oracles separately guard controller command semantics.

## Rejected admin-queue hypothesis

The state review initially assumed CAP.MQES also limited admin queues. The
[primary NVMe 1.4c specification](../specifications/nvme/NVM-Express-1_4c-2021-06-28.pdf),
Figure 81 and section 4.1.3, disproves that assumption: MQES limits I/O queues;
admin queues independently support up to 4096 entries. The proposed production
restriction was reverted. The original admin-enable function is byte-identical
to its predecessor.

The failed experiment (45 controls passed, two incorrect tests failed) is retained
as a rejected assumption, not a product defect. The corrected complete admission
owner passes all 47 tests against both the original and current controller.
It exercises all 4096 AQA sizes on each side with nonoverlapping queue extents.
The new checkpoint format separately validates the 4096 admin and 256 I/O bounds.

## Assumption register and remaining integration

| ID | Assumption and dependent result | Stress/falsification probe | Status |
|---|---|---|---|
| S1 | Control records contain every owned field that affects these controllers. | Exact field parser, roundtrip equality, pending CQ/SQ, fatal/next slot, masks, task file and readonly continuation. A missing field that changes continuation fails. | Locally tested. |
| S2 | Guest RAM and VM quiescence are external to the device API. | Restore records zero DMA even with pending work; continuation uses a separately cloned RAM image. | Explicit caller contract; full VM barrier remains open. |
| S3 | Restore must not reissue commands or mutate host backing implicitly. | Backpressure and stopped/fatal commands, changed source RAM, detached real-file test. Any replay before an explicit event fails. | Locally tested. |
| S4 | Malformed control data must not partially change the destination. | Every prefix, trailing byte, boolean, slot, alignment, queue association and media mismatch. Exported destination before/after must match. | Locally tested. |
| S5 | Admin and I/O queue size limits are different. | Primary Figure 81/4.1.3; all AQA sizes, actual old controller and 4096-entry checkpoint. Initial contrary hypothesis and its failed tests are retained. | Corrected; no admin-enable product change. |
| S6 | Media readonly protection survives detachment; live persistent rebinding is separate. | RO guest writes, actual source-file bytes and restored COW behavior. | Locally tested; VM storage rebinding/replay integration remains open. |

High impact: runtime/container capture of all controllers/media, other PCI models,
PCI configuration, full multi-CPU/private/platform state, consistent quiescence,
replay and native/boot validation remain integration requirements. Medium impact:
media copies are bounded but fully resident; persistent rebinding must check the
intended source identity before enabling host writes. Low impact: future queue or
port profile changes require a new explicit record revision.

The group requires complete native/translated owner and library inventories,
C API, build, Clippy, formatting, CI selection and all independent storage/state
comparisons before commit. Partial or self-comparison evidence cannot substitute
for the independent field/continuation parser or the full final gates.

The [PCI bridge checkpoint](pci-checkpoints.md) separately preserves raw configuration, BAR profiles and ordered routing; endpoint-private state remains independently owned.
