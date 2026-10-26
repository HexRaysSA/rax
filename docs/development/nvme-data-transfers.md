# NVMe data transfers and queue state

The controller implements one in-memory namespace with 512-byte logical blocks,
4 KiB host pages (`CAP.MPSMIN=MPSMAX=0`), at most four I/O SQs and four I/O CQs,
and at most 256 entries per I/O queue (`CAP.MQES=255`). Admin queues support
2-4096 entries. All wire structures and registers use little-endian encoding.

The architectural source is [NVM Express Base Specification 1.4c](../specifications/nvme/NVM-Express-1_4c-2021-06-28.pdf).
[Reference provenance](../specifications/nvme/PROVENANCE.md) identifies the exact
PDF and QEMU source snapshots. The executed QEMU 11.1.2 binary is distinct from
the pinned explanatory QEMU 11.1.0 source; binary/source identity is unverified.

## PRPs and transfer effects

PCIe Admin commands use PRPs. NVM commands select PRPs with PSDT=0 and SGLs with
PSDT=1/2. PSDT=3 is reserved. The namespace has no separate metadata, so its
metadata pointer is unused. SQEs retain their 64-byte wire format.

| PRP pointer | Alignment | Page offset |
| --- | --- | --- |
| First data pointer | 4 bytes | Permitted |
| Direct second data pointer | 4096 bytes | Zero |
| First list pointer in command | 8 bytes | Permitted |
| Data pointer in a list | 4096 bytes | Zero |
| Subsequent list pointer | 4096 bytes | Zero |

The final list slot is a link only if additional data pages remain. Planning
resolves every list entry before payload DMA. Physical page zero is valid.
Physical list/data pages may repeat: the command's finite byte count bounds
traversal. After at most one initial link without data, each further link follows
511 data entries. Invalid offsets report generic status 0x13; failed metadata
or payload access reports 0x04. Identify uses the same PRP planner.

NLB is zero-based and 16 bits wide:

```text
maximum blocks = 65535 + 1 = 65536
maximum bytes  = 65536 * 512 = 33554432 bytes = 32 MiB
```

A first offset of 4092 bytes requires 8193 data extents. PRP planning takes O(k)
time and storage for k pages. Writes stage O(n) source bytes before committing
n media bytes, preserving media on a late source failure. Reads write extents
in order; a late destination failure can leave earlier writes visible. No DMA
rollback is provided.

## PCIe SGL profile

Identify Controller SGLS is `0x00040001`: byte-granular Data Block, Segment and
Last Segment descriptors, including buffers larger than the requested payload.
Keyed, Bit Bucket, transport and offset forms are not advertised.

The planner validates the complete metadata chain before payload DMA, including
metadata following sufficient data capacity. Null data entries and finite
data-less intermediate segments remain valid. Segment addresses require
8-byte alignment and lengths must be nonzero multiples of 16. A link must be
the final descriptor in a non-final segment. A Last Segment cannot link onward;
a Segment must link onward.

Address/length arithmetic uses 128 bits. An exclusive endpoint of 2^64 is valid;
a larger endpoint reports Data SGL Length Invalid. Relevant generic statuses:

| Condition | Status |
| --- | --- |
| Metadata or payload DMA failure | 0x04 |
| Invalid segment structure | 0x0d |
| Misplaced link | 0x0e |
| Insufficient capacity or address overflow | 0x0f |
| Unsupported descriptor type/subtype | 0x11 |

For d descriptors, m metadata segments and k retained payload extents, planning
costs O(d + m log m) time and O(m + k) storage. A deterministic set of entered
(address, length, type) views detects cycles iteratively. Metadata is assumed
immutable while the controller owns the command. No payload write occurs until
validation completes. Metadata size is not constrained by the payload size or
replaced by an arbitrary progress cutoff.

## Queue admission and feature state

I/O queue identifiers are 1-4. Duplicate creation preserves the existing queue.
Queue bases require page alignment; physical page zero is valid. `CAP.CQR=1`
requires physically contiguous queues. I/O SQs cannot bind to admin CQ0 or an
uncreated CQ.

| Admission failure | Combined SCT/SC |
| --- | --- |
| In-range CQ not created | 0x100 |
| Invalid, duplicate or admin queue identifier | 0x101 |
| Invalid queue size or I/O entry-size field | 0x102 |
| Unsupported interrupt vector | 0x108 |
| Delete CQ while an SQ remains bound | 0x10c |
| Save an unsaveable Number-of-Queues feature | 0x10d |
| Noncontiguous queue in the contiguous-only profile | 0x02 |
| Misaligned queue base | 0x13 |
| Set Number-of-Queues after queue creation | 0x0c |

I/O CQ creation requires `CC.IOCQES=4`; I/O SQ creation requires `CC.IOSQES=6`.
Admin enable remains independent of those fields, permitting initialization to
configure I/O entry sizes before creating the corresponding I/O queues. Admin
queues require at least two entries. ASQ/ACQ reserved low bits read as zero.

The fixed four-queue allocation is retained: section 5.21.1.7 permits allocating
more queues than requested. A request field of 0xffff is invalid. Once any I/O
queue has been created, deleting every queue does not unlock Set Features;
Controller Reset does. Get Features returns the fixed current/default/saved
allocation and reports changeable, nonsaveable, global capabilities for this
feature. Reserved selectors 4-7 are explicitly rejected by the local profile;
the specification does not define a supported result for those selectors.
Other feature identifiers still require separate implementation work.

## Completion backpressure, DMA failure and interrupts

A queue of n slots is full at n-1 occupied entries. Dispatch waits for space in
the bound CQ, preserving unread CQEs and pending SQ entries. CQ head progress
resumes bound SQs without another tail notification, including shared CQs.
Acknowledgement cannot pass the published tail. Dispatch costs O(q + c) for q
represented SQs and c completed commands; ring metadata is O(1) per queue.

CQE DMA precedes tail/phase publication. A failed SQ fetch sets CFS without
consuming the command. A failed CQE write sets CFS after command consumption,
preserves the unpublished CQ position, and stops execution until reset. Media
or guest-memory effects can already exist. An adapter returning failure after a
partial write can leave partial CQE bytes. These failure policies do not provide
rollback or retry executed commands.

`take_interrupt()` exposes the single pin/vector-zero level derived from all
active, interrupt-enabled CQs with unacknowledged entries and INTMS bit 0.
Acknowledgement or masking deasserts it; unmasking a pending CQ reasserts it.
`clear_interrupt()` retains its callable signature and does not acknowledge
guest entries. Native IRQ routing and MSI/MSI-X delivery are separate work.

Controller Reset clears represented CC, CSTS, INTMS and internal queue state,
retaining AQA, ASQ, ACQ and namespace bytes. It abandons stalled work; re-enable
does not recreate I/O queues.

## Validation and independent reference limits

Run the complete registered owners:

```sh
cargo +stable test --test nvme_prp --test nvme_sgl --test nvme_queues --test nvme_admission --test nvme_commands
```

| Owner | Tests | Principal coverage |
| --- | --- | --- |
| nvme_prp | 32 | 160 scattered layouts, 1024 first offsets, 32 MiB, repeated list pages, DMA boundaries, Identify, CQ origin |
| nvme_sgl | 50 | 253 type/subtype cells, null/data-less chains, 512 extents, 32 MiB, overflow and DMA boundaries |
| nvme_queues | 48 | 3072 seeded ring events, shared CQs, multiple IRQ sources, masks, fatal DMA and reset |
| nvme_admission | 45 | 131072 size admissions, 8190 offset admissions, identifiers, entry sizes and feature lifetime |
| nvme_commands | 49 | Compare/zeroes/DSM, 32 MiB, 256 ranges, DMA faults, namespace/FUSE admission and Identify consistency |

Existing fixtures now program valid I/O entry sizes, publish actual CQEs before
acknowledging them, and use 0xfffe rather than reserved 0xffff for the successful
maximum queue request. Separate tests retain each invalid-input regression.

Each reference tool requires QEMU, LLVM and an already built RAX library:

```sh
python3 tools/nvme-diff/admission_oracle.py --repo . \
    --work-dir /path/to/empty/evidence --llvm-bin /path/to/llvm/bin \
    --target-dir /path/to/built/cargo-target
```

The same options apply to `prp_oracle.py`, `sgl_oracle.py` and `queue_oracle.py`.
The immutable helper library supplies shared memory/device traits; owning tests
and comparators compile the current device sources directly. Separate full
engine gates validate the normal product. Source/library hashes, commands,
versions, raw inputs, guest ELFs, media and outputs are retained. Missing frames,
timeouts, failed tools, source changes and unexpected differences fail validation.
`--reference-only` is explicitly labeled and does not establish product agreement.

| Probe | Fresh guests | Executed commands | Recorded comparison |
| --- | --- | --- | --- |
| PRP | 6 | 18 | 8448000 payload bytes and 18 full CQEs |
| SGL | 9 | 27 | 12288 payload bytes and 27 full CQEs |
| Queue/pin | 7 | 917 | 153168 complete frame bytes, including 917 full CQEs |
| Admission | 14 | 54 | 1200 frame bytes; 24 DNR and 5 declared policy differences retained |

The QEMU PRP profile uses MDTS=9 (2 MiB). Actual MDTS=0/10 attempts were rejected
by its host IOV limit. Local tests establish the larger 32 MiB and failed-DMA
cases, rather than attributing them to independent device execution.

QEMU SGLS is `0x00080001`, differing from RAX's selected primary profile. QEMU
accepts the oversized descriptor exercised here despite its unset excess-length
bit. It accepts a data-only Segment terminus and separately rejects a valid
data-less intermediate segment and one finite three-segment layout. Raw inputs
remain retained; these cases are local primary-source regressions. The pinned
source labels its per-segment progress restriction as not strictly compliant.
A reused descriptor pointer is a possible explanation for the other failure;
installed-binary/source identity is unverified.

Admission retains every raw CQE. QEMU returns 0x100 for Delete-CQ0, whereas
Figure 161 specifies 0x101. QEMU returns current values for reserved selectors
4-7, while the selected local profile rejects them. DNR policy differs on
24 commands. The comparator verifies these exact differences separately from
all other completion fields; its result does not claim full CQE equivalence.

Native NVMe hardware, full machine/PCI routing, queue arbitration, remaining
features and commands, storage images and complete checkpoint/media/private
state remain pending. Device-local source tests and QEMU guests do not close
those integration requirements.

## Optional NVM command data paths

`src/devices/nvme/nvm.rs` owns Read, Write, Flush, Compare (0x05), Write Zeroes
(0x08) and Dataset Management (0x09). Identify ONCS is 0x000d. Fused command
support is not advertised, and either fused member is rejected before payload
DMA or media mutation. The single namespace has no metadata or end-to-end PI.

Compare stages the complete PRP/SGL source before comparing against media;
a mismatch reports media/data integrity status 0x285 without modifying either
source or media. A late source fault reports 0x04 even if an earlier byte
mismatches: that precedence is an explicit local policy. Compare requires
PRACT=0; PRCHK is ignored for this no-PI namespace. Write Zeroes requires
PRCHK=0 and performs no payload DMA. Both DEAC modes return zero, and all
LR/FUA/DEAC/PRACT combinations admitted by this selected profile are covered.
Invalid protection settings report command-specific status 0x181.

The controller advertises no volatile write cache and explicit broadcast Flush
support (`VWC=6`). The absent cache's Set/Get feature returns Invalid Field.
Flush of namespace 1 or broadcast succeeds without data transfer. Other invalid
namespace IDs return generic status 0x0b. The in-memory namespace is the logical
media model; these results do not establish host filesystem durability.

DSM NR is zero-based, with at most 256 descriptors of 16 bytes each. A descriptor's
length is a one-based block count. Zero-length and out-of-range descriptors are
ignored by the selected advisory policy. With AD clear, IDR/IDW are ignored
without consulting the range buffer. With AD set, every metadata/source read
completes before any range is cleared. Valid ranges are sorted and coalesced,
then cleared; repeated/overlapping ranges do not multiply work on the same media.
For r ranges and u bytes in their union, this costs O(r log r + u) time and O(r)
metadata storage. All attribute combinations are admitted. Namespace DLFEAT=9
reports zero after deallocation and support for Write Zeroes DEAC. DULBE is not
advertised, and no separate deallocation-error bitmap is introduced.

The command reference tool uses the same options as the other probes:

```sh
python3 tools/nvme-diff/commands_oracle.py --repo . \
    --work-dir /path/to/empty/evidence --llvm-bin /path/to/llvm/bin \
    --target-dir /path/to/built/cargo-target
```

Its sixteen fresh guests execute 39 I/O commands and retain 214256 frame bytes,
262144 complete media bytes and 212992 final Read bytes. Every completion field
is checked, with six DNR differences and one namespace-profile status difference
reported separately. Raw QEMU ONCS/VWC/DLFEAT/SGLS/NN are retained; their values
are 0x075d/7/9/0x80001/256, compared with RAX's 0x000d/6/9/0x40001/1. NSID 2 is
therefore an inactive in-range identifier in QEMU and outside RAX's advertised
maximum. These results do not claim complete capability equivalence.

DSM is advisory: a controller may preserve requested blocks instead of
choosing to deallocate them. In this corpus QEMU preserves five sets of small
requested ranges that RAX clears. Both complete namespace images are checked
against the primary per-block contract: mandatory Write Zeroes data must be
zero; an advisory block may remain unchanged or become zero; unrelated blocks
must remain unchanged. Each actual final Read must equal its own complete
namespace image. No arbitrary byte mask is used. The raw differing media and
outputs remain retained, and five advisory differences are reported rather than
counted as exact media matches. Aligned DSM cases establish actual independent
deallocation as well as command completion.

A controlled `--discard ignore` run uses identical SQEs, guest ELFs and CQEs.
Only the drive option changes. Four aligned cases change media when discard is
set to `unmap`; the earlier small ranges remain unchanged in both configurations.
The probe defaults to `--discard unmap`. This is evidence for the executed cases,
not a claim about every host filesystem's discard granularity. The initial
namespace-profile assumption and discard-configuration observations are retained
as reconciled evidence rather than erased failed iterations.

The full local owner has 17 new cases plus 32 existing controls. It checks
32 MiB Compare/Write Zeroes, all 256 DSM descriptors, final-descriptor effects,
all attribute combinations, fused rejection, invalid namespaces, exact bounds,
metadata faults and the advertised fields. The unchanged parent fails all
17 new cases and its independent command completions fail in all 16 guests.
The seventeen backend/storage owners execute in both explicit CI selections.

Queue arbitration, remaining feature identifiers, other optional NVM commands,
full PCI routing, storage-image durability and complete checkpoint/private/media
state remain separate work. The commands above are implemented, not represented
by successful stubs.
