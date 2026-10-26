# NVMe data transfers

The controller advertises a4KiB host-page profile (`CAP.MPSMIN=MPSMAX=0`).
PRP1, direct PRP2 and chained PRP lists use NVMe1.4c section4.3/Figures108-111.
Unsupported nonzero page sizes fail enable with CFS and no armed queues.

| Pointer | Required alignment | Page offset |
| --- | --- | --- |
| First data pointer | 4 bytes | Permitted |
| Direct second data pointer | 4096 bytes | Zero |
| First list pointer in command | 8 bytes | Permitted |
| Data pointer in list | 4096 bytes | Zero |
| Subsequent list pointer | 4096 bytes | Zero |

The final list slot is a link only when additional data pages remain. The walker
resolves every list entry before payload DMA. It does not impose uniqueness on
physical list/data pages:the command's finite byte count bounds traversal, even
if a list page is referenced again. After at most one offset-list link, each
further link follows511 data entries. Address arithmetic is checked;physical
page zero is admitted. Invalid offsets report generic status0x13, and failed
metadata/DMA accesses report0x04. Identify uses the same scatter/gather planner.
PCIe Admin commands use PRPs. NVM commands select PRPs with PSDT0 and SGLs
with PSDT1/2;PSDT3 is reserved. The namespace has no separate metadata, so its
metadata pointer is unused. The64-byte SQE wire format is unchanged.

Read/Write NLB is zero-based16-bit, so the maximum transfer is
65536*512=33554432 bytes (32MiB). A first offset4092 requires8193 data segments.
Planning requires O(k) time/storage for k pages. Writes stage O(n) source bytes
before committing n media bytes, so a late source error preserves the complete
namespace. Reads copy segments in order;a late destination error can retain
prior guest-memory writes. This is not an atomic DMA/rollback claim.

Completions carry the actual submitting queue ID and its consumed head. Queue
sharing and ring wrap do not infer origin by searching for the first SQ bound
to a CQ. Native interrupt wiring, additional NVM commands, storage-image wiring
and complete checkpoint/media state remain separate work items.

Run the complete registered device target:

```sh
cargo +stable test --test nvme_prp -- --test-threads=4
```

Its32 tests execute the production NVMe source:17 existing controls plus15
regressions. The unchanged parent source fails14 and passes18. Coverage includes
160 scattered layouts in both directions, all1024 dword-aligned first offsets,
list links, physical zero, malformed later entries, DMA error boundaries,
split Identify, PSDT/page-size admission, and completion identity/head tracking.
The32MiB command compares every returned byte and bounds metadata/DMA calls.

The independent bare-metal probe configures an actual QEMU PCI NVMe controller:

```sh
python3 tools/nvme-diff/prp_oracle.py --repo . \
    --work-dir /path/to/empty/evidence --llvm-bin /path/to/llvm/bin \
    --target-dir /path/to/built/cargo-target
```

It uses an already built RAX library for the shared `Mem`/`MmioDevice` contracts;
the owning target and comparator compile the exact current production NVMe
source, with source/library hashes checked. No expectation is generated from
RAX behavior. Six fresh device/disk instances execute18 I/O commands. All
8448000 read/read-back bytes and18 complete CQEs must match the production
device. Original reference records, guest sources/ELFs, media bytes, commands,
versions, timings and hashes remain in the owned evidence directory. Missing
records, failed commands, timeouts, wrong completion metadata, source mutation
or mismatches fail the probe. `--reference-only` skips product comparison and
is explicitly labeled in its manifest.

QEMU11.1.2 on this host has IOV_MAX1024. Its source requires
`(2^MDTS)+1 <= IOV_MAX` and disallows MDTS0, so MDTS9 permits a2MiB reference
command. This reference does not establish the32MiB local case or native NVMe
hardware behavior. The full primary-source local contract retains those tests.

Primary source:NVM Express Base Specification1.4c section4.3, generic status
Figure128 and CC.MPS definition. Copyright2007-2021 NVM Express,Inc.
[Official specification](https://www.nvmexpress.org/wp-content/uploads/NVM-Express-1_4c-2021.06.28-Ratified.pdf).


## PCIe SGL profile

Identify Controller SGLS is `0x00040001`:byte-granular Data Blocks, Segment and
Last Segment descriptors, and buffers larger than the command's requested data.
Keyed, Bit Bucket, transport and offset subtypes are not advertised. PCIe Admin
commands retain their mandatory PRP format;NVM data dispatch admits PSDT1/2.

The planner validates the full metadata chain before payload DMA, including
metadata after sufficient data has already been described. Zero-length data
entries and data-less intermediate segments remain valid. Segment addresses
must be8-byte aligned and lengths nonzero multiples of16. Links occur only in
the last descriptor of a non-final segment. A Last Segment cannot contain a
further link. A non-final Segment must link onward. This last rule follows the
primary type definition;QEMU accepts a data-only terminus marked non-final,
which is retained as a separate structural discrepancy.

Address/length endpoints are checked in128-bit arithmetic:an exclusive endpoint
of2^64 is representable, while larger endpoints return Data SGL Length Invalid.
Unsupported types/subtypes return0x11;invalid segment structure returns0x0d;
a misplaced link returns0x0e;insufficient capacity/range overflow returns0x0f.
Failed metadata/DMA access returns0x04. Source writes retain the staging policy
above;destination reads retain their explicit partial-write policy.

For d descriptors, m metadata segments and k retained data extents, planning
costs O(d+m*log(m)) time and O(m+k) storage. A deterministic set of entered
(address,length,type) views detects cycles without recursion. Metadata remains
stable while a command is owned by the controller;no payload writes occur until
validation finishes. This admits finite data-less links without imposing an
incorrect per-segment data-progress requirement. Command metadata can be larger
than the payload;the implementation does not replace that domain with MDTS.

```sh
cargo +stable test --test nvme_sgl -- --test-threads=4
python3 tools/nvme-diff/sgl_oracle.py --repo . \
    --work-dir /path/to/empty/evidence --llvm-bin /path/to/llvm/bin \
    --target-dir /path/to/built/cargo-target
```

The complete owner executes50 tests:32 PRP/device controls and18 SGL tests.
PSDT1/2 are now covered as valid SGL formats;the former PRP-only format rejection
control is restricted to reserved PSDT3. Tests include253 unsupported type/
subtype cells,32 unaligned-address/mode cells in both directions, nulls,
oversized buffers, a512-entry metadata array spanning pages,32MiB Read/Write,
cycles, exact64-bit range boundaries and late DMA errors.

Nine fresh QEMU devices execute27 I/O commands. Every12288 read/read-back byte
and27 complete CQEs must match the current production device. The first eight
corpora remain byte-identical when the512-entry case is added. Source, helper
library, raw media, guest ELF, commands and reference outputs are retained and
hashed. The tool executes the complete50-test owner before the raw comparison.

QEMU's raw SGLS is `0x00080001`, while RAX's selected primary contract is
`0x00040001`. Their common byte-granular data behavior is compared;the raw words
are retained and full capability equivalence is not claimed. QEMU accepts the
single oversized descriptor exercised here despite its unset excess-length bit.
It separately rejects a valid data-less intermediate segment and one finite
three-segment shape with status0x0d/DNR. The pinned QEMU source labels its
per-segment progress restriction as not strictly specification-compliant.
A retained pointer into a reused descriptor array is a possible explanation for
the three-segment failure;installed-binary/source identity is not asserted.
These exact failing inputs remain local primary-source regressions. Another
three-segment layout is included in the shared passing corpus.

Primary source:NVMe1.4c section4.4/Figures112-119, SGLS Figure251, and PCIe
PSDT rules in Figure105. Native NVMe hardware, optional SGL types, metadata
namespaces, complete interrupt/queue error wiring, additional NVM commands,
storage images and complete checkpoint state remain separate work items.

## CQ backpressure, fatal DMA and pin interrupt level

NVMe 1.4c section4.1.2 reserves one empty ring entry: a queue of n slots is
full with n-1 occupied entries. The controller executes a pending command only
when its bound CQ has space. It preserves unread CQEs and resumes submitted
work when the host advances that CQ's head, including multiple SQs sharing it.
The host cannot acknowledge more entries than the controller has published.
Each dispatch pass is O(q+c) for q represented SQs and c completed commands;
per-queue ring metadata is O(1). No pending command is retried after a fatal
completion-DMA failure.

CQE DMA precedes publication of the CQ tail/phase. A failed SQ fetch sets CFS
without consuming the command. A failed CQE write sets CFS after consuming the
executed command, preserves the unpublished CQ position, and stops further
execution until reset. Media or guest-memory effects of that command can already
exist; no rollback is claimed. A memory adapter that partially writes before
returning failure can also leave a partial CQE. Failed DMA injection is tested
locally; the reference guests do not emulate host-memory bus faults.

`take_interrupt()` exposes the single pin/vector-zero level, derived from all
active interrupt-enabled CQs with unacknowledged completions and INTMS bit0.
CQ acknowledgement or masking deasserts the level; unmasking a pending CQ
reasserts it. `clear_interrupt()` retains its callable signature and does not
consume guest CQ entries. Nonzero Create-CQ interrupt vectors return command-
specific Invalid Interrupt Vector (0x108). Native MSI/MSI-X delivery and machine
IRQ routing remain separate work.

A Controller Reset clears CC, CSTS, INTMS and internal queue state, retaining
AQA, ASQ, ACQ and namespace bytes (NVMe 1.4c section7.3.2). Stalled work is
abandoned; re-enabling does not resurrect deleted I/O queues.

```sh
cargo +stable test --test nvme_queues -- --test-threads=4
python3 tools/nvme-diff/queue_oracle.py --repo . \
    --work-dir /path/to/empty/evidence --llvm-bin /path/to/llvm/bin \
    --target-dir /path/to/built/cargo-target
```

The complete owner has48 tests:32 existing PRP/device tests and16 queue tests.
A seeded independent ring model checks3072 event steps across sizes2,3,4,7,64
and256. Separate cases exercise admin CQ saturation, shared CQs, multiple IRQ
sources, source/completion DMA faults, reset state, invalid acknowledgements and
unsupported interrupt vectors. The old doorbell fixture acknowledged an empty
CQ; it now publishes two real completions first. Invalid acknowledgement is
retained as a distinct regression.

Seven fresh QEMU PCI controllers execute917 Flush commands, using CQ sizes2,
3,4,7,16 and64 with both enabled/disabled interrupts. All917 full CQEs, complete
unread-ring snapshots and PCI Interrupt Status observations are compared:
153168 raw frame bytes, including mask/unmask and reset. No fields are projected
out. RAX's choice to defer execution while its CQ is full is an implementation
schedule; the comparison observes CQ/interrupt state, not pending-command media
mutation. Native hardware and full controller/PCI integration are unverified.
