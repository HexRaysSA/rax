# NVMe PRP data transfers

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
PSDT formats other than PRP are explicitly rejected in the current PRP-only
profile;the command's raw flag byte is retained when parsing the64-byte SQE.

Read/Write NLB is zero-based16-bit, so the maximum transfer is
65536*512=33554432 bytes (32MiB). A first offset4092 requires8193 data segments.
Planning requires O(k) time/storage for k pages. Writes stage O(n) source bytes
before committing n media bytes, so a late source error preserves the complete
namespace. Reads copy segments in order;a late destination error can retain
prior guest-memory writes. This is not an atomic DMA/rollback claim.

Completions carry the actual submitting queue ID and its consumed head. Queue
sharing and ring wrap do not infer origin by searching for the first SQ bound
to a CQ. CQ delivery failures, full-queue backpressure, complete interrupt
wiring, SGLs, additional NVM commands, storage-image wiring and checkpoint/media
state remain separate work items.

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
