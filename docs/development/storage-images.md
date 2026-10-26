# Raw images and device media

The shared `BlockImage` backend attaches raw files to virtio-blk, NVMe and AHCI.
The existing constructors that take `Vec<u8>` retain their behavior and capacity
rules. `with_image` is additive on all three controllers. For example:

```rust,no_run
use rax::devices::virtio::{blk::VirtioBlk, block_image::{BlockImage, ImageMode}};
let image = BlockImage::open("disk.raw", ImageMode::CopyOnWrite, 4 * 1024 * 1024 * 1024)?;
let device = VirtioBlk::with_image(image);
# Ok::<(), std::io::Error>(())
```

| Mode | Guest modifications | Source file | FLUSH |
|---|---|---|---|
| `ReadOnly` | Rejected | Preserved | No pending host writes |
| `ReadWrite` | Written through | Updated before command success | Synchronizes the opened file; errors propagate |
| `CopyOnWrite` | Instance-local memory | Preserved | No source-file publication |

Images are nonempty, regular files whose length is a multiple of 512 bytes.
Opening requires an explicit byte budget, at most 64 GiB. The backend loads all
image bytes into memory in bounded chunks; resident storage remains O(image
length). It rejects empty, partial-sector, oversized and changing-length input.
No image is implicitly created, padded or resized. COW is an instance-local copy;
it is not an on-disk overlay format or lazy paging implementation.

Persistent images retain a nonblocking exclusive file lock. Read-only/COW loads
hold a shared lock while capturing their bytes and then release the descriptor.
Locks coordinate cooperating processes and aliases, including hard links; they
cannot exclude host programs that ignore advisory locking. A loaded read-only
or COW instance remains a frozen byte view if the source is later changed.
Persistent writes and FLUSH reject a changed file length. Arbitrary concurrent
host content changes and path replacement are outside this attachment contract.

WRITE, zeroing and deallocation commands validate metadata and stage guest
sources as before. Media mutation then uses the same backend for all three
controllers. Successful persistent writes include `sync_all`, so ordinary writes
and NVMe FUA both receive write-through completion. The existing NVMe VWC=0
profile remains valid: no new volatile write-cache feature is advertised. NVMe
reports namespace write protection in NSATTR and returns generic status 20h for
prohibited modifications. Host write/flush failures return media status SCT2/SC80h
(280h). AHCI reports a task-file error and retains the failed command for explicit
recovery. Virtio reports IOERR and advertises RO when the image is read-only;
clearing its software override does not disable image-level protection.

A host write can fail after accepting a prefix. The byte view tracks every
accepted host write before an error is returned. It does not claim atomic host
rollback. An interrupted write resumes; short writes continue without duplicating
bytes; zero progress is an error. A synchronization failure reports failure even
if all bytes reached the host cache. Dropping a COW instance never commits it.
Physical power-loss behavior remains a filesystem/device property.

Opening takes O(n) time and resident memory for n image bytes. A k-byte write or
zero operation takes O(k) transfer work plus host synchronization; zeroing uses
64 KiB scratch space. File-system synchronization latency has no fixed bound
in this interface. The locking API uses standard-library functionality stable
since Rust 1.89; [archived API source and licenses](../specifications/rust/PROVENANCE.md)
identify the actual validation toolchain.

## Evidence

`cargo test --test storage_images` runs 24 public-API and device-command tests.
They exercise all three modes, exact byte preservation, capacity/budget and range
boundaries, conflicting locks/aliases, changed host capacity, read-only reads and
writes, NSATTR, persistent command completion, COW guest writes and host FLUSH
failures. Four shared media-module fault tests check accepted prefixes, immediate
errors, interrupted/short writes and zero progress. They also execute in the
library and both owning virtio binaries (46 indirect tests and 66 range tests).
The complete core backend/device selection contains 22 targets and 531 tests on
the two local macOS architectures.

The independent operation model runs after a current library build:

```sh
python3 tools/storage/image_oracle.py --repo . \
  --work-dir /path/to/empty-evidence-directory \
  --target-dir /path/to/cargo-target
```

A seeded Python byte/file model validates every retained operation from a Rust
program using the public API. The three modes execute 1,548 operations, including
543 expected errors. Every intermediate cache and source-file byte is compared:
50,534,400 bytes in total. Inputs, binaries, complete raw records, final media and
source/library hashes are retained. Explicit host truncation operations are
separate from guest writes in the stream. Existing NVMe, AHCI and virtio QEMU
comparisons separately guard unchanged controller wire/data behavior.

## Assumption register

| ID | Assumption and dependent result | Stress/falsification probe | Status |
|---|---|---|---|
| I1 | Raw-image capacity is sector-aligned and explicitly bounded. | Empty/partial/oversized/missing/directory input, invalid budgets, exact end and overflow. Any padding, growth or source mutation falsifies admission. | Locally tested. |
| I2 | COW/readonly are frozen loaded instances; persistent mode retains its file. | Three modes, independent concurrent instances, external source change after load, actual controller commands. Any COW guest write reaching the source fails. | Locally tested. |
| I3 | Advisory locks coordinate cooperating users. | Conflicting read/write opens, lock release and hardlink/symlink aliases. Noncooperating host writers are explicitly outside exclusion guarantees. | Local macOS behavior tested; platform CI required. |
| I4 | Host writes can accept a prefix before failure. | Immediate/late error, short/interrupted writes and zero progress. Cache bytes beyond the accepted prefix must remain unchanged. | Fault-injection tests pass. |
| I5 | Command success includes persistent synchronization. | Persistent writes visible without an extra guest FLUSH; NVMe FUA; all three FLUSH error paths; independent intermediate file records. | Locally tested; physical power-loss durability unknown. |
| I6 | Device protection and error status follow their respective interfaces. | RO feature/NSATTR, guest reads, forbidden writes/zeroes/deallocation, host capacity failure. False success or bypass through `set_read_only(false)` fails. | Locally tested. |
| I7 | File identity, image bytes and external effects require broader checkpoint/replay integration. | Future configured attachment, source identity, complete media snapshots and replay suppression. Public API tests alone cannot close these requirements. | Integration remains open. |

High impact: CLI/TOML attachment, complete checkpoint media/private-device state,
strong source identity and replay suppression of external writes remain required
integration work. Medium impact: the complete loaded image resides in memory;
large-image paging and persistent COW overlays are separate capabilities. Native
Linux/Windows locking and boot validation remain independent gates. Low impact:
Rust 1.89 is the minimum for this standard-library lock API.

The semantic group may be committed only after the complete native/translated
owners and library inventories, C API, build, Clippy, formatting, documentation,
CI selection, independent image model and existing storage oracles pass against
the frozen sources. Reported local tests do not substitute for those final gates.
