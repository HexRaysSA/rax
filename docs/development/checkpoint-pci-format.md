# PCI checkpoint bundle extension

`SnapshotBundle` adds PCI state and media while preserving the existing public
`Snapshot` fields and base-only six-section writer. The bundle is an extensible
container; it does not by itself establish full CPU/platform state or VM-wide
quiescence. Runtime capture/resume integration remains separate.

| Section | Schema | Contents |
|---|---|---|
| 1..6 | Existing schemas | Existing config, metadata, CPU, emulator, legacy devices and compressed RAM |
| 7 | 1 | `RAXPCS01` control record, bridge state, optional five endpoint records and two media headers |
| 8 | 1 | Independent zstd frame for NVMe media |
| 9 | 1 | Independent zstd frame for AHCI media |

The writer orders control metadata before compressed media and RAM. Endpoint
presence requires both media sections, including explicit empty media. The base
`Snapshot` reader rejects a bundle with PCI state; it cannot silently drop a
required extension. `SnapshotBundle` can also load original/tagged base v8 files
with explicit absent PCI state. Older readers reject unknown required sections.

All control integers are fixed-width little endian; booleans are exactly 0/1.
The section-7 record starts with an eight-byte tag, endpoint-present byte and
u32 bridge length, followed by bridge bytes. Present endpoint records appear as
u32 length plus bytes in e1000/UHCI/NVMe/AHCI/AC'97 order. Each media header then
stores u64 uncompressed bytes, readonly byte and 32 SHA-256 digest bytes. Digest
verification occurs during bounded decompression before device import.

The runtime profile has one bridge-only function or six functions/six windows.
Bridge controls are limited to 4096 bytes, e1000 to 64 MiB and the complete
control section to 65 MiB. Other controller records retain their fixed sizes.
RAM plus both uncompressed media are limited to 64 GiB in this bundle profile;
compressed lengths have separate checked bounds. Allocation and decompression
must fail through returned errors rather than trust file length prefixes.

| ID | Assumption / dependency | Stress/falsification probe | Status |
|---|---|---|---|
| B1 | Existing public Snapshot shape and base wire bytes remain stable. | Existing owner/codec oracles and actual older tagged fixture; base-only reader rejects required PCI state. | Locally tested; final gates required. |
| B2 | Control metadata admits the complete payload geometry before decompression. | Missing/duplicate/order/schema/length/topology/header tests and total-budget boundary. | Locally tested; final gates required. |
| B3 | Media bytes survive compression independently of source files. | Independent system-zstd/SHA-256 comparisons; deleted source files and changed guest media. | Locally tested; final gates required. |
| B4 | Malformed media cannot exceed the declared output budget. | Truncated/corrupted/short/long streams, digest mismatch, huge declared lengths and exact boundaries. | Locally tested; final gates required. |
| B5 | File publication preserves an existing target on failure. | Invalid metadata, encode/decode errors, temporary cleanup and preserved file bytes/permissions. | Locally tested; final gates required. |
| B6 | Container parsing is not live VM restore. | Explicit device import and VM quiescence requirements; base-only image guards retained; typed runtime/file integration is described in `checkpoint-resume.md`. | Locally tested; final gates required. |

High impact: all-CPU/private/platform closure, VM-wide quiescence, replay effects,
remain open. Represented runtime/CLI resume is described in
`runtime-checkpoint-bundles.md` and `checkpoint-resume.md`. Medium impact: the explicit 64 GiB
aggregate bundle budget can reject a combination of individually admitted
images/RAM; no payload may be silently omitted. Low impact: future record kinds
require explicit section schemas and reader admission rules.

The complete `checkpoint_pci` owner contains 20 tests. It includes every control
prefix, all conditional-section failures, huge length/aggregate declarations,
short/long/truncated/digest-corrupt media, actual prior schema-1 bytes, absent
source files and atomic target preservation. The 64 GiB aggregate boundary test
checks declared metadata without allocating that amount of physical RAM.

The independent Python parser and separate system zstd executable validate six
published fixtures, 49 sections, 15,036 control bytes, 98,304 media bytes, 786,432
RAM bytes, eight media digests and six original image identity records. All 12
referenced input paths are absent after publication. An executable linked to the
actual prior product library rejects section 7 before media/RAM. The fixture
media patterns are explicitly constructed typed checkpoint inputs; these are
serialization/restore-boundary controls, not guest CPU or hardware execution.

`SnapshotBundle` has private fields and accessors/builders. The public base
`Snapshot` field declarations remain byte-identical to their predecessor. Its
existing six-section output remains byte-identical on base roundtrip. Runtime
image-backed capture/restore guards remain in place pending full integration.

For b total uncompressed media bytes and c control bytes, compression/digest and
decompression/checking take O(b+c) time and O(b+c) additional space at the fixed
compression profile. Output grows with fallible reservation and checks the first
excess decompressed byte; it does not reserve a declared large media extent
before bytes are produced. Compressed file-section allocation checks both the
configured bound and remaining physical file length, then reserves fallibly.

Base-only parsing rejects section 7 immediately after its header, before reading control/media/RAM payloads. A header-only file verifies that rejection while the bundle reader independently reports truncation. The earlier preflight was explicitly interrupted to add this stronger admission test; its logs and sources are retained.
