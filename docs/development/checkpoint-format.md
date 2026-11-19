# Checkpoint version 8

The checkpoint writer preserves the optional PCI-device setting and publishes a
bounded, tagged version-8 container. The loader also reads the original
untagged version-8 representation and the first tagged config schema. This is a container and configuration change;
additional CPU instances, optional-device internals, platform state and
scheduler/private-engine state still require capture/restore integration.

## Framing

All container integers are unsigned, little-endian and fixed-width. The header
contains:

| Offset, bytes | Width, bytes | Value |
|---|---|---|
| 0 | 8 | `RAXCKPT\0` |
| 8 | 4 | Checkpoint version, 8 |
| 12 | 4 | `RXS8` tag |
| 16 | 4 | Section count, at most 64 |

Each section has a 16-byte header: kind (`u32`), schema (`u32`) and payload length
(`u64`). The required section set is:

| Kind | Schema | Payload | Limit |
|---|---|---|---|
| 1 | 2 (also reads 1) | `CheckpointConfig`, including PCI and image attachment identity | 1,048,576 bytes |
| 2 | 1 | Instruction count, elapsed ns, uncompressed RAM bytes: three `u64` values | 16,777,216 bytes |
| 3 | 1 | Current version-8 `CpuState` representation | 16,777,216 bytes |
| 4 | 1 | `EmulatorState` | 16,777,216 bytes |
| 5 | 1–4 | Represented PIC/PIT/UART/local-APIC state | 16,777,216 bytes |
| 6 | 1 | Raw zstd-compressed RAM bytes | Declared RAM bytes + floor(RAM bytes / 128) + 1,048,576 |

Typed metadata uses bincode's fixed-integer encoding and rejects trailing payload
bytes. The compressed RAM section contains the zstd frame directly; it does not
contain an additional bincode vector-length prefix.

Required kinds have their high bit clear. Unknown kinds with bit 31 set are
optional and can be skipped only within the actual remaining file length.
Required kinds cannot be marked optional. Unknown required kinds, duplicate
kinds, unsupported schemas, missing sections and trailing file bytes fail.
Known sections can be reordered, but configuration and metadata must precede
RAM so declared memory size is validated before allocating its compressed
payload. Header count and lengths are checked before allocation or seeking.

Let r be declared RAM bytes, s be the section count and m be metadata bytes.
The parser uses O(s + m + compressed RAM bytes) input work and retains O(m +
compressed RAM bytes). Optional payloads are skipped with bounded seeks. Declared
RAM is subject to the existing 64 GiB guest-memory maximum. Memory decompression
grows only for produced bytes and stops after r + 1 bytes; it reports either
short or excess output. A tiny input does not reserve all declared RAM up front.

## Original version-8 compatibility

The original format starts with the same magic and version, followed immediately
by the old bincode struct layout. Its next word is the architecture discriminant,
which differs from the `RXS8` tag. The compatibility reader uses a frozen
`LegacyConfig` field sequence and separately bounded config, CPU, emulator and
device decoding. It validates RAM metadata before reading the old byte vector.
Version 7 and other versions are rejected after the fixed version word, before
version-dependent layout decoding.

The [captured original-writer fixture](../../tests/fixtures/checkpoint/README.md)
retains the exact observed bytes and producer provenance. The actual old writer
produced identical files for PCI enabled and disabled when all other state was
held fixed. That bit is unknown in those old files: it was absent. Legacy loading
retains the old false default; CLI enablement can override it. New tagged files
preserve both true and false across config capture, binary serialization and
resume. Human-readable config metadata defaults an absent field to false.

Adding `pci_devices` changes the typed `CheckpointConfig` schema. The file reader
handles the old schema explicitly; generic deserialization of unversioned old
config-only bincode payloads is not used to guess field presence. Existing config
method signatures and the C API layout are unchanged. Image metadata extends the
configuration payload to schema 2; schema 1 has an explicit frozen decoder with
empty image attachments. It is never inferred from payload length. Old schema-1
readers reject schema 2. Unknown configuration schema 3 remains an early error.
The [captured tagged-schema-1 fixture](../../tests/fixtures/checkpoint/README.md)
retains PCI=true and loads without its original kernel path. Schema 2 records
canonical image paths, access modes, byte budgets, source lengths and SHA-256
identities. Recorded PCI images require x86 PCI topology. Runtime image-backed
capture/restore remains rejected until complete device/media state is available;
recording an attachment path alone cannot preserve COW modifications.

## PIT read-back state

Device schema 2 allows a pending 8254 status byte alongside a pending counter
read. Schema 3 also preserves a pending live high byte behind a count latch.
Schema 4 also preserves gate-triggered PIT modes and their oscillator phase.
The writer selects the lowest device schema that represents all device state.
Each retains the version-8 container header.

Each channel's read-back slot is an optional little-endian `u32`. An untagged
word retains the historical counter encoding. Bit 25 or bit 26 marks an
extended word.

| Bits | Extended word |
|---|---|
| 0–16 | Counter latch, or `0x1ffff` for no pending count |
| 17–24 | Pending 8254 status byte, or zero if bit 25 is clear |
| 25 | Status byte pending, requires schema 2 or later |
| 26 | A live high byte follows the count latch, requires schema 3 or later and a pending count |
| 27–31 | Zero |

Counter latch values `0x00000`–`0x0ffff` represent a full count.
Values `0x10000`–`0x100ff` represent a pending high byte in bits 0–7.
A historical status-only latch used the same slot as a small count. The
reader preserves its historical interpretation as a count because those two
states have identical bytes. Tagged schema 1 and original untagged version 8
both reject an extended word.

## PIT gate-triggered state

In schema 4, the channel's serialized operating mode can use a new variant for
8254 mode 1 or 5. It records whether software has written a complete reload,
the active divisor and its transfer tick, and the scheduled transfer tick of
any pending GATE trigger. The active divisor and the programmed reload can
differ. Both timestamps are expressed in PIT oscillator ticks from the VM
clock epoch. A channel using the variant requires schema 4 even before its
first trigger. Historical records retain their original interpretation until
the guest writes another control word to select a counting mode.

## Publication

The writer validates represented CPU state and memory metadata, writes a unique
sibling temporary file, flushes and syncs that file, then renames it onto the
selected directory entry. Serialization and I/O failure before rename leave an
existing checkpoint intact; temporary files are cleaned up. On Unix, new files
are private and existing regular-file permissions are retained. Atomic rename
is separate from complete machine quiescence and power-loss durability of every
storage backend.

```text
validate -> encode bounded metadata -> write temporary -> flush/sync -> rename
```

## Verification

The public `checkpoint_config` regression exercises capture, bincode metadata and
resume through the actual product API. It fails against the actual pre-change
library with `false` restored from an enabled source config. The tests in
`vm::snapshot` cover the tagged layout, original writer fixture, all seven
current CPU payload variants, keyed AArch64 state, version-before-layout errors,
duplicate/missing/optional sections, oversized lengths, seeded truncated
prefixes, bounded decompression and failed-save preservation.

`tools/checkpoint/codec_oracle.py` builds a publisher using the product's public
API, then independently parses complete config and section framing. A separate
system zstd executable checks all produced RAM bytes. Ten bounded serialization
fixtures cover x86-64, AArch64 and RISC-V with PCI off/on and four x86 image
configurations: 60 sections, 40,960 RAM bytes and six image-identity records.
Python independently checks their image lengths and SHA-256 values. The captured
schema-1 fixture is also parsed independently. They use 4 KiB to bound test resources and do not establish a bootable
machine, complete device-state capture or native hypervisor behavior. Source
and library hashes are checked before and after the probe.

## Assumption register

| ID | Assumption and basis | Dependent result | Stress or falsification probe | Status |
|---|---|---|---|---|
| K1 | Original v8 config had no PCI field; actual original-writer files are identical for off/on | Legacy false default, new tagged persistence | Actual pre-change API regression and captured binary | Confirmed absence; prior value unknown |
| K2 | Fixed v8 CPU payload layouts remain compatible | Legacy decoding and current CPU sections | Original writer fixture, all seven variants and AArch64 keyed-state tests | Required compatibility gate for later CPU schema changes |
| K3 | File payload lengths are untrusted | Allocation and optional-seek bounds | `u64::MAX`, truncated prefixes, oversized config/RAM and excessive section count | Bounded checks precede allocation |
| K4 | Declared guest RAM is bounded by the existing guest-memory limit | Compressed-input and decompressed-output budgets | Oversized metadata, short output and compressed expansion beyond r | Existing limit retained; output stops at r + 1 |
| K5 | Rename publishes within the selected directory's filesystem | Existing target preservation | Invalid serialization, repeated replacement and directory target | Local filesystem behavior tested; no whole-storage durability claim |
| K6 | Config persistence does not imply optional-device private-state persistence | Finding classification and scope | Resume with outstanding DMA, additional CPUs and platform devices | Full state closure remains open |

QG1: no normative assessment is needed. QG2: K1-K6 include dependencies and probes.
QG3: container/config coverage is explicit. QG4: widths, byte limits and RAM
budgets are specified. QG5: absent legacy information and remaining state closure
are explicit. QG6: original implementation, captured fixture, source-bound probe
and executable results provide provenance. QG7: quiescence, additional device/CPU
state, replay identity and native boot remain bounded follow-on requirements.

The additive [PCI/media bundle extension](checkpoint-pci-format.md) preserves the base Snapshot API and six-section wire writer while defining required control/media sections 7--9 for SnapshotBundle. This container extension is separate from complete VM capture/resume integration.
