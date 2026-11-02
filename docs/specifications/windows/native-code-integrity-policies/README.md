# SystemCodeIntegrityPoliciesFullInformation

The four-argument `NtQuerySystemInformation` class 189 returns opaque native
code integrity policy bytes. The class name is retained in the pinned PHNT
header referenced by `sources.json`. The implementation does not infer an
internal policy layout or implement signature enforcement from this metadata.

Native acquisition occurs when a Windows native runtime is selected. Each
attempt queries the required size, then compares complete outputs from private,
eight-byte-aligned buffers initialized with opposite poisons. Three attempts
allow at most nine fixed, read-only host queries. Each requested payload is
bounded by 16 MiB (16,777,216 bytes). Missing, oversized, unstable, or incompletely
written native data remains an explicit unavailable result. Guest class values,
addresses, and lengths never reach these acquisition calls.

The process retains its immutable snapshot. Guest queries use its actual byte
length; the measured length is not a product constant. Querying does not allocate
host storage proportional to the guest's declared length. Acquisition takes
`O(N)` payload storage and `O(N)` byte work per bounded attempt; guest copying
takes `O(N)` byte work in addition to the existing memory-probe traversal.

## Native observations

The retained campaign runs independent C executables as ARM64, x64, and x86
processes on one ARM64 Windows 10.0.29695 kernel. These are three process ABIs,
not three physical kernels. Each executable and its actually mapped NTDLL file
are identified and hashed before and after execution. The x86 mapped provider
is SyChpe32 NTDLL; its logical path alone is not its file identity.

Each ABI has 14 lengths × 18 output roles × 13 ReturnLength roles + 4 poisoned
controls = 3,280 calls, or 9,840 calls overall. The output roles include short,
unaligned, null, upper-address, first-page, interior-page, final-page, guard,
read-only, and declared-tail cases. ReturnLength roles include null, invalid,
unaligned, protected, crossing-page, and output-aliasing destinations.

Every case restores protections after recording their reached guard state.
The observer then compares every arena byte with a lossless representation:
initial poison, a prefix of the separately captured native payload, and eight
actual watched ReturnLength bytes. `arena_reconstruction_verified` records that
complete comparison. `copy_prefix` is a reconstruction length; an alias can
mask payload bytes, so it does not independently identify the number of stores.

All three ABIs returned the same 525,972-byte payload, with SHA-256
`3a60028c64c2070936b33f602b7e437fd269daa9e3abe8f398bcc23e40837e80`.
Four additional discovery buffers, simultaneously live at different addresses
and initialized with different poisons, returned the same complete bytes.

On this kernel the three recorded matrices are identical:

- A nonempty output requires ULONG alignment and a writable full declared span.
- Optional ReturnLength is probed for four writable bytes before size dispatch.
- A short output leaves its contents intact, reports the required size, and
  returns `STATUS_INFO_LENGTH_MISMATCH` after those probes.
- A sufficient output receives exactly the captured payload, followed by the
  required-size store. Its remaining declared tail stays intact.
- WoW64 forwards both destinations. It has no converted-output workspace or
  copy-before-ReturnLength-probe path for this class.

`controls-v1.json` binds the exact producer sources, raw JSONL, opaque payload,
executed images, process ABIs, and mapped providers. Imported raw files retain
their original bytes through the local Git attributes.

## Reproduction

Verify the retained evidence on Windows, macOS, or Linux:

```text
python tools/ci/windows_code_integrity_policies.py --verify-corpus
```

Capture fresh native observations and replay them on a native 64-bit Windows
host with MSVC, CMake, Python, and the repository Rust toolchain:

```text
python tools/ci/windows_code_integrity_policies.py
```

The runner requires a new in-tree output directory, compiles independent native
producers, preserves their actual executables and raw outputs, and selects both
the retained and fresh Rust replay checks. It rejects changed sources, missing
ABIs, incomplete matrices, mismatched payloads, or incomplete test selection.
The owning CI lane preserves its evidence even when a later check fails.

## Assumptions and boundaries

| ID | Assumption | Basis and dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|
| P1 | The selected metadata can be replayed as opaque bytes. | Complete poison/destination/ABI equality supports an immutable process-owned record. | Fresh native captures reject undefined, destination-dependent, unstable, or ABI-dependent bytes. | Confirmed for the measured kernel and payload. |
| P2 | All standard four-argument process ABIs use the measured probe/copy order. | Identical native matrices define the shared adapter. | Fresh independent native matrices and complete guest-arena comparison on Windows. | Measured; other kernel versions require their own observations. |
| P3 | The internal blob format need not be interpreted to reproduce this query. | Only its native length and exact bytes are published. | Arbitrary-byte snapshots and altered guest version fields must preserve every byte. | Implementation contract; no internal layout assumed. |

High impact: this query alone does not establish complete installed-process
startup. Protected IFEO acquisition under an ordinary token remains a separate
boundary. The six-argument `NtQuerySystemInformationEx` selector is a separate
adapter; no equivalence or additional support is claimed here.
