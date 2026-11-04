# Retained NT directory enumeration

This profile implements `NtQueryDirectoryFileEx` and `NtQueryDirectoryFile`
through an appended export family that preserves earlier synthetic NTDLL
ordinals and trap RVAs. Service numbers come from the
selected NTDLL image. No guest address, callback or guest handle value is sent
to the host kernel.

## Record contract

All sizes and offsets below are in bytes. Caller alignment and the spacing
between successive records are distinct. The captured NTFS results use
eight-byte record spacing, including `FileNamesInformation`.

| Class | Record | Filename offset | Minimum caller size | Caller alignment |
|---|---|---:|---:|---:|
| 1 | `FILE_DIRECTORY_INFORMATION` | 64 | 72 | 8 |
| 2 | `FILE_FULL_DIR_INFORMATION` | 68 | 72 | 8 |
| 3 | `FILE_BOTH_DIR_INFORMATION` | 94 | 96 | 8 |
| 12 | `FILE_NAMES_INFORMATION` | 12 | 16 | 4 |
| 37 | `FILE_ID_BOTH_DIR_INFORMATION` | 104 | 112 | 8 |
| 38 | `FILE_ID_FULL_DIR_INFORMATION` | 80 | 88 | 8 |
| 60 | `FILE_ID_EXTD_DIR_INFORMATION` | 88 | 96 | 8 |
| 63 | `FILE_ID_EXTD_BOTH_DIR_INFORMATION` | 114 | 120 | 8 |

The fixed minimum includes the declared one-element filename array and its
structure padding. A completed final record need not include trailing
structure padding. For example, class 3 with `alpha.txt` contains
`94 + 9 * 2 = 112` bytes. A 96-byte first buffer returns
`STATUS_BUFFER_OVERFLOW`, preserves the full 18-byte filename length, and
contains only its first 2 bytes. A subsequent 616-byte call returns the same
complete entry. Odd buffer sizes can cut a UTF-16 unit in half; the copied
data remains bytes, rather than a decoded string.

Ordinary continuation retains the first expression. Restart with a non-NULL
expression can replace it on the measured NTFS installation. Restart with
NULL retains it. `SL_NO_CURSOR_UPDATE_QUERY` starts an independent query
without advancing or changing the ordinary per-open scan. A first unmatched
query returns `STATUS_NO_SUCH_FILE` without publishing the IOSB; exhaustion
of an initialized scan returns `STATUS_NO_MORE_FILES` with zero information.

Raw NT expressions distinguish `*` from `*.*`. DOS_STAR, DOS_QM and DOS_DOT
are accepted as raw expression tokens. Alternate volume filenames participate
in matching and in the information classes that report them. The controls
include `LONGSU~1.TXT`, its lowercase spelling and the corresponding long
filename with a supplementary Unicode character.

## Ownership and platform mechanics

Windows uses the retained native directory handle. Private initialized,
eight-byte-aligned output storage, an owned IOSB and a captured UTF-16
expression remain live through terminal completion. Returned counts and
record chains are validated before guest publication. Pending observation
errors do not release request buffers. The extended export is resolved from
the already loaded NTDLL; ordinary flags have a legacy-call fallback. A host
without the extended export rejects extended flags explicitly.

Linux and macOS mapped volumes enumerate relative to the retained descriptor
with `fdopendir` and `openat`, then retain a bounded per-open snapshot. Handle
duplicates share the cursor; independent opens do not. Replacing the old
pathname cannot substitute another directory. Metadata and Windows attributes
come from owned child descriptors. POSIX volumes supply no alternate NTFS
filenames; the shared record model preserves them when supplied by a volume.
The portable matcher uses single-BMP-unit Rust uppercase. Windows matching
and casing use the actual installed filesystem and NLS implementation.

The snapshot accounting includes names and captured Windows EA payloads and
is bounded by 16 MiB and 65,536 entries. Output requests are bounded by 16 MiB.
Guest asynchronous scheduling and APC delivery are explicit unsupported
frontiers. Other information classes remain explicit unsupported requests.
The directory snapshot can retain an earlier filesystem view, as permitted
by the API's directory-mutation contract.

EA extent is the sum of four-byte-rounded `FILE_FULL_EA_INFORMATION` entries,
including each eight-byte prefix, name terminator and value. The independent
closed-writer controls establish cumulative extents 12, 28 and 48 bytes.
Malformed private mapped-volume EA records are rejected. Unrelated host
xattrs are not exposed as Windows EAs.

For N retained entries, P expression units and F filename units per entry,
portable matching takes O(N * P * F) time and O(P) matching scratch. Snapshot
storage is O(total captured entry and EA bytes), subject to the above bounds.
Native Windows enumeration is delegated to the filesystem; no filesystem
complexity claim follows from the portable matcher.

## Independent evidence

`native-directory-v5.rs` links no RAX code. Each architecture corpus records
337 directory queries and 3 EA setters, plus private timestamp initialization.
The ARM64 and x64 processes run on the ARM64 Windows host. x64 results are
native-kernel API evidence, not a physical-x86 instruction oracle. Source and
image hashes bind each corpus. The wrapper's NTDLL hash binds host System32
NTDLL, not a separately established x64 loaded-module byte image.

Fixture timestamps are initialized to 2030-01-01T00:00:00Z using exact
FILETIME ticks:

```text
116444736000000000 ticks + 1893456000 s * 10000000 ticks/s
    = 135379296000000000 ticks
1 tick = 100 ns
```

The first enumeration still changes access metadata. The replay feeds the
observed first snapshot to the first open and the separately observed
subsequent snapshot to later opens. Metadata is an opaque filesystem input;
no result bytes are masked. Alternate names and file identifiers are captured
from the independent native ID-directory result.

The portable replay covers 302 admitted queries from each architecture,
including every output byte and untouched tail. The 28 minimum-length cases
per architecture are covered by actual guest-service tests. The remaining 7
queries cover metadata-only access, a regular-file object, EA changes and
directory rename; dedicated service, encoding and retained-handle tests cover
those contracts. These counts partition each 337-query corpus.

`native-directory-event-v1.rs` independently measures both query services,
both initial manual-event states, and success, overflow and first unmatched
query outcomes. Each architecture supplies 12 cases. Success and overflow
signal the event and publish the IOSB. A first unmatched query clears even
an initially signaled event and leaves the poisoned IOSB unchanged. The
32-bit status write preserves the upper IOSB union bytes in both 64-bit
native profiles. `windows_directory_events` checks all 24 captured rows
through public HLE contexts for all three guest ABIs: 72 calls per host.
This complements the service-number dispatch tests; projecting pointer-width
fields to the x86 guest does not supply an independent native WoW64 oracle.
The target runs on Unix CI and in dedicated native Windows x64/ARM64 jobs.

The prior installed CMD control stopped at service `NtQueryDirectoryFileEx`
while querying `Users` under `C:\\`. The directory implementation advanced
the observed ARM64 controls to actual command completion: `exit 37` returned
37, and echo returned 0 with exactly matching stdout and empty stderr. These
finite cases do not establish complete Windows userland support.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|---|
| A1 | Admitted record classes contain no pointers or handles. | Pinned Microsoft declarations and the record layouts above. | Bounded native bytes can be copied into guest storage. | Reject out-of-range counts, bad offsets, odd declared filename lengths and truncated fixed prefixes. Any pointer-bearing admitted field falsifies this contract. | Confirmed for the eight admitted classes. |
| A2 | Cursor state belongs to the retained open object. | Independent duplicate and independent-open controls. | Duplicate handles share scans without pathname identity substitution. | Interleave handles, restart, rename the directory, replace its original path and first-enumerate a previously unopened scan. A replacement entry returned through the old handle falsifies ownership. | Confirmed by controls and service tests. |
| A3 | Filesystem metadata can change between independent opens. | Captured access-time transition after the first query. | Replay inputs use the applicable captured filesystem snapshot. | Compare unmasked first and subsequent snapshots; a result byte inconsistent with its selected input fails replay. | Confirmed for the retained captures. |

## Bounded findings

| Impact | Finding | Task effect |
|---|---|---|
| High | Installed CMD `dir /b` of its own executable still stops at `NtQueryInformationFile` class 9. | Separate file-name-information frontier; prevents declaring complete CMD support. |
| High | An additional installed CMD `ver` comparison exits 0 but emits only two CRLF pairs, omitting the native version text. The cause remains unknown. | Does not invalidate directory record packing; blocks a complete CMD/userland claim. |
| High | Asynchronous I/O, APC delivery and other unimplemented NT services remain outside this finite directory contract. | Prevents declaring the full process-emulation goal achieved. |
| Medium | Portable mounted volumes do not reproduce native Windows NLS tables or generate NTFS alternate filenames. | Native same-host Windows calls use the installed filesystem; portable mapping has the explicit semantics above. |
| Medium | A prior whole-library checked optimized campaign recorded a FIFO EOF-readiness failure, despite a passing isolated rerun. | Independent failure remains recorded; directory checks do not make that campaign green. |

`primary/provenance-v1.json` binds the unchanged Microsoft reference copies
and redistribution notices. `manifest-v1.json` and `verify.py` bind the
frozen evidence. Qualification results are recorded separately from this
behavioral contract; filtered tests and cross-builds do not prove native
runtime coverage.
