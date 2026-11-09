# Native SystemMemoryUsageInformation controls

`NtQuerySystemInformation(182, output, bytes, returned)` returns seven
64-bit byte counters. The record is `7 × 8 B = 56 B` for ARM64, AMD64 and
WoW64 x86 callers. The signed third field is `ResidentAvailableBytes`.
The [PHNT declaration](https://github.com/winsiderss/phnt/blob/master/ntexapi.h)
names the fields; computing its enum values identifies this class as 182.
The general four-argument API is described by
[Microsoft](https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation).
Private-class buffer behavior below is measured, rather than inferred from
that public API description.

## Capture and limits

`native-oracle-v1.c` calls the installed NTDLL entry directly and writes binary
stdout without a CRT. The controlled host was Windows 10.0.29698.0 on ARM64;
AMD64 and x86 callers used Windows translation. Each caller produced 2,450
rows: 1,920 output-span cases, 400 ReturnLength cases and 130 page-edge cases.
Thus the corpus contains `3 × 2,450 = 7,350` independent calls. Other kernel
versions and physical AMD64 hosts are not established by these captures.

Each raw stream is `96 B + 2,450 × 112 B = 274,496 B`. The packed header is
`<8s6I64s`: magic, version, machine, pointer width, row count, row bytes,
record bytes and the first 64 entry bytes. Each row is `<12I64s`: id,
buffer kind, supplied bytes, offset, return kind, initial pattern, NTSTATUS,
DOS error, returned DWORD, LastError, output guard, return guard and 64
observed output bytes. `observations-v1.json` records raw-stream SHA-256
identities and preserves each caller's volatile payloads through a byte palette.
`cases-0-v1.json` and `cases-1-v1.json` contain the shared control columns in
original order. `reduce-native-v1.py RAW_DIRECTORY OUTPUT_DIRECTORY` regenerates
those three JSON files from `arm64-native-v2.bin`, `x64-native-v2.bin` and
`x86-native-v2.bin`. Native counter samples change between captures.

Observed status counts per caller were 18 success, 344 length mismatch,
646 access violation, 1,312 datatype misalignment and 130 guard-page violation.
The LastError sentinel `0x12345678` survived every call. The supplied writable
span is checked before the exact-size rule; nonzero spans require 4-byte
alignment. Both 55 B and 57 B fail with required length 56 B. ReturnLength
accepts an unaligned DWORD, probes all four bytes before publishing a result,
and is stored after the complete record. Aliasing ReturnLength over output
therefore overwrites those four bytes with 56. Reached guard pages are consumed
without partial record publication. Trailing bytes remain unchanged.

The replay test injects each captured successful payload into the production
buffer path. Before injection, any ReturnLength-aliased four bytes are replaced
with `de ad be ef`, proving that the final length store wins. This normalization
does not estimate a missing native counter. All other captured bytes, statuses,
DOS errors, guard effects and ReturnLength values are compared exactly.

## Guest accounting

RAX uses its existing single-address-space memory budget, which already backs
`SystemBasicInformation` and `KUSER_SHARED_DATA.NumberOfPhysicalPages`. It has no
guest paging file. Querying host-wide counters would describe unrelated host
processes and disagree with that guest budget. No guest pointer or class is
forwarded to the host for this query.

| Byte offset | Field | Guest value |
|---|---|---|
| 0 | TotalPhysicalBytes | Usable frame commitment limit |
| 8 | AvailableBytes | Limit minus current commitment |
| 16 | ResidentAvailableBytes | Same available capacity, checked signed conversion |
| 24 | CommittedBytes | Current successful backing charges |
| 32 | SharedCommittedBytes | Unique committed pagefile-section pages |
| 40 | CommitLimitBytes | Same no-paging-file limit |
| 48 | PeakCommitmentBytes | Largest successfully published commitment |

Private commits charge only new pages. Shared aliases charge an object page
once until its final view retires. File views retain their existing conservative
view-sized commitment reservation; they do not count as pagefile-section shared
bytes. Failed admissions do not advance the peak. Decommit and release reduce
current commitment while retaining its peak. Snapshot and peak updates require
O(1) time and O(1) additional space. Existing mapping operations keep their
documented complexity. No public C ABI or serialized checkpoint layout changes;
current process runtimes explicitly report `checkpoint: false`.

Portable tests replay all captured caller contracts and exercise actual native
service dispatch for all three guest ABIs. Separate lifecycle tests check
private, shared and file-view accounting, failed charges, release and peak
retention. Host-native execution on Windows, macOS and Linux is a separate
qualification gate; these fixtures alone do not prove complete process support.
