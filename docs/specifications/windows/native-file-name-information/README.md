# Native file-name information controls

These controls define the implementation of `NtQueryInformationFile`
class 9 (`FileNameInformation`). The record starts with an unsigned byte count
and contains a variable UTF-16 name. Microsoft documents name syntax that depends
on the open history and traverse privilege, and an overflow result that reports
the complete required name length. Unmodified primary inputs and their license
and provenance are under [primary](primary/).

`native-name-v1.rs` links only the Rust standard library and Windows system
libraries. It opens the installed system directory and its `ntdll.dll` with
metadata-only, read-attributes and generic-read requests. It neither creates nor
writes either object. Each handle is synchronous and privately owned. The source
queries 24 buffer lengths at offsets 0 and 1, capturing all 16 IOSB bytes and
the complete supplied output span plus both sentinels: 288 direct native calls
per 64-bit caller architecture. Pending requests retain their handle and both
private allocations until observed completion. Surprising wait results are
not treated as terminal completion.

The producers require Windows NTDLL. Their frozen results drive the shared
emulated dispatcher on Windows, macOS and Linux; host path mechanics remain in
narrow platform adapters. Independent native measurements and emulator replays
are distinct evidence.

## Extended observations

The frozen observations were collected on Windows ARM64 build 29698. An x64
process on this host is compatibility-process evidence, not a physical AMD64
kernel or instruction-set oracle.

| Caller | Producer | Queries | Successful queries | Skipped |
| --- | --- | --- | --- | --- |
| ARM64 | `native-name-v3.rs` | 2,016 | 324 | 0 |
| x64 | `native-name-v3.rs` | 2,016 | 324 | 0 |
| x86 WoW64 | `native-name-v2.cs` | 2,016 | 756 | 0 |
| x64, independent managed caller | `native-name-v3.cs` | 2,016 | 324 | 0 |

Each extended matrix covers both synchronous and overlapped handles, the same
three access requests and two installed objects, 24 lengths and offsets
0, 1, 2, 3, 4, 7 and 8. The actual x86 caller accepts all seven tested
alignments; both 64-bit callers require 4-byte output alignment for class 9.
Every matrix
retains the complete native IOSB, its initial bytes, output and both sentinels.
The compiled and managed x64 query records agree in all 2,016 cases. Source,
executable and output hashes bind the observations; system-DLL hashes describe
the collector's filesystem context and do not attest each child's loaded view.

`IsWow64Process2` reports an unknown process machine for a process outside
WoW64. Substituting the host machine for that value does not identify its
associated process architecture. The v3 producers instead use
`GetProcessInformation(ProcessMachineTypeInfo)` and its 8-byte
`PROCESS_MACHINE_INFORMATION`; compiled producers additionally check that
machine against their compiler target. The v2 C# x86 profile has an explicit
nonzero WoW64 machine value and 4-byte pointers. Provisional 64-bit labels from
the older heuristic are excluded from architecture qualification.
See the [WoW64 API contract](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process2),
[process-machine record](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_machine_information)
and [information-class enumeration](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ne-processthreadsapi-process_information_class).

`fault-observations-v1.json` retains 2,163 additional class 9 observations:
103 length/fault cases for each of seven roles and three caller ABIs. These
records come from the previously completed, hash-bound
[`native-file-information/faults-v1.c`](../native-file-information/faults-v1.c)
controls; they were excluded from that feature's fixed-class replay subset.
They distinguish guard consumption, late IOSB faults, both output/IOSB overlaps,
and synchronous versus overlapped publication. Sparse runs preserve the original
observation windows rather than claiming that every byte of an entire page was
captured. Full fixture names derive from the source-defined working directory
and relative `CreateFileW` operand; their length and captured prefix are checked
against the independent native records. This derivation is identified in the
profile provenance. The replay tests compare all captured status values, IOSB
bytes, output windows and protection effects for each of the three guest ABIs.

## Retained names and namespace projection

Each open retains its original mapped volume. Duplicate handles share that
origin, root-relative opens inherit the directory handle's volume, and later
drive-map changes do not select a different naming root. Selected installed
libraries retain an explicit guest-directory prefix without granting general
host-filesystem authority. Name queries preserve synchronization-only guest
grants: the Windows identity check uses `FileIdInfo` rather than requiring
general read-attributes metadata access.

Windows resolves retained handles with `GetFinalPathNameByHandleW` and
`FILE_NAME_OPENED`. Linux retains metadata-only `O_PATH` descriptors and resolves
their current paths. macOS captures the opened directory entry's filesystem
and link identifiers, then resolves that link with `fsgetpath`; an inode alone
does not distinguish hard-link spellings. The adapter validates the returned
path against the retained file identity. Apple's pinned
[fsgetpath contract](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/fsgetpath.2)
specifies link-ID lookup and its filesystem-support boundary.

`native-name-lifetime-v1.cs` records 27 native class 9 name queries and 54
independent final-path queries. Renames follow the opened link; a replacement
does not substitute another identity; independently opened hard links retain
distinct names. Native deletion can produce an opaque `\$Extend\$Deleted`
name. The emulator does not synthesize that namespace for unlinked Unix files:
an unavailable retained name remains an explicit unsupported result. Moves
outside the captured guest volume and ambiguous renamed hard links on a Darwin
filesystem without usable link IDs are also explicit unsupported boundaries.

`native-root-move-v1.cs` and `root-move-observations-29698-v1.json` separately
measure the host directory-rename operation. On the measured Windows host,
`MoveFileExW` succeeds without retained handles and returns
`ERROR_ACCESS_DENIED` with an open child file, including without RAX root
handles. The Windows replay asserts that observed boundary and rechecks all
retained names. macOS and Linux exercise successful root renaming, same-name
root replacement, and the names retained through both operations.

## Qualification bounds

The current targeted selection replays all 6,048 ordinary native observations
and 2,163 fault/overlap observations across ARM64, x64 and x86 guests. It also
retains the preceding fixed-class corpus and exercises real NT and Win32 opens.
The broader selection covers native file open/create/read/write/attribute and
section lifetimes, plus the Win32 file tests. All reported selections have zero
failures and zero ignored tests.

| Execution host | Targeted tests | Broader file tests |
| --- | --- | --- |
| Native macOS ARM64 | 9 | 63 |
| Native Windows ARM64 VM | 10 | 58 |
| Linux amd64 under ARM64-host translation | 9 | 62 |

The owning library and its test configuration also compile and receive Clippy
checks on all three targets without diagnostics in the changed files. Aggregate
strict Clippy commands still fail on unrelated NVMe/HVF integration-test errors;
these results do not claim a clean workspace-wide lint gate.

A bounded comparison of installed ARM64 `cmd.exe /d /c dir /b` gets past class 9
and stops at unsupported `NtQueryVolumeInformationFile` class 5. Native Windows
prints `cmd.exe` followed by CRLF and returns zero; the emulated command has not
completed. This is a measured next frontier, not end-to-end command success.

On a native Windows host, keep all outputs and temporary files in the checkout:

```powershell
$control = Join-Path (Get-Location) 'target/file-name-native-v3'
$temporary = Join-Path $control 'tmp'
New-Item -ItemType Directory -Force $control, $temporary | Out-Null
$env:TMPDIR = $temporary
$env:TMP = $temporary
$env:TEMP = $temporary
$image = Join-Path $control 'native-name-v3.exe'
rustc +1.95.0 --edition=2024 -C opt-level=2 -C target-feature=+crt-static `
  docs/specifications/windows/native-file-name-information/native-name-v3.rs `
  -o $image
if ($LASTEXITCODE -ne 0) { throw 'native control compilation failed' }
$child = Start-Process -FilePath $image -NoNewWindow -PassThru -Wait `
  -RedirectStandardOutput (Join-Path $control 'observations.jsonl') `
  -RedirectStandardError (Join-Path $control 'stderr.log')
if ($child.ExitCode -ne 0) { throw 'native control failed' }
```

Require one host record, two input records and a final record reporting 2,016
queries and zero skips. The v3 machine query requires Windows build 22000 or
later. Bind the source, executable and output hashes and the
native kernel/caller identities before comparing emulated behavior. Remove the
generated image and build-only directory after collecting the observations and
confirming that the owned process is terminal.
