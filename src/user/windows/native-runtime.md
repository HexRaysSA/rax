# Installed Windows runtime selection

`WindowsConfig::native_libraries = true` selects read-only installed DLLs and
the installed version-6 API-set namespace on a Windows host. Its default is
false. `host_filesystem = false` still denies general guest host-file access;
native library selection is a separate, explicit input grant. A different host
OS or unmatched installed NTDLL architecture returns an error.

The selector obtains the Windows and system directories through wide Win32
APIs, and obtains the actual version through `RtlGetVersion`. Canonical host
paths remain distinct from guest paths: the `\\?\` prefix added by Windows
canonicalization is not placed in guest loader/process parameters. Installed
DLL files and their native-mode mappings are bounded to 67,108,864 bytes.
Application DLLs remain subject to general host-file access or explicit supplied
bytes. Supplied bytes override installed files in native mode. KnownDLL names
select installed system files; no missing installed DLL selects an HLE image.

The API-set parser preserves the schema-defined hash identity, importer-specific
aliases, explicitly unavailable values, and the raw namespace mapped at
`PEB.ApiSetMap`. Version-6 entries record `HashedLength` through the major/minor
identity, excluding the final numeric revision. Requested numeric revisions
resolve within that identity; an absent major/minor identity does not. Malformed
hash extents and duplicate hash identities are rejected.
Import binding and export forwarding supply the importing module's basename.
The parser bounds checked byte extents, UTF-16 decoding, namespace/value counts
and aggregate decoded text. It does not infer neighboring contract families.
The installed base schema differs from process-specific live PEB extensions;
those extensions are not currently imported.

For E contracts, V values and B decoded text bytes, parsing uses
O(B + E log(E+1) + V log(V+1)) work excluding string-comparison cost and
O(B+E+V) metadata. E and aggregate V are each at most 65,536; the retained
schema and aggregate decoded UTF-16 source text are each at most 4,194,304
bytes. Individual UTF-16 strings are at most 8,192 bytes. Reads use O(B) transfer
work/storage with B <= 67,108,864 bytes, excluding host filesystem costs.

Native NT kernel entry uses numbers decoded from admitted NTDLL exports:

```text
ARM64: real SVC immediate -> checked NT operation -> real RET
x64:   real SYSCALL/EAX   -> checked NT operation -> real RET
x86:   real CALL/thunk    -> private WoW64 entry  -> real RET imm16
```

The x86 adapter preserves all 32 encoded service bits. It admits the complete
`MOV EAX; MOV EDX; CALL EDX; RET imm16` leaf only when its target is the image's
indirect jump through the exported `Wow64Transition` slot. The guest slot is
initialized with a process-owned kernel frontier. With transition ESP = S,
the internal return is at S, caller return at S+4, and argument zero at S+8.
The kernel return consumes only 4 bytes; the installed DLL's actual `RET imm16`
consumes its caller return and arguments. Unknown/hooked/partial encodings and
unimplemented NT operations stop explicitly. The adapter executes no host NT
syscall for guest requests.

Supported kernel operations include checked NtClose, memory allocation/free/
protection, context continuation, forced termination, installed startup system
queries (`NtQuerySystemInformation`, classes 0 and 50), and the process-cookie
query (`NtQueryInformationProcess`, class 36). Other query classes remain
explicit unsupported operations.
Unrecognized WoW64 encodings, native RTL heap/bootstrap requirements,
the broader NT object/file/section/query surface and ordinary Win32/CRT startup
remain incomplete. Native-subsystem images load NTDLL without inventing the
Win32 KERNEL32/KERNELBASE roots; Win32 images select those installed DLLs too.

## Assumptions and probes

| ID | Assumption | Basis | Dependent behavior | Stress test / falsification probe | Status |
|---|---|---|---|---|---|
| W1 | Installed files are not adversarially replaced between canonicalization and read-only open. | Installed runtime directories are selected inputs; the check/open operation is not atomic. | Native directory containment and replay. | Replace a symlink/reparse point during selection; truncate a selected file. | Retained; no atomic host sandbox or immutable snapshot claim |
| W2 | The installed base API-set schema supplies the hash identities needed by the selected application. | Version-6 file from Windows 10.0.29683.1000, 987 entries. | Import/forwarder redirects. | Compare live PEB contracts; absent major/minor identities and empty hosts must fail. | Confirmed for tested base redirects; seven Hyper-V hosts differ in the live PEB |
| W3 | Admitted NTDLL leaves use a recognized encoding. | Installed ARM64 and x86 NtClose bytes; controlled x64 stubs. | Service identity and argument ABI. | Change a CALL target, truncate a stub, collide numbers, unload the table owner or call an unknown operation. | Confirmed for exercised leaves; other encodings remain explicit failures |
| W4 | Modern PEB and x86 transition fields have the recorded layout. | Native ARM64, x64 and x86 probes on Windows 10.0.29683.1000. | PEB schema and x86 TEB transition pointer. | Native probe on another Windows build; compare header and export bytes. | Confirmed on this installation; broader builds unverified |
| W5 | Version-6 loader resolution uses the recorded hash identity while accepting numeric final revisions. | All 987 installed entries hash their name without that revision; native `LoadLibraryExW` resolves rtlsupport l1-1 revisions 0, 1 and 65535 to NTDLL. | Older imported spellings in installed KERNEL32. | Nonnumeric revision, missing identity, conflicting schema keys, importer alias and unavailable override. | Confirmed on Windows 10.0.29683.1000; compare another Windows build with the native-loader regression test |

The native loader resolves `api-ms-win-core-rtlsupport-l1-1-0.dll` and
`...-l1-1-65535.dll` through the installed `...-l1-1-1` entry. It similarly
resolves l1-2 revisions 0, 3 and 65535 through the l1-2-3 entry, while rejecting
nonnumeric revision `banana` and absent l1-3/l2-1 identities with Win32 error 126.
This is observed loader behavior on the recorded build, not an API availability
or compatibility guarantee for a requested immutable version identifier.
Microsoft's public API-set documentation distinguishes contract identifiers
from DLL files and states that successful loading does not establish API
availability. The native regression test compares the selected host with
`LoadLibraryExW`, using `LOAD_LIBRARY_SEARCH_SYSTEM32` and balanced references.

Native probes read `RtlGetCurrentPeb()+0x68` for 64-bit processes and `+0x38`
for x86. All returned namespace version 6, size 171,740 bytes and count 987.
The x86 TEB probe read its transition pointer at offset `0xC0`. The base file
namespace is 171,404 bytes. Binary layout is direct observation, not a public
Win32 layout guarantee.

On this ARM64 installation, `GetSystemWow64DirectoryW` reports 20 UTF-16 units
but leaves the buffer zero. Embedded NULs are rejected. The selector then
checks `SysWOW64` under the API-derived Windows root, and validates its actual
NTDLL machine before admission. It does not accept an unvalidated directory.

High, blocking full process support: ordinary native Win32/CRT startup and the
broader kernel surface remain incomplete. Medium: live API-set extensions and
ARM64X/hybrid runtime selection require additional adapters. Medium: native
evidence does not certify another Windows build, x64 Windows kernel or physical
x86 hardware. These limitations do not change the existing built-in profile.

## Hash-identity correction validation

The correction is based on installed Windows loader behavior, not a guessed
contract-family fallback. ARM64 smoke, MSVCRT streams, UCRTBASE streams and
installed `whoami.exe` previously refused open at KERNEL32's rtlsupport
l1-1-0 import. All four now open with 4, 5, 5 and 21 modules respectively,
then stop explicitly at the unimplemented installed NTDLL
`NtQuerySystemInformation` service 0x36. Those stops identify the next kernel
boundary; they do not establish ordinary process compatibility.

| Gate | Result | Evidence |
|---|---|---|
| macOS full RAX library binary | 7,449 passed; 0 failed; 2 ignored; 0 filtered | `/tmp/assist-native-apiset-full-macos.log` |
| Linux full RAX library binary | 7,442 passed; 1 failed; 2 ignored; 0 filtered | `/tmp/assist-native-apiset-full-linux.log`; previously observed `a_timeout_is_removed_or_updated` fails under the full run |
| Windows ARM64 full RAX library binary | 6,819 passed; 5 failed; 2 ignored; 0 filtered | `/tmp/assist-native-windows-29683/native-apiset-final-full.log`; same four BZHI lowering assertions and native FP16 feature failure as the preceding run |
| Complete C API package on macOS, Linux and Windows | 168 passed; 0 failed; 0 ignored; 0 filtered on each native OS | `/tmp/assist-native-apiset-capi-{macos,linux}.log`; `/tmp/assist-native-windows-29683/native-apiset-capi.log` |
| Installed Windows loader comparison | Passed | Native regression exercises revisions 0, 1 and 65,535; malformed and missing identities fail |
| Windows shipping archive / startup probes | Archive builds; all four images open; all four execution probes stop at service 0x36 | `/tmp/assist-native-windows-29683/{assist-apiset-shipping-build,native-process-apiset-probe}.log` |

All three full binaries ran without filters. The generic malformed-extent,
duplicate-identity and importer-alias tests pass on each host. A passing native
loader comparison does not make the Linux or Windows full suites green.

## Installed startup range query

Class 50 of `NtQuerySystemInformation` returns the process profile's range-start
pointer. The installed ARM64 startup calls it with X0 = 0x32, X2 = 8. No guest
request invokes the host kernel; the shared checked handler supplies the guest
profile value. The export is appended to the existing synthetic NTDLL table,
retaining previous export/trap-slot indices. Native entry still uses the number
decoded from the selected installed stub, never a hard-coded service number.
At range-query revision `ab3d32621cc5adf7690aeefe76dd121f3608f29b`, other
classes produced an explicit unsupported diagnostic. The basic-query section
below records the subsequent extension to class 0.

The private class layout and following behaviors were measured on Windows
10.0.29683.1000 through native ARM64, x64 and x86 processes. The x64 and x86
probes run through that ARM64 Windows installation's compatibility adapters;
they do not establish x64-kernel or physical x86-kernel behavior. Public
Microsoft documentation establishes the four-argument query API, optional
32-bit ReturnLength and NTSTATUS result, not class 50's private structure.

| Guest profile | Exact output bytes | Returned value | Output alignment | Error ReturnLength | Invalid ReturnLength ordering |
|---|---|---|---|---|---|
| ARM64 / x64 | 8 | 0xFFFF800000000000 | 4-byte alignment; +4 succeeds, +1 fails with STATUS_DATATYPE_MISALIGNMENT | 8 on wrong length | Probe before output write; output remains unchanged |
| x86 WoW64 | 4 | Guest user-address limit: 0x7FFF0000 normally, 0xFFFF0000 for a large-address-aware PE | Unaligned output accepted | 0xFFFFFFFC on wrong length or null output | Converted output is written before ReturnLength faults |

Lengths smaller or larger than the exact width return
`STATUS_INFO_LENGTH_MISMATCH`; they do not silently truncate or accept extra
bytes. Native 64-bit entry probes nonempty output spans before length dispatch,
so inaccessible oversized spans return `STATUS_ACCESS_VIOLATION` first. Its
ReturnLength pointer accepts unaligned storage. Null ReturnLength is allowed.
Native 64-bit null output with exact width faults without writing ReturnLength;
x86 WoW64 null output returns `STATUS_INVALID_PARAMETER` and writes the recorded
error ReturnLength. Unmapped/read-only destinations use checked guest writes;
no output fault dispatches an HLE guest exception or consumes a caller return
address.
The actual installed RET/RET imm16 performs the final caller cleanup. Armed
output/ReturnLength guards are cleared once and return
`STATUS_GUARD_PAGE_VIOLATION`; retry succeeds after the guard clears. Native
ARM64 leaves both destinations unchanged on either guard. Native x86 publishes
its converted output before a ReturnLength guard, matching its write order.
These cases were measured directly and are covered by shared ABI tests. A native
x86 `/LARGEADDRESSAWARE` probe returns 0xFFFF0000, while the ordinary image
returns 0x7FFF0000. The shared handler reads `VirtualMemory::high()` for x86;
it does not reuse a fixed normal-image constant for large-address-aware images.

The 64-bit adapter probes at most ceil(L / 4096) + 1 pages for a requested
L-byte output, stopping at the first fault, with L <= 4,294,967,295 bytes.
The upper bound is 1,048,577 page checks, plus at most two checks for the
4-byte ReturnLength. No allocation scales with L: auxiliary space is O(1).
The x86 conversion and successful fixed-size output use O(1) work/storage,
excluding address-space lookup and backing-page population costs.

| ID | Assumption | Basis | Dependent behavior | Stress test / falsification probe | Status |
|---|---|---|---|---|---|
| Q1 | The selected installed startup requests the private range query with one pointer-sized output. | Captured ARM64 class 0x32/8-byte arguments and native NtQuerySystemInformation outputs. | DLL initialization proceeds beyond its first kernel query. | Capture another startup class; compare installed NTDLL leaf and native query on a different Windows build. | Confirmed on Windows 10.0.29683.1000; broader builds unverified |
| Q2 | The guest's modern Windows profile uses the recorded 64-bit range and WoW64 conversion behavior, with x86 range selected by the PE large-address-aware flag. | Native ARM64/x64/x86 query probes, exact-length/alignment/fault-order measurements; existing x86 adapter models WoW64. | Shared class-50 ABI, including 32-bit partial publication and error ReturnLength. | Different version/kernel architecture, large-address-aware x86 image, overlapping outputs and read-only destinations. | Revised after the large-address-aware probe falsified a fixed x86 value; both PE flag states now use the owning guest address-space limit. Physical x86 and x64 Windows kernels unverified |
| Q3 | Unimplemented system-query classes must remain distinguishable from completed queries. | The range-query revision admitted only class 50. | Caller diagnostics and bounded capability claims. | Classes 0, 1 and 0xFFFFFFFF, invalid buffers and unknown admitted service numbers. | At that revision, generic tests required explicit class-bearing failure; the basic-query section records class 0 support |

High, still blocking ordinary startup: additional system/process queries, native
RTL heap/bootstrap and the wider NT surface remain incomplete. At the range-query revision, all four tested
Win32 images passed the range query and stopped explicitly at class 0, requesting
64 bytes for SystemBasicInformation. Medium: native
query behavior is version/build-specific private evidence; guard handling for
other NT services remains outside this query implementation.
The existing default DLL profile, host access grant, C ABI and all three host
OS source memberships remain unchanged except for this appended NT query.

### Final range-query validation

| Gate | Result | Evidence |
|---|---|---|
| macOS full RAX library binary | 7,455 passed; 0 failed; 2 ignored; 0 filtered | `/tmp/assist-native-query-laa-final-full-macos.log` |
| Linux full RAX library binary | 7,448 passed; 1 failed; 2 ignored; 0 filtered | `/tmp/assist-native-query-laa-final-full-linux.log`; previously observed `a_multishot_timeout_reports_each_expiry` fails |
| Windows ARM64 full RAX library binary | 6,826 passed; 5 failed; 2 ignored; 0 filtered | `/tmp/assist-native-windows-29683/native-query-laa-final-full.log`; same four BZHI lowering assertions and FP16 host-feature failure |
| Native query boundary probes | ARM64/x64/x86 exact width, alignment, optional and invalid destinations; ARM64/x86 one-shot guards; x86 normal/LAA ranges measured | `/tmp/assist-native-windows-29683/native-query-{pointer-*,guard-*,laa}.log` |
| Current macOS / Linux complete C API packages | 168 passed; 0 failed; 0 ignored; 0 filtered each | `/tmp/assist-native-query-laa-final-capi-{macos,linux}.log` |
| Current Windows complete C API package | 168 passed; 0 failed; 0 ignored; 0 filtered | `/tmp/assist-native-windows-29683/native-query-laa-final-capi.log` |
| Current macOS / Linux shipping archive linkage | macOS 5/5 Assist CTests pass; Linux API 1.11.0 ABI and one-archive link checks pass | `/tmp/assist-native-query-laa-root-macos-ctest.log`; `/tmp/assist-native-query-laa-root-linux-link.log` |

These full binaries include the final guard and large-address-aware correction.
Earlier fixed-x86-range builds are not the final validation. All six shared
query tests and the Windows installed-leaf test pass. The Linux and Windows
full suites remain failing; current passing C API/link checks do not erase them.
The selected query is identical on each host OS and reads/writes only the guest
address space. Its Windows-native probes and selected-leaf execution establish
private ABI behavior within the recorded installation, not another kernel build.

Primary API contracts:
[NtQuerySystemInformation](https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation),
[Creating guard pages](https://learn.microsoft.com/windows/win32/memory/creating-guard-pages),
[Windows API sets](https://learn.microsoft.com/windows/win32/apiindex/windows-apisets),
[LoadLibraryExW](https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw),
[GetSystemDirectoryW](https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw),
[GetSystemWow64DirectoryW](https://learn.microsoft.com/windows/win32/api/wow64apiset/nf-wow64apiset-getsystemwow64directoryw),
[RtlGetVersion](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlgetversion),
[OSVERSIONINFOEXW](https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-osversioninfoexw).

## Installed startup basic query

`NtQuerySystemInformation` class 0 (`SystemBasicInformation`) now returns the
Windows guest profile through the same checked native-entry dispatcher as
class 50. The four observed Win32 probes previously stopped at class 0 with
64-byte outputs after passing class 50. Unimplemented classes still produce
an explicit class-bearing diagnostic; this addition does not infer support
for another query or complete Win32 startup.

The native probe programs and compiler outputs are retained under
`docs/specifications/windows/native-query/`. Run each program with MSVC
`cl /nologo /std:c++20 /EHsc` from a scratch directory after selecting
`Launch-VsDevShell.ps1 -HostArch arm64 -Arch arm64` (or x86/x64). The pointer
probe's printed `width` denotes its class output extent, 44 or 64 bytes; its
source derives that from `sizeof(void*)`. The system/correlation probes print
the actual pointer width. Guard probes use native SEH to distinguish a returned
NTSTATUS from a dispatched exception. Outputs are a measured snapshot, not
fixed host-memory or processor expectations on another machine.

The retained Microsoft contract is
[ntquerysysteminformation.md](../../../docs/specifications/windows/native-query/ntquerysysteminformation.md),
with its source, retained native probe programs/outputs, retrieval date, exact
content hashes and license locations in
[sources.json](../../../docs/specifications/windows/native-query/sources.json).
Its public structure reserves the first 24 bytes and four pointer-sized slots;
only `NumberOfProcessors` is public. The additional meanings below are the
recorded private guest profile, not a public SDK guarantee. Native ARM64/x64/x86
probes on Windows 10.0.29683.1000 correlate page size, allocation granularity,
address bounds, affinity and processor count with `GetSystemInfo`, physical
page count with `GlobalMemoryStatusEx`, and the timer field with the largest
`NtQueryTimerResolution` interval. Native physical pages * 4096 bytes equals
85,892,726,784 bytes, agreeing with `ullTotalPhys`; native 156,250 units *
100 ns equals 15.625 ms. Guest values describe the emulated machine instead.

| Field / offset | x86 WoW64 | ARM64 / x64 | Guest source |
|---|---|---|---|
| Required bytes | 44 | 64 | Native exact-length probes |
| Actual written bytes | 41; final 3 bytes unchanged | 64; padding zero | Native canaries and inaccessible-tail probes |
| Timer / +4 | 10,000 units of 100 ns | Same | Guest 1 ms tick granularity; declared profile value |
| Page size / +8 | 4096 bytes | Same | `PAGE_SIZE` |
| Physical pages / +12 | Usable backing bytes / 4096 | Same | `VirtualMemory::commit_limit`; excludes reserved frames, no paging file |
| Physical arena bounds / +16,+20 | 0 through last backing-frame index | Same | Actual guest physical-memory extent |
| Allocation granularity / +24 | 65,536 bytes | Same | `ALLOCATION_GRANULARITY` |
| Minimum user address | +28 | +32 | `VirtualMemory::low()` |
| Maximum user address | +32 | +40 | `VirtualMemory::high() - 1`, inclusive; x86 normal/LAA limits differ |
| Affinity mask | +36 | +48 | 1, matching the single virtual processor |
| Processor count | +40 | +56 | 1, matching PEB, KUSER_SHARED_DATA and guest environment |

Process construction now writes the same usable page count into the existing
`KUSER_SHARED_DATA.NumberOfPhysicalPages` profile field. Physical page counts
and frame extents that do not fit `ULONG` fail explicitly rather than truncate.
The arena rounds capacity down to 4096-byte pages; a 128 MiB + 123-byte input
reports 32,768 pages and last frame 32,767. The shared x86 test checks both PE
large-address-aware states against the owning VM address ceiling.

Wrong lengths, including larger buffers, return `STATUS_INFO_LENGTH_MISMATCH`
and ReturnLength 44 or 64. Native 64-bit initial destination probes and 4-byte
output alignment precede class/length dispatch. WoW64 probes its 41 converted
bytes before publishing any output, accepts unaligned buffers, and does not
probe inaccessible trailing padding. Native crossing-page probes with 40
accessible output bytes leave all output unchanged on failure; 41 accessible
bytes succeed in WoW64. Null exact WoW64 output returns
`STATUS_ACCESS_VIOLATION` with observed error ReturnLength 0xFFFFFFEC. A bad
WoW64 ReturnLength can fault after output publication. Native 64-bit output
alignment and the supplied output span are probed first, then ReturnLength,
before either output is written. Combined-fault probes in the process-cookie
group below corrected the previous ReturnLength-first initial probe order.
Optional/unaligned/overlapping ReturnLength, read-only output,
one-shot guards and installed RET/RET imm16 caller cleanup have explicit tests.
No guest call forwards to a host kernel query.

Layout generation uses a fixed 64-byte stack buffer: O(1) work and storage.
The existing 64-bit initial probe is O(ceil(L / 4096) + 1) page checks for
an L-byte supplied length, stops at the first fault, and allocates no L-sized
buffer. Successful class-0 writes span at most two pages. Checked address-space
lookup and backing-page population retain their existing costs.

| ID | Assumption | Basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|---|
| B1 | The modern native profile uses the recorded class-0 lengths, padding and write/fault order. | Native ARM64/x64/x86 length, pointer, guard and crossing-page probes. | Installed NTDLL basic-query path. | Repeat on another Windows build or physical x64/x86 kernel; test short/long, inaccessible padding and aliases. | Confirmed on the recorded ARM64 Windows installation; other kernels/builds unknown |
| B2 | Query output describes the existing emulated machine. | Guest VM/page/commit bounds, PEB and KUSER single processor; tick multiplier uses milliseconds. | Resource/CPU values and KUSER page count. | Vary arena rounding, large-address-aware PE flag and reserved backing; compare output with owner state. | Retained profile; 1 ms reported timer granularity is a modeled value, not the native host interval |
| B3 | Completing this query does not establish broader Win32 startup support. | Explicit unsupported service/class dispatch and executable startup probes. | Capability and completion claims. | Run all four installed-DLL images to their next real boundary. | Retained; current startup outcome recorded below |

Affected planes: Windows process construction/shared-data profile, checked guest
memory query and native service transport, default HLE query behavior, ABI tests
and documentation. Existing NTDLL export indices, number decoding, CPU semantics,
SMIR/JIT, C ABI 1.11.0, native selectors, read-only host backing and permission
model are unchanged. The shared Windows personality compiles and runs tests on
macOS, Linux and Windows; physical Windows behavior is checked on its native OS.
Assist compiles the same embedded RAX archive on all three through its existing
single-archive target; no host-specific source omission is introduced.

High, blocking full process emulation: broader NT services, native RTL heap and
loader bootstrap remain incomplete. Medium: private query behavior is bounded
to the recorded native build and its x86/x64 compatibility adapters. Neither
an unfiltered full-suite failure nor a passing leaf test is hidden by a startup
success claim. Non-blocking adjacent code is left unchanged.

### Basic-query validation

| Gate | Result | Evidence |
|---|---|---|
| macOS full RAX library binary | 7,460 passed; 0 failed; 2 ignored; 0 filtered | `/tmp/assist-native-basic-final-full-macos.log` |
| Linux full RAX library binary | 7,451 passed; 3 failed; 2 ignored; 0 filtered | `/tmp/assist-native-root-cpp-linux/native-basic-final-full.log`; prior multishot timeout, updated timeout and readiness/EINTR failures |
| Windows ARM64 full RAX library binary | 6,831 passed; 5 failed; 2 ignored; 0 filtered | `/tmp/assist-native-windows-29683/native-basic-final-full.log`; prior four BZHI assertions and FP16 host-feature failure |
| All five shared class-0 tests, normal/LAA profile test, installed ARM64/x86 leaf | Passed in the owning unfiltered binaries | Same full logs; native leaf test also verifies actual RET/RET imm16 cleanup |
| Complete C API packages | 168 passed; 0 failed; 0 ignored; 0 filtered on each OS | `/tmp/assist-native-basic-final-capi-macos.log`; `/tmp/assist-native-root-cpp-linux/native-basic-final-capi.log`; `/tmp/assist-native-windows-29683/native-basic-final-capi.log` |
| macOS current shipping archive / Assist | 5/5 CTests passed | `/tmp/assist-native-basic-root-macos-{build,ctest}.log` |
| Linux current shipping archive / Assist | Locked build; tool 184 checks, adapter 162 checks, disabled factory, ABI 2/2, one-archive link passed | `/tmp/assist-native-root-cpp-linux/native-basic-final-{shipping,cpp}.log` |
| Windows current shipping archive / Assist | Locked static-CRT build; tool 182 checks, adapter 162 checks, disabled factory, ABI 2/2, one-archive link passed | `/tmp/assist-native-windows-29683/assist-native-basic-final-{shipping,cpp}.log` |
| Current installed-DLL startup | All four pass classes 50 and 0, then stop at NtQueryInformationProcess class 0x24 with 4-byte output | `/tmp/assist-native-windows-29683/native-basic-final-archive-cpp-probe-output.log`; decoded service 0x19, no ordinary program completion claim |

The three full library binaries ran without filters. The Linux and Windows
full suites remain failing; passing affected tests, C API packages and archive
checks do not make them green. Two long Parallels command dispatches failed
before starting the Windows archive build. The exact pipeline then ran from a
task-local script, and actual logs/exit codes established its result; no build
success was inferred from either rejected dispatch.

Native aliases at offsets 0, 1, 8, 24, 40 and 60 establish that class-0 output
precedes ReturnLength on all three native process ABIs. The native x86
large-address-aware basic query returns inclusive maximum 0xFFFEFFFF, agreeing
with the guest's exclusive 0xFFFF0000 ceiling minus one. High, remaining ordinary
startup blocker: `NtQueryInformationProcess` class 36 (0x24), requesting 4 bytes.
The wider kernel/RTL bootstrap and full application/package acceptance remain
incomplete. Quality review records material assumptions, current full counts,
explicit prior failures, width/length/fault/padding/guard/alias/PE-flag cases,
retained primary/native provenance and bounded remaining limitations.

## Installed process-cookie query and system-probe correction

The installed startup's `NtQueryInformationProcess` class 36 (0x24,
`ProcessCookie`) has a checked four-byte guest result. The public Microsoft API
establishes its five arguments and optional `ULONG *ReturnLength`; class 36,
its handle right and its first-fault behavior are private observations on
Windows 10.0.29683.1000, not a public SDK guarantee. The primary document and
four independent native probe programs with ARM64/x64/x86 outputs
and the installed x86 NTDLL signature inspection are retained
under `docs/specifications/windows/native-process-query/`; `sources.json`
records provenance and byte-exact SHA-256 checksums. Compile each with MSVC
`/std:c++20 /EHsc`, using `-Arch arm64`, `-Arch amd64` or `-Arch x86` in the
ARM64-host VS developer shell. The policy probe creates, queries and terminates
only its own suspended child; it does not query arbitrary host processes.

| Step | ProcessCookie, all three guest ABIs | System classes 0/50, native 64-bit entry |
|---|---|---|
| 1 | For nonzero supplied length, require four-byte output alignment. | Require four-byte output alignment and probe the entire supplied output span. |
| 2 | Probe optional four-byte ReturnLength for writing, with unaligned storage allowed. | Probe optional four-byte ReturnLength for writing. |
| 3 | Require implemented class 36 and exact four-byte length; wrong length leaves ReturnLength unchanged. | Dispatch class/length; wrong length publishes the class-specific required length. |
| 4 | Validate current-process pseudo-handle or real current-process handle with PROCESS_VM_WRITE (0x20). | Validate/serialize the requested guest system fields. |
| 5 | Probe four output bytes, publish the process cookie, then publish ReturnLength=4. | Publish output, then ReturnLength. |

WoW64 system queries retain their separate conversion path. ProcessCookie's
output alignment applies to WoW64 too. Unknown process-query classes and
queries of unmodeled peer processes remain explicit unsupported operations.
Measured native queries of a real suspended child succeed with sufficient
rights; this personality owns only the current guest process's cookie.

Combined-fault probes falsified the previous system-query initial probe order:
misaligned output plus invalid ReturnLength must report
`STATUS_DATATYPE_MISALIGNMENT` on native 64-bit entry. Output guard plus read-only
ReturnLength must report `STATUS_GUARD_PAGE_VIOLATION` and consume the output
guard. The corrected handler probes output before ReturnLength. ProcessCookie
has a different measured order: the same guard/read-only combination reports
`STATUS_ACCESS_VIOLATION` and leaves the output guard armed. The new shared
regression failed against the previous system handler and passes after the
correction. Successful aliases publish output before ReturnLength; either
query's consumed guard returns a status without creating a guest SEH frame.

`Proc.process_cookie` is an eagerly initialized opaque 32-bit compatibility
value: `low32(seed XOR (seed >> 32)) XOR 0xA5A55A5A`. It remains stable for the
process lifetime, reproduces for an identical seed and does not consume or
change the existing PRNG stream. It is not a cryptographic guarantee and does
not claim uniqueness across processes. No guest query reads a host cookie or
forwards to a host NT service. Fixed four-byte output and ReturnLength probing
checks at most two pages each, taking O(1) additional work and storage; existing
system-query supplied-span bounds remain unchanged.

The selected x86 `NtQueryInformationProcess` has a measured 41-byte
conditional leaf. Its `CALL $+5; POP EDX` obtains the comparison location;
an image-base high-byte marker chooses `CALL FS:[0xC0]` or the conventional
exported WoW64 thunk. Both branches use `RET 20`; the five-argument caller's
stack advance is 4 + 20 = 24 bytes. Admission validates every fixed instruction,
the marker against the image's preferred base, identical cleanup counts and
the fallback thunk's exact reference to exported `Wow64Transition`. Partial,
hooked and mismatched patterns are rejected. Recognition uses O(1) work and
storage within the existing 64-byte stub window. The production thread
constructor already initializes FS:0xC0 when the selected NTDLL is loaded;
no host kernel transition or new TEB policy was added.

The native integration test creates a fresh installed-DLL process before
removing its thread for isolated calls. A previous test fixture loaded NTDLL
into a thread created in the built-in profile, leaving FS:0xC0 uninitialized;
its null fetch was rejected as evidence. The final test checks the actual
fresh-native TEB transition and executes the installed cookie leaf and
`RtlEncodePointer`/`RtlDecodePointer` round-trips, including zero, one,
0x12345678 and the ABI's maximum pointer. No RTL helper is replaced with HLE.
The full signatures and installed binary hash are retained; the DLL binary
is not redistributed.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| P1 | The recorded installed startup requires class 36 with a four-byte current-process output. | Four shipping C++ startup probes stopped at service 0x19/class0x24 after system queries. | Appended NT query and installed startup progress. | Actual DLL kernel entry and RET cleanup on each selected guest ABI. | Run a different installed DLL/build and capture the next boundary. | Confirmed for the recorded Windows installation; other kernels/builds unknown. |
| P2 | Class-36 length, alignment, handle-right and first-fault behavior follow the retained native probes. | Native ARM64/x64/x86 length, rights, alias, guard and combined-fault outputs. | Status and output publication order; system-query correction. | Wrong/huge length, null/invalid/unaligned/read-only destinations, guards, aliases and query-only handles. | Repeat native probes on another kernel/build; compare both system/process query fault combinations. | Revised: PROCESS_VM_WRITE required; output alignment first, ReturnLength probe before output pages; native system output-span probe first. |
| P3 | A process-owned deterministic opaque value suffices for this guest profile's cookie query. | Existing per-process seed/PRNG ownership; explicit no-host-query profile. | Stable guest value without altering prior random sequences. | Repeated queries, PRNG consumption, identical seeds and peer handles. | Observe a changed cookie, consumed random state, shared global value or host-cookie forwarding. | Retained compatibility assumption; no cryptographic or cross-process uniqueness claim. |
| P4 | The recorded conditional WoW64 leaf's two complete entry paths have the measured 41-byte form and matching caller cleanup. | Installed x86 NTDLL signatures and actual native execution. | Strict service-table admission for class 36. | Truncation, changed opcode/branch/TEB offset, unequal RET counts, wrong marker/base or fallback slot. | A changed pattern is admitted, or fresh-native selected NTDLL cannot execute the leaf. | Confirmed for the recorded installation; alternate encodings remain unknown and rejected. |

| Plane | Change / evidence |
|---|---|
| Windows personality / loader kernel frontier | Appended NtQueryInformationProcess export without shifting old indices; shared class-36 handler; corrected system initial probe order; complete conditional WoW64 leaf admission. |
| Process lifecycle / memory | Proc owns a stable cookie; main constructor and both isolated test constructors initialize it; checked guest writes and existing one-shot guard handling. |
| CPU/lifter/IR/optimizer/lowerers/JIT/hypervisors | No instruction or execution representation changes; installed DLL instructions execute through the existing interpreter. |
| C ABI / Assist products / packages | ABI stays 1.11.0; no new dependencies, lockfile changes, exported C prototypes, schema/default selection or package layout. Existing Rust archive membership compiles the same personality on Windows/macOS/Linux. |
| Tests / provenance | Five shared cookie tests, combined system-fault regression, conditional admission corruption/truncation tests, native installed-leaf/pointer round-trip test and byte-exact Microsoft/native references. |

High: wider NT/RTL heap, loader bootstrap and ordinary Win32/CRT startup remain
incomplete and block the full native-runtime goal. Peer-process query support
is explicitly unavailable, rather than publishing an invented peer cookie.
Medium: private Windows query behavior remains build-specific; physical x64/x86
kernels and other Windows builds have not supplied native oracle evidence.
Native IDA plugin/CLI/Qt harness execution and packaging remain separate from
pure Rust, C API, archive linkage and private Windows probes.

### Process-cookie validation

| Gate | Result | Evidence |
|---|---|---|
| macOS complete RAX library binary | 7,467 passed; 0 failed; 2 ignored; 0 filtered | `/tmp/assist-native-process-query-complete-full-macos.log` |
| Linux complete RAX library binary | 7,461 passed; 0 failed; 2 ignored; 0 filtered | `/tmp/assist-native-root-cpp-linux/native-process-query-complete-full.log` |
| Windows ARM64 complete RAX library binary | 6,839 passed; 5 failed; 2 ignored; 0 filtered | `/tmp/assist-native-windows-29683/native-process-query-complete-full.log`; same four BZHI lowerer assertions and FP16 host-feature failure |
| Five shared cookie tests, combined system-fault regression, conditional-leaf admission | All passed on all three OSes, in the owning unfiltered binaries | Same complete library logs |
| Installed NTDLL leaf and pointer encoding | Passed on Windows ARM64 and x86, with native-profile TEB, actual RET cleanup and pointer inverse checks | Same Windows complete library log |
| Complete C API packages | 168 passed; 0 failed; 0 ignored; 0 filtered on each OS | `/tmp/assist-native-process-query-complete-capi-macos.log`; `/tmp/assist-native-root-cpp-linux/native-process-query-complete-capi.log`; `/tmp/assist-native-windows-29683/native-process-query-complete-capi.log` |
| macOS current shipping archive / Assist | Locked build and 5/5 CTests passed | `/tmp/assist-native-process-query-complete-root-macos-{build,ctest}.log` |
| Linux current shipping archive / Assist | Locked build; tool 184 checks, adapter 162 checks, disabled factory, ABI 2/2, one-archive link passed | `/tmp/assist-native-root-cpp-linux/native-process-query-complete-{shipping,cpp}.log` |
| Windows current shipping archive / Assist | Locked static-CRT build; tool 182 checks, adapter 162 checks, disabled factory, ABI 2/2, one-archive link passed | `/tmp/assist-native-windows-29683/assist-native-process-query-complete-{shipping,cpp}.log` |
| Current installed-DLL startup | All four open and now exit with guest STATUS_ACCESS_VIOLATION (0xC0000005), rather than the previous unimplemented class-36 diagnostic; no ordinary program completion | `/tmp/assist-native-windows-29683/native-process-query-complete-archive-output.log`; fault instruction/address unknown; next falsification probe is boundary tracing before thread teardown |

The three complete library binaries ran without filters. The Windows complete
suite remains failing; passing the affected tests, C API packages and archive
checks does not make it green. Earlier Linux runs exhibited timeout/readiness
failures; their absence in this final run is not evidence of remediation.
The initial installed-x86 test's access violation and a diagnostic compile
failure were rejected; the final native-profile fixture and full binaries
establish the recorded results. Quality review covers exact input widths,
probe order, handles, aliases, guards, guest lifetime/PRNG, complete stub
admission, all three OS configurations, primary/native provenance, material
assumptions and bounded unresolved startup/application/platform proof.
