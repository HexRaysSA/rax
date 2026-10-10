# Installed Windows runtime selection

`WindowsConfig::native_libraries = true` selects read-only installed DLLs,
the installed version-6 API-set namespace, and an immutable snapshot of the
fixed system NLS CodePage registry key and installed NLS section tables on a Windows host. Its default is
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
queries (`NtQuerySystemInformation`, classes 0, 50 and 250), and the process-cookie
query (`NtQueryInformationProcess`, class 36). Other query classes remain
explicit unsupported operations.
Unrecognized WoW64 encodings, native RTL heap/bootstrap requirements,
the broader NT object/file/section/query surface and ordinary Win32/CRT startup
remain incomplete. Native-subsystem images load NTDLL without inventing the
Win32 KERNEL32/KERNELBASE roots; Win32 images select those installed DLLs too.

Class 250 is the extended processor-feature bitmap: bit `k` means PF `64 + k`.
Its recorded native 64-bit profile accepts lengths >=16 bytes in 8-byte
multiples, writes 16 bytes, and probes the entire supplied span first. The
WoW64 profile returns `STATUS_INVALID_INFO_CLASS` before destination probes.
The baseline 64 `KUSER_SHARED_DATA.ProcessorFeatures` bytes now use the same
guest CPU policy as the HLE API; the separately indexed extended bitmap does
not advertise unknown features or copy host capabilities.

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

## Processor-feature prerequisite and native heap diagnostic (2026-10-10)

The [processor-feature record](../../../docs/specifications/windows/native-processor-features/README.md)
retains primary documentation, exact source revisions/licenses, all three
native oracle logs, before/after diagnostic traces and 21 reference checksums.
The initial HLE process heap is incompatible with the installed RTL layout:
`0x10000 + 0x138` yields `0x80006`, then an 8-byte-offset read faults at
`0x8000E`. Clearing only `PEB.ProcessHeap` does not make native heap creation
succeed: native `RtlCreateHeap` instead dereferences an uninitialized lock
pointer. No exception-handler callback result is accepted as a heap handle.

The isolated native loader probe advances from 36 instructions at unsupported
class 250 to 141 instructions at unsupported `NtCreateEvent` after this query
prerequisite is implemented. The production lifecycle still lacks native NTDLL
process initialization and real RTL heap bootstrap; the four ordinary Windows
installed-DLL programs still terminate with `STATUS_ACCESS_VIOLATION`.

| Validation surface | Final result | Evidence |
|---|---|---|
| Before/after regressions | Two tests fail before; both pass after; four shared feature tests pass in every OS configuration | `/tmp/assist-native-processor-features-{before,after,expanded}-macos.log`; full logs below |
| macOS complete RAX library | 7,471 passed; 0 failed; 2 ignored; 0 filtered | `/tmp/assist-native-processor-features-full-macos.log` |
| Linux complete RAX library | 7,464 passed; 1 failed; 2 ignored; 0 filtered; recorded io_uring timeout-removal/update race | `/tmp/assist-native-root-cpp-linux/native-processor-features-full.log` |
| Windows complete RAX library | 6,844 passed; 5 failed; 2 ignored; 0 filtered; same four BZHI byte assertions and host FP16 execution failure | `/tmp/assist-native-windows-29683/native-processor-features-complete-full.log` |
| Installed query / RTL instructions | Selected ARM64/x86 query leaves and ARM64 RTL feature queries pass, including real RET cleanup and no kernel SEH frame | Same Windows full log; focused log has 5 passed, 0 failed |
| Complete C API package | 168 passed; 0 failed; 0 ignored; 0 filtered on each OS | `/tmp/assist-native-processor-features-capi-macos.log`; `/tmp/assist-native-root-cpp-linux/native-processor-features-capi.log`; `/tmp/assist-native-windows-29683/native-processor-features-complete-capi.log` |
| Current Assist archives | macOS 5/5 CTests; Linux tool 184 / adapter 162 / disabled factory / ABI 2/2 / archive link pass; Windows tool 182 / adapter 162 / disabled factory / ABI 2/2 / archive link pass | `/tmp/assist-native-processor-features-root-macos-{build,ctest}.log`; `/tmp/assist-native-root-cpp-linux/native-processor-features-{shipping,cpp}.log`; `/tmp/assist-native-windows-29683/assist-native-processor-features-complete-{shipping,cpp}.log` |

The query, shared startup bytes and HLE API are shared Rust on Windows, macOS
and Linux. CPU implementations, IR/JIT planes, dependencies, lockfiles,
public C ABI 1.11.0, defaults and package wiring are unchanged. Current archive
linkage does not establish a real IDA plugin, harness or package execution.
Assumptions F1-F4 and bounded high/medium limitations are maintained in the
linked record. Full failing suites remain failing; query tests do not erase
those failures or certify complete process emulation.

## Shared native NT events and next loader prerequisite (2026-10-10)

The [native-event record](../../../docs/specifications/windows/native-events/README.md)
retains primary API/attribute documentation, 17 checksummed reference inputs,
ARM64/x86/x64 native oracle logs and exact isolated loader before/after traces.
`NtCreateEvent`, `NtSetEvent` and `NtResetEvent` now operate on the same
reference-counted event objects as Win32 waits/state/close. Output widths,
unaligned destinations, guard consumption, native64/WoW64 argument ordering,
access masks and failed publication are covered across all guest ABIs.
`Object::Event.signaled` is now a LONG-compatible `i32`, preserving creation's
low BOOLEAN byte (including 2/255); wait readiness is nonzero, automatic reset
stores 0, and setting/resetting stores 1/0. The Rust field type changes;
C ABI 1.11.0 and the Assist process ABI remain unchanged.

Only unnamed process-local events with null security/name/QoS inputs are
admitted. Token/ACL/SACL privileges and named NT directory semantics remain
explicit unsupported paths. The native invalid-event-type status differs
from the public DDI list; the recorded build29683 profile and exact supported
partitions are documented in the linked record. No host NT event is used as
an emulated kernel backend, and no native RTL/loader helper is intercepted.

| Validation surface | Result | Evidence |
|---|---|---|
| Before/after regression | One failure before; pass after | `/tmp/assist-native-events-{before,after}-macos.log` |
| Shared/native event behavior | Seven shared tests on all host configurations; installed ARM64/x86 event leaves additionally pass on Windows | Complete logs below |
| macOS complete library | 7,478 passed; 0 failed; 2 ignored; 0 filtered | `/tmp/assist-native-events-complete-macos.log` |
| Linux complete library | Final 7,472 passed; 0 failed; 2 ignored; 0 filtered; earlier run retained 2 known timeout/signal failures | `/tmp/assist-native-root-cpp-linux/native-events-{complete-full,full}.log` |
| Windows complete library | 6,852 passed; 5 same BZHI/FP16 failures; 2 ignored; 0 filtered | `/tmp/assist-native-windows-29683/native-events-complete-final-full.log` |
| Complete C API | 168 passed on each OS | `/tmp/assist-native-events-capi-macos.log`; `/tmp/assist-native-root-cpp-linux/native-events-capi.log`; `/tmp/assist-native-windows-29683/native-events-complete-capi.log` |
| Current Assist archives | macOS five CTests; Linux tool 184 / adapter 162 / disabled / ABI 2/2 / archive pass; Windows tool 182 / adapter 162 / disabled / ABI 2/2 / archive pass | `/tmp/assist-native-events-root-macos-{build,ctest}.log`; `/tmp/assist-native-root-cpp-linux/native-events-{shipping,cpp}.log`; `/tmp/assist-native-windows-29683/assist-native-events-complete-{shipping,cpp}.log` |

The isolated loader probe passes `NtCreateEvent` at turn 141 and reaches
unimplemented `NtManageHotPatch` class 9/service `0x119` at turn 160,
guest PC `0x1800021D0`. These are zero-based diagnostic slice indices:
the earlier ledger's 36/141 instruction descriptions refer to that measure,
not an independent CPU retired-instruction count. Production native NTDLL
initialization/RTL heap bootstrap is still absent; the four ordinary Windows
installed-DLL startups still exit with `STATUS_ACCESS_VIOLATION`.
Native leaf evidence is separate from full startup, current C API/archive
proof is separate from real IDA/plugin/harness/package execution, and no
Linux timing/signal or Windows lowerer failure is claimed fixed.
Assumptions E1-E4, the Rust source-level field migration, and blocking
high/medium findings are reconciled in the linked record. Shared event code
compiles and runs in all three host OS configurations; Linux/Mach-O process
policy, ISA/SMIR/JIT implementations, dependency/default/lock/package wiring
and public C ABI remain unchanged.


## Native hotpatch availability and registry frontier (2026-10-10)

The [hotpatch query record](../../../docs/specifications/windows/native-hotpatch-check/README.md)
retains the pinned private phnt declaration/license by reference, 669 native
class-9 queries across ARM64/x86/x64, three observed red-green regressions,
and exact isolated loader before/after/extended traces. `NtManageHotPatch`
class 9 now reports the guest's unavailable patch capability, with native64
mandatory 4-byte ReturnLength publication and WoW64 length/capture/copy-back
semantics. WoW64 copies captured information back even after a kernel error;
a copy-back fault supersedes kernel status after kernel guard consumption.
Aliases and partial output preserve that sequence. Synthetic imports return
NT fault statuses rather than entering guest SEH. Other hotpatch classes
remain explicit unsupported results; no host patch operation is issued.

| Validation surface | Final result | Evidence |
|---|---|---|
| Shared query behavior | Five tests pass on every host configuration; installed ARM64/x86 NTDLL query leaf passes on Windows | Full logs below; `regressions-after.log` in linked record |
| macOS complete library | 7,483 passed, 0 failed, 2 ignored, 0 filtered | `/tmp/assist-native-hotpatch-full-macos.log` |
| Linux complete library | 7,477 passed, 0 failed, 2 ignored, 0 filtered; earlier 1 known multishot timeout failure retained | `/tmp/assist-native-root-cpp-linux/native-hotpatch-full.log`, `first-native-hotpatch-full.log` |
| Windows complete library | 6,858 passed, same 5 BZHI/FP16 failures, 2 ignored, 0 filtered | `/tmp/assist-native-windows-29683/native-hotpatch-complete-full.log` |
| Complete C API package | 168 passed on each OS | Current hotpatch C API logs specified in linked record |
| Current Assist archives | macOS five CTests; Linux tool184 / adapter162 / disabled / ABI2/2 / archive; Windows tool182 / adapter162 / disabled / ABI2/2 / archive all pass | Current hotpatch build/C++ logs in linked record |

The first Windows library attempt had an owned test compilation error, now
corrected and retained in the record; no test pass is attributed to that attempt.
The final Linux pass does not remediate its earlier timeout race. Public C ABI
1.11.0, Assist interfaces, ISA/SMIR/JIT implementations, dependencies, defaults,
locks and package wiring remain unchanged.

The explicit isolated trace observes `STATUS_NOT_SUPPORTED` and ReturnLength
0 at hotpatch slice 160, with Version 1 / Flags 0 unchanged. The earlier
Version-0 working assumption was falsified by that buffer capture. The loader
then reaches unimplemented `NtOpenKey` service `0x12`, PC `0x180001130`,
at slice 709, requesting the NLS CodePage registry key. These are zero-based
one-instruction-budget run-slice indices; 709 - 160 = 549 slice calls.
The diagnostic still clears guest PEB.ProcessHeap and supplies the modeled
initial context; production bootstrap/RTL heap integration is unchanged.
All four ordinary installed-DLL startups still fault. Assumptions P1-P5 and
high/medium limits are reconciled in the linked record. Full native startup,
NT registry/security/namespaces, full POSIX process behavior and the required
application/package matrix remain incomplete; the full goal remains active.


## Snapshot-backed NLS key services, 2026-10-10

The explicit selector reads only
`HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage`, with query-only
access, after installed NTDLL architecture validation. Two matching enumerations
and unchanged metadata fence observed instability, with three bounded attempts.
Raw names/types/data and the selected ordinal UTF-16 upcase table become private
immutable records; the host HKEY closes before selection returns. The default
supplied-only profile remains empty. Guest calls never forward names or access
masks to the host registry. The read-only guest grant is an explicit model,
not copied host token/DACL authorization. [The profile and assumption register](../../../docs/specifications/windows/native-nls-registry/README.md)
record bounds, private priority, unsupported scope and fidelity limits.

Appended native metadata selects `NtOpenKey` (3 arguments) and `NtQueryValueKey`
(6 arguments) from actual installed service stubs. No prior export index changes.
`Object::Key(Arc<Key>)` extends the Rust-visible object model; handles share
snapshot lifetime and close through the existing table. Native reads validate
class/type/access, capture counted UTF-16, publish ResultLength, and copy only
the defined output extent in page order. A later page fault retains earlier
writes. WoW64 captures query descriptors before class/handle checks, then reads text;
its open attribute conversion captures name text before output and private output
conversion. Its undefined scratch/error bytes are represented by private zeros,
not host allocator contents. Native output alignment is observed as 4 bytes even
for Align64 classes. Unaligned UNICODE_STRING descriptors are accepted. A short
name copy ending between UTF-16 bytes zeroes the incomplete byte. Raw data is
preserved without adding terminators. Synthetic NTDLL entries return NT fault
statuses with ordinary RET cleanup rather than invoking guest SEH.

The independent retained oracle performs 4,428 queries and 111 opens through
ARM64, x86 and x64 processes on the Windows ARM64 kernel. Its portable checker
verifies 3,402 aligned matrix rows, including status, required length, all defined
bytes and untouched tails. Five observed regressions pass after implementation:
two initially missing services, odd-name truncation, query descriptor/text capture
priority, and native odd-length rejection before text probing. Fourteen new
shared tests run all guest ABIs; two additional native Windows
tests compare actual raw metadata/all 65,536 case units and execute installed
ARM64/x86 NTDLL open/query/close leaves. Selected leaf success is separate from
native loader, heap and CRT startup.

| Final check | Result | Evidence |
|---|---|---|
| Complete macOS library | 7,497 passed, 0 failed, 2 ignored, 0 filtered | `/tmp/assist-native-registry-verified-full-macos.log` |
| Complete Linux library | 7,489 passed, 2 failed, 2 ignored, 0 filtered | `/tmp/assist-native-root-cpp-linux/native-registry-verified-full.log` |
| Complete Windows library | 6,874 passed, 5 failed, 2 ignored, 0 filtered | `/tmp/assist-native-windows-29683/native-registry-verified-full.log` |
| Complete C API | 168 passed per OS; no failures/ignored/filtered | Final C API logs on all three hosts |
| Current locked owning Assist archives and five production C++ checks | Passed on all three hosts | Final owning build/CTest/CPP logs |
| Compiled discovery checks | Both manifest tests pass; rebuilt macOS bridge plaintext scan passes | `/tmp/assist-native-registry-manifest-checks.log`, `/tmp/assist-native-registry-mcp-build.log` |
| Native metadata/case and NTDLL leaves | Passed on Windows ARM64 and x86 guest profiles | Windows complete library log |
| Ordinary Windows startup | Four controlled probes still end with STATUS_ACCESS_VIOLATION | `/tmp/assist-native-windows-29683/native-registry-verified-archive-output.log` |

The Linux final failures are `a_timeout_is_removed_or_updated` and
`finite_empty_and_expired_waits`. An exact-parent full run passes 7,477 tests;
an attempted switch back reused that parent binary and reproduced those same
two failures with the parent test count. That run is **not current-tree proof**.
The source was rebuilt after `cargo clean -p rax`, then the final two capture-order
corrections triggered another rebuild selecting 7,493 total tests, including all
fourteen new shared tests. The first pre-correction Linux
run also failed `a_multishot_timeout_reports_each_expiry` and
`timers_do_not_outlive_exec_or_cross_fork`; the latter was not reproduced by the
single passing parent run and is not claimed as confirmed pre-existing.
No Linux implementation/test assertion was changed. Retry results are not
remediation evidence. Windows failures are the same four BZHI assertions and
host-unavailable FP16 case recorded for the parent. The first Windows validation
attempt stopped during a private resource transfer before tests; the subsequent
complete and final runs are separately recorded.

The isolated ARM64 loader trace returns success from NtOpenKey at slice 709,
publishes guest handle `0x18`, queries ACP at slice 749 (`REG_SZ`, raw `1252\0`,
22-byte partial result), queries OEMCP at slice 928 (`437\0`, 20-byte result),
and closes at slice 1056. It next stops at slice 1101 on NtGetNlsSectionPtr,
service `0x101`, PC `0x180002050`, with arguments
`[11, 1252, 0, 0x1803BDD00, 0]`. PHNT declares five arguments, and the observed
loader passes a null SectionSize despite its declared required output.
No NLS-section result is fabricated. The 392-slice delta from 709 to 1101 counts
one-instruction scheduler calls, not proven retired instructions. This private
probe clears PEB.ProcessHeap and invokes LdrInitializeThunk with saved guest
context; it is not exact native-kernel entry or production RTL heap evidence.
The original trace source, before/after captures and checksums are retained.

| Plane | Effect or reason unaffected |
|---|---|
| Runtime selection, kernel, objects, memory, scheduling | Fixed NLS acquisition; typed guest key lifetime/access; counted query serialization, guard/status/copy priorities and native service metadata |
| Public Rust/C API and persistence | Additive public Rust object variant; stable C ABI 1.11.0/layout unchanged; no persisted schema/checkpoint or dependency/lock/default change |
| Assist tool/schema/rendering/UI/context/agent/conversation | Existing option and worker ownership; description discloses fixed metadata; schema, backend requests, transcript, widget/IDA dispatch unchanged |
| Permissions/mesh/MCP/transport/crypto | Existing native-runtime read_files_outside gate precedes selection; regenerated encrypted discovery description; no guest host-registry forwarding, permission-policy, route or transport change |
| Windows/macOS/Linux and products | Shared kernel/model tests compile/run on all three; Windows adapter runs natively; current owning archives link production C++ adapter/factory/ABI checks on all three. Same archive membership reaches plugin, CLI and Qt harness. Full plugin/harness/package/application matrix remains overall-goal work |
| ISA/SMIR/JIT/optional engines/release | No touched contracts, source or wiring; no dependency/default/ABI-version/packaging changes or release publication |

Assumptions R1-R6 are reconciled in the linked register. High-impact remaining
work is full native loader/RTL heap/CRT startup and wider NT/NLS/security/registry
coverage, plus the complete application/package/native-platform goal matrix.
Medium limits are arbitrary host snapshot concurrency and exact undefined WoW64
scratch lifecycle. No nonblocking adjacent implementation was added.

## Installed NLS section mappings and view policy, 2026-10-10

Explicit selection captures actual NtGetNlsSectionPtr mapping bytes for installed
code-page candidates plus five normalization forms and the case table. Capture
unmaps every owned host view before return. Guest services never call the host
interfaces and retain no host address. Each section is bounded to 8 MiB and
aggregate bytes to 64 MiB. The fixed CodePage snapshot and native system-directory
names supply candidates; arbitrary host updates are not an atomic transaction.
The supplied-only profile has no selected NLS section namespace.

Appended metadata supplies NtGetNlsSectionPtr (5 arguments) and
NtUnmapViewOfSection (2 arguments) without moving prior export indices. Guest
queries create distinct page-rounded read-only MEM_MAPPED views from immutable
bytes. SectionSize is optional; aliases overwrite pointer output with size.
Native64 probes both nonnull outputs before pointer-width ContextData capture;
WoW64 captures that input first and preserves kernel status when optional size
copy faults. Guards, misalignment, null outputs and unknown types follow retained
build29683 observations. Error size bytes are outside defined-field fidelity.

Native probes exposed a second contract: these views reject writable/copy/
executable/noaccess/guard protections, private release/decommit and repeated
private commitment. The common virtual-memory manager seals only NLS views,
so every NT/Win32 caller receives the same section policy. NtProtectVirtualMemory
reports PAGE_NOACCESS as old protection on its rejected NLS change. Interior
unmap releases the whole owned view and returns commitment; private/absent
addresses return STATUS_NOT_MAPPED_VIEW, with typed/access-checked process
handles. Other mapped/image sections and other processes remain unsupported.
Public Rust VmError adds AlreadyCommitted and CannotDeleteSection; C ABI
1.11.0/layouts are unchanged. The new NT-to-Win32 error mappings follow measured
installed RtlNtStatusToDosError values rather than guessed defaults.

[The exact profile, assumptions N1-N5 and primary/oracle records](../../../docs/specifications/windows/native-nls-sections/README.md)
include 1,596 original NLS requests, 12 native RTL error conversions, a portable
independent checker, three observed regressions, eight shared tests and two
installed Windows tests. Actual file comparisons validate all eight table
contents and padding. Installed ARM64/x86 NTDLL map/unmap leaves return normally
without guest SEH. Shared tests execute x86/x64/ARM64 guest semantics on all
three host operating systems. This is separate from native loader/heap/CRT
startup and physical Intel-kernel coverage.

| Final source validation | Result and evidence |
|---|---|
| Complete macOS RAX library | 7,505 passed, 0 failed, 2 ignored, 0 filtered; `/tmp/assist-native-nls-verified-full-macos.log` |
| Complete Linux RAX library | 7,495 passed, 4 failed, 2 ignored, 0 filtered; `/tmp/assist-native-root-cpp-linux/native-nls-verified-full.log` |
| Complete Windows RAX library | 6,884 passed, 5 failed, 2 ignored, 0 filtered; `/tmp/assist-native-windows-29683/native-nls-verified-full.log` |
| Complete C API | 168 passed, no failures/ignored/filtered on every OS; corresponding verified C API logs |
| Current locked owning Assist archives | Rebuilt on all three; five production C++ adapter/factory/ABI/link checks pass; verified CTest/CPP logs |
| Compiled discovery | Manifest CTests 2/2, rebuilt macOS bridge protected-text scan; embedded exact-JSON native probes on all three recorded separately |
| Installed NTDLL/table file checks | Both native Windows tests pass; ARM64/x86 leaves and eight independent file/padding comparisons |
| Ordinary native startup | All four controlled Windows programs still exit with STATUS_ACCESS_VIOLATION; verified archive-output log |

The final complete library binaries select 7,507/7,501/6,891 tests on
macOS/Linux/Windows, without filters. Linux failures are
`a_multishot_timeout_reports_each_expiry`, `a_timeout_is_removed_or_updated`,
`finite_empty_and_expired_waits` and `timers_do_not_outlive_exec_or_cross_fork`.
The first three were reproduced on earlier parent/feature binaries; the fourth
remains unclassified and is not claimed as confirmed pre-existing. The earlier
NLS run reports only the multishot failure. No Linux assertion/implementation was
changed and passes are not remediation. Windows retains the same four BZHI
assertions and host-unavailable FP16 case. The first final Windows attempt had
Parallels result retrieval exit255/no logs and is excluded; the exact private
validation script was rerun and its complete results captured. An initial
private macOS manifest link omitted required system frameworks; the corrected
probe includes the owning archive's actual framework/library dependencies.

The final owning-archive loader trace succeeds on both code-page mappings:
ACP type 11/data1252 at slice1101 (view `0xAC0000`) and OEMCP type11/data437
at slice1112 (view `0xAE0000`), each 69,632 bytes and read-only MEM_MAPPED. It then
stops at slice2412 on NtQueryVirtualMemory, service0x23, PC0x180001240, arguments
`[-1, 0x180000000, 6, 0xABE930, 24, 0]`. The 1,311-slice advance counts scheduler
calls, not proven retired instructions. The diagnostic clears PEB.ProcessHeap
and enters LdrInitializeThunk with saved context; production native bootstrap
and RTL heap initialization remain incomplete. Ordinary installed-DLL probes
still terminate with STATUS_ACCESS_VIOLATION.

| Plane | Effect or evidence of unchanged ownership |
|---|---|
| Runtime/kernel/objects/memory | Selection-only NLS capture, immutable records, guest view ownership, common sealed section policy, appended exports and precise NT/DOS statuses |
| Rust/C ABI/persistence | Two additive public Rust VmError variants; stable C ABI 1.11.0; no persistent schemas, ABI layouts, dependencies, locks or defaults |
| Assist schema/tool/UI/context/agent/history | Existing option/session/worker ownership; copy adds installed tables, schema and all other tools unchanged; no widget/IDA-thread or backend change |
| Permission/MCP/mesh/transport/crypto | Existing read_files_outside gate precedes acquisition; compiled discovery regenerated; no guest host calls, route or permission-policy change |
| Windows/macOS/Linux/products | Shared model/kernel/view rules compile/run on all three; actual Windows acquisition, file comparison and installed leaves run natively; existing common archive membership serves plugin/CLI/Qt harness. Complete native IDA/package/application matrix remains overall-goal work |
| ISA/SMIR/JIT/optional engines/release | No touched source/contracts, default features, dependency pins, build wiring or release publication |

High-impact blocking work remains full native loader/RTL heap/CRT startup, wider
NT section/query/security/registry services, broader POSIX/process semantics and
complete application/package coverage. Medium limits are private compatibility
error bytes and arbitrary host update atomicity. Low-impact cross-process
snapshot sharing remains unimplemented. Full process emulation remains active.

## Guest virtual-memory queries (2026-10-10)

NtQueryVirtualMemory metadata is appended without moving previous exports:
six arguments `[Ptr, Ptr, I32, Ptr, Ptr, Ptr]`, including pointer-width SIZE_T
length and return-length destination. Classes 0/6 report the authoritative
guest VM's basic region or image base/size. Querying a guarded/noaccess target
does not read it. Free class-6 addresses return STATUS_INVALID_ADDRESS;
reserved/private/mapped allocations return a zero image record. Complete
executable image mappings report UNCHECKED signing and no uncreated kernel
CFG/SCP extension, partial-map or no-execute flag. Host trust is not inherited.
The current-process pseudo-handle or typed current-process handles with either
PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION are admitted;
VM_READ alone is insufficient. Closed, wrong-type, denied and upper-bound
addresses return explicit statuses. Other processes and other declared classes
remain explicit unsupported frontiers. No host syscall or IDA operation runs.

Native 64-bit entry checks class/minimum length/address limit, requires 8-byte
output alignment, probes the complete supplied extent then optional SIZE_T
destination, validates the process, writes the defined record and publishes
length last. WoW64 first probes optional 4-byte return length; its fault consumes
a guard and disables publication. It then validates/copies only the 28/12-byte
converted record, accepts null/unaligned output and preserves kernel/output
status on optional length faults. Shared output/length guards can therefore
produce successful output with no length publication. Separate guards return
the output guard status and consume both. An earlier first-output-guard
assumption was falsified by independent byte captures; its abandoned test is
retained as discarded evidence, not a regression claim. The actual shared-page
regression fails on the pre-correction implementation and passes afterwards.

[The retained profile and assumptions V1-V4](../../../docs/specifications/windows/native-virtual-memory/README.md)
include three original programs, 1,245 queries across native ARM64 and
compatibility x86/x64 on Windows 10.0.29683.1000, pinned PHNT declarations,
Microsoft DDI/signing-level sources, raw CRLF output, an independent checker
and two valid observed regressions. The checker validates matrix/fault/boundary/
rights/priority/alias records and counts the other-class inventory. Physical
Intel kernels, native 32-bit kernels and other Windows builds are unverified.
Ten shared tests execute all guest ABIs on each host. The installed Windows
test executes actual ARM64/x86 NTDLL leaves, normal return/stack cleanup,
image/NLS/private semantics, optional/misaligned return length and shared guards.

| Final source validation | Result and evidence |
|---|---|
| Complete macOS RAX library | 7,515 passed, 0 failed, 2 ignored, 0 filtered; `/tmp/assist-native-vm-query-final-full-macos.log` |
| Complete Linux RAX library | 7,509 passed, 0 failed, 2 ignored, 0 filtered; `/tmp/assist-native-root-cpp-linux/native-vm-query-final-full.log` |
| Complete Windows RAX library | 6,895 passed, 5 failed, 2 ignored, 0 filtered; `/tmp/assist-native-windows-29683/native-vm-query-final-full.log` |
| Complete C API | 168 passed, no failures/ignored/filtered on every OS; corresponding final C API logs |
| Registered user_windows integration | 544 passed on macOS/Linux; Windows selects 0 because cfg(unix), explicitly excluded as native coverage |
| Registered user_windows_memory | 4 passed on native Windows; macOS/Linux select 0 because cfg(windows), explicitly excluded as memory runtime coverage |
| Current locked owning Assist archives | RAX rebuilt on all three; five production C++ adapter/factory/ABI/archive-link checks pass; final build/CTest/CPP logs |
| Installed NTDLL query leaves | Native Windows test passes with ARM64/x86 actual selected DLLs, including shared guards |
| Ordinary native Windows startup | Four controlled programs still return STATUS_ACCESS_VIOLATION; final archive-output log |

The final complete library binaries select 7,517/7,511/6,902 tests on
macOS/Linux/Windows without filters. Windows retains the same four BZHI
assertions and host-unavailable FP16 case; no lowerer/assertion was changed.
An earlier source run had the two Linux multishot/remove timeout failures;
later absence is not remediation and their cause remains unresolved. The
previous NLS register's readiness and exec/fork timer failures remain historical
unresolved evidence. Intermediate suite passes do not validate the subsequent
WoW64 correction. The original boundary transfer had Parallels result retrieval
exit255 and is excluded; complete original source/log captures were obtained
by rerunning the unchanged experiment. Formats/source hashes and reference
hashes are checked separately. No stable C ABI/layout/dependency/lock/default,
discovery/schema/permission/packaging/ISA/SMIR/JIT change is included.

The final owning-archive isolated loader trace passes NtQueryVirtualMemory
class6 at slice2412, service0x23, PC0x180001240, returning base0x180000000,
size0x473000 (4,665,344 bytes) and guest flags0. It then reaches class4 at
slice2778, same service/PC, arguments
`[-1, 0, 4, 0xABF530, 80, 0]`. The 366-slice difference is scheduler calls,
not proven retired instructions. The diagnostic still clears PEB.ProcessHeap
and enters LdrInitializeThunk with saved context; production loader/RTL heap/
CRT entry is incomplete. Broader NT services, guest CFG/SCP/integrity,
POSIX/process coverage and native application/package/IDA matrices remain
high-impact blocking work for the overall goal. Medium limits are undefined
WoW64 error length bytes, unresolved suite failures and other-build fidelity;
additional private query classes are a low-impact diagnostic opportunity.


## 2026-10-10: guest working-set array queries

NtQueryVirtualMemory class4 now consumes MemoryWorkingSetExInformation arrays.
The existing six-argument metadata and service indices are unchanged. Records
are 16 bytes on native64 and 8 bytes on WoW64. Required minimums, the separate
BaseAddress bound, native8-byte alignment/full supplied output/optional return
probe, and WoW64 optional-return preprobe/input-capture/handle/output ordering
follow 684 original build29683 observations. Native publishes supplied length;
WoW64 publishes the complete-record prefix and ignores incomplete tail bytes.
Read-only input with invalid handle, null input, huge requests, target/output
versus return guards and aliased bytes are tested independently of class0/6.

AddressSpace::is_resident reads PTE validity without translating or touching
queried pages. Actual allocation/state-run protection determines valid records,
resident guarded/no-access invalid-location records, and zero records for lazy,
reserved, released or invalid addresses. Target guard and residency are retained.
Current Windows mappings own private anonymous frames: image/NLS labels do not
imply sharing. Normal priority5, node0 and absent locking/large-page/standby/
graphics state follow the current closed guest memory model. WoW64 converted
16-byte-record storage is logically bounded by guest backing capacity, returning
STATUS_NO_MEMORY before input capture above that budget; the native host
exhaustion threshold is unknown and is not inherited. The implementation uses
O(1) auxiliary storage, O(q+n(log a+log s)) work for probe pages q, records n,
allocations a and state runs s, without a proportional guest-controlled host Vec.

Primary material, two original programs/raw three-ABI outputs, a missing-service
red/green regression, independent checker, source hashes and W1-W3 assumptions
are retained in docs/specifications/windows/native-working-set. Ten new shared
cases run all guest ABIs on all hosts; a Windows-only actual installed
ARM64/x86 leaf case additionally verifies return/stack cleanup and residency.
Final unfiltered library results: macOS7525 passed/0failed/2ignored,
Linux7519/0/2, Windows6906/5/2. Selections7527/7521/6913, all0filtered. The
five Windows failures remain four BZHI assertions and host-unavailable FP16;
no lowerer/assertion/skip change. Earlier Linux timing failures remain unresolved
historical evidence despite their absence here. Separate complete C API168
passes on all three, and current owning Assist archives rebuild RAX with all
five production adapter/factory/ABI/archive checks passing. Registered Unix
user_windows544 passes on macOS/Linux; Windows excludes it by cfg(unix).
All-target builds pass on all three; native user_windows_memory4 passes, with
cfg(windows) exclusions on macOS/Linux recorded explicitly.
The first Windows transfer and initial Windows-only test-constructor compile
were corrected and excluded from passing library proof; the final full run and
five transferred source hashes establish the reported Windows result.

The current-owning-archive isolated loader trace passes class4 at slice2778,
service0x23, PC0x180001240, [-1,0,4,0xABF530,80,0], preserving all five code
addresses and returning flags0x05000201. It reaches NtOpenKey at slice3237,
service0x12, PC0x180001130, requested Session Manager registry key outside the
selected NLS snapshot. Delta459 is scheduler calls, not retired instructions.
This diagnostic clears PEB.ProcessHeap and enters saved LdrInitializeThunk
context; no production native bootstrap/RTL heap/CRT completion is established.
All four ordinary controlled Windows programs still return STATUS_ACCESS_VIOLATION.
Wider native NT/registry/bootstrap, POSIX process/symlink and native IDA/package/
application matrices remain high-impact blockers for the overall goal. C API
1.11.0/layouts/dependencies/locks/defaults, permissions/discovery/schema/package
wiring and all ISA/SMIR/JIT/other-guest implementations remain unchanged.


## 2026-10-10: Session Manager registry snapshot

Native runtime selection now captures two fixed SYSTEM keys: NLS CodePage and
Session Manager. Portable lookup shares one immutable 65,536-unit UTF-16 upcase
table. Keys retain raw value types/bytes and survive through typed guest handles
when the namespace drops; codepage discovery is explicitly scoped to NLS.
Unknown keys/subkeys remain unsupported. Capture opens query-only host HKEYs
sequentially, samples metadata/two identical enumerations with three bounded
attempts, closes each native handle before returning, and retains no host
callback. The keys are not acquired in a cross-key transaction.

The constructor bounds aggregate count to 4,096, raw names/data to 16 MiB,
names to 16,383 UTF-16 units and value data to 1 MiB. Enumeration now reuses
scratch and retains only returned bytes after budget checks. An original native
regression detects the inherited truncation/capacity defect (five-unit name,
18-unit capacity); current native assertions pass. Capture transient raw payload
can reach 48 MiB plus at most 1,081,344 scratch bytes and O(N) metadata; final
raw payload is 16 MiB maximum plus folded-name copies/table/metadata. For N
values, B raw bytes, maximum name length L and U=65,536 table entries, work is
O(U+B+N*L*log(N+1)) plus host calls; storage O(U+B+N).

The source/provenance/assumption register is
[docs/specifications/windows/native-session-manager/README.md](../../../docs/specifications/windows/native-session-manager/README.md).
It retains 153 original Windows 10.0.29683.1000 opens/query observations across
ARM64 native and x86/x64 compatibility, independent checker, primary declarations/
Microsoft shared-key and alternate-view sources/licenses, two observed native
regressions, exact source/log hashes and the current loader diagnostic. Two new
portable model cases, one all-guest-ABI NT case and one native acquisition case
pass; the existing installed NTDLL case now opens/queries/closes both keys using
actual selected ARM64/x86 leaves. Other releases/native32/physical Intel remain
unverified, and sampled capture cannot exclude restored concurrent mutations.

Final unfiltered library: macOS 7,528 passed/0 failed/2 ignored, Linux
7,520/2/2, Windows 6,910/5/2; selections 7,530/7,524/6,917, all 0 filtered.
Linux retains remove-timeout/readiness failures; Windows retains four BZHI and
host-unavailable FP16. The prior source's Windows thread-clock assertion fails
at 15,625,000*4 = 62,500,000 ns versus 62,500,000 ns; final absence is not
remediation. No timing/lowerer assertions or skips changed. C API 168 passes
on all three, all-target builds pass, registered Unix integration 544 passes
on macOS/Linux (cfg(unix) Windows exclusion), and native external memory 4
passes (cfg(windows) exclusion elsewhere). Current locked owning Assist archives
recompile RAX and pass five production C++ checks on every OS. Compiled CLI
manifest regeneration and both macOS manifest checks pass; current description
discloses fixed registry scope. Windows-only final storage/test changes do not
alter the portable compiled source; corrected Windows gates/hash checks pass.

The private cleared-PEB-heap/saved-context current-archive loader opens Session
Manager at turn 3,237, queries absent RaiseExceptionOnPossibleDeadlock at 3,248,
and reaches Image File Execution Options at 3,405, service 0x12,
PC 0x180001130, access 9. Delta 168 is scheduler calls, not retired instructions.
All four ordinary native Windows probes remain STATUS_ACCESS_VIOLATION.
Production native loader/RTL heap/CRT, wider NT/registry, POSIX/process/symlink
and complete native application/package/IDA matrices still block the full goal.
C API 1.11.0/layouts/options/schema/dependencies/locks/defaults/permissions/package
wiring and ISA/SMIR/JIT/other guest semantics are unchanged.


## 2026-10-10: IFEO immutable loader-policy subtree

Native Windows selection adds a complete bounded subtree below the fixed Image
File Execution Options (IFEO) root, alongside NLS CodePage and Session Manager
values. All keys share one installed ordinal case table. Raw value types/bytes
and descendant keys are immutable, owned through typed ancestor/child handles,
and survive namespace drop. Guest names never reach native registry APIs.
Native acquisition opens query/enumerate-only HKEYs (access 9), closes parents
before descendants, and uses at most three metadata/double-sample attempts per
key. Only error 2 at the optional fixed root establishes known absence; an
enumerated child disappearing aborts acquisition. No cross-key transaction,
parent replacement or restored-mutation exclusion is claimed [I3,I4].

IFEO has <=1,024 keys including root, root-zero depth <=32, child components
1..255 UTF-16 units and aggregate full-path bytes <=1 MiB. All roots share the
4,096-value/16 MiB raw name/data budget, name <=16,383 units and data <=1 MiB.
Pending siblings reserve the global key budget before enumeration. Constructor
and acquisition reject collisions/exhaustion; retained values copy exact returned
bytes. Known absent children/root return 0xC0000034; repeated/trailing backslashes
are ignored, '.'/'..'/'/' are literal names, and rooted relative names fail
0xC000003B. Other namespaces remain explicitly unsupported [I1,I2,I4].
NtQueryKey/NtEnumerateKey are not implemented by this group. Resource arithmetic,
algorithmic/storage complexity, complete plane map and the Assumption Register
are in [IFEO evidence](../../../docs/specifications/windows/native-ifeo-registry/README.md).

Two original read-only C++ oracles yield 2,889 observations on Windows
10.0.29683.1000 ARM64 plus compatibility x86/x64 across all three view flags.
Independent replay checks raw root/49-child metadata/names, end status and 15
relative-path statuses. The separate final native walk checks all 54 keys,
106 values and 4,756 raw name/data bytes; a child-failure injection reaches two
opens and aborts with error 2. Actual root absence remains controlled adapter
coverage, not an observed native absent-profile case [I4]. Four portable model
cases and three all-guest-ABI NT cases pass on all hosts, plus two native
acquisition cases and actual selected ARM64/x86 NTDLL leaves. Primary sources,
licenses, original raw logs, regressions, exact source/final-log hashes and the
private current-archive loader diagnostic are retained with provenance.

Unfiltered library: macOS 7,535 pass/0 fail/2 ignore/0 filter, Linux 7,528/1/2/0,
Windows 6,919/5/2/0; selections 7,537/7,531/6,926. Linux retains multishot timeout
and earlier remove-timeout/readiness evidence; Windows retains four BZHI/FP16
failures and historical strict-clock evidence. No unrelated assertion/lowerer/
skip changed. These suites precede final formatting and a Windows-only
injection-test budget isolation adjustment. Final focused selections are seven
on macOS/Linux and nine on Windows, plus one actual installed NTDLL case;
all-target builds, complete C API 168 cases and current locked owning Assist
archives/five production C++ checks pass on all three. Registered Unix cases
544 pass on macOS/Linux, cfg(unix) excludes Windows; native memory four pass,
cfg(windows) excludes other hosts. Final macOS CLI compiled manifest reproduces
exact bytes, both manifest checks pass within seven relevant CTests, and protected
CLI/MCP plaintext scans pass. The generated manifest changes only the tool
description. Initial test compilation/target naming/log retrieval mistakes are
excluded from passing proof; exact final Windows transferred hashes match.

The isolated saved-context/cleared-PEB-heap trace opens IFEO at turn 3,405 and
returns known absence for probe.exe. It reaches fixed Session Manager\Segment
Heap at turn 4,462, NtOpenKey service0x12, PC0x180001130, access1, outside the
selected namespace. Delta1,057 is scheduler calls, not instructions. All four
ordinary native Windows programs still return STATUS_ACCESS_VIOLATION. Production
native loader/RTL heap/CRT, wider native services, POSIX process/symlink and full
native application/package/IDA matrices still block the overall goal. C API
1.11.0/layouts/defaults/options/schema/dependencies/locks/permissions/package
wiring and ISA/SMIR/JIT/other guest semantics remain unchanged.


### Optional fixed Segment Heap snapshot (2026-10-10)

Native Windows selection captures optional fixed Session Manager\Segment Heap
values or records actual root absence. Only fixed RegOpenKeyExW error2 means
absence; other open/later capture errors fail selection. Metadata/double matching
raw value samples obey remaining shared4,096-value/16 MiB limits, with three
bounded attempts. A parent-owned selected child and immutable shared value maps
preserve absolute/relative opens and old namespace/parent-handle lifetimes,
without cloning parent raw payload or charging child values twice. Unknown
siblings/subkeys stay unsupported; a present child under a parent reporting
zero children is rejected. Guest key strings never reach the native adapter.
No ABI1.11.0/layout/options/defaults/schema/permission/dependency/package/ISA change.

The independent query-only oracle observes9 paired native/Win32 opens (18
operations), all absent, on Windows29683 nativeARM64/compatibilityx86/x64 and
view0/0x100/0x200. Actual configured-present profile is unknown. Two model and
two all-guest-ABI NT cases pass across hosts; three native acquisition cases
include a controlled real query-only Session Manager HKEY and independent
RegQueryValueExW comparison, without modifying registry settings. Final Windows
focused7 and installed NTDLL leaf1 pass; baseline absence regression failed
before implementation. Parent/child cross-key transactions and ABA exclusion
are not claimed. Assumptions, bounds, complexity, planes, raw original sources,
primary licenses and exact phase/source/log hashes are in [Segment Heap evidence](../../../docs/specifications/windows/native-segment-heap-registry/README.md).

Unfiltered library pass/fail/ignore/filter is macOS7,539/0/2/0,
Linux7,531/2/2/0, Windows6,926/5/2/0; selections7,541/7,535/6,933.
Linux retains two known io_uring timeout assertions; Windows retains four BZHI
assertions and one FP16 assertion; historical readiness/clock evidence remains unresolved. Full suites
precede only strengthening an independent Windows-native query assertion;
production/shared sources are identical. All-target builds/CAPI168/current
locked owning Assist archives/five production C++ checks pass all three.
RegisteredUnix544 passes macOS/Linux and is cfg-excluded Windows; native memory4
passes Windows and is cfg-excluded elsewhere. macOS seven relevant CTests,
CLI-generated description-only manifest and protected CLI/MCP scans pass.
Container Linux evidence is distinct from physical native x86-64 proof.

Private saved-context/cleared-PEB-heap current owning-archive trace returns
Segment Heap NAME_NOT_FOUND at turn4,462 and reaches NtQuerySystemInformation
class62 at turn11,206, service0x36, PC0x1800013a0, supplied64 bytes; it remains
explicitly unsupported. Delta6,744 is scheduler calls, not instructions. Four
ordinary native Windows programs still return STATUS_ACCESS_VIOLATION. Native
production Ldr/RTL heap/CRT, wider NT/POSIX and full application/package/IDA
matrices still block the overall goal; this group claims only its bounded scope.


### Native emulation basic information (2026-10-10)

NtQuerySystemInformation class62 (SystemEmulationBasicInformation) now uses the
existing guest basic-information serializer/probe contract. Original native
ARM64/compatibility x86/x64 and separate x86 LAA oracles confirm class0 equality
on build29683, exact44/64-byte lengths, x86 three-byte untouched padding,
4-byte native64 output alignment, ABI-specific fault/write order, one-shot
guards and output-then-ReturnLength aliases. Guest VM backing/address limits and
one virtual CPU govern returned values; no guest query reaches the host kernel.
For64 MiB backing /4096-byte pages=16,384 pages; timer10,000*100 ns=1 ms.
Class114 is a native comparison control and remains outside this implementation.
Assumptions, complete planes, complexity, sources/licenses, original result bytes
and exact source/gate hashes are in [emulation basic evidence](../../../docs/specifications/windows/native-emulation-basic/README.md).

Independent replay verifies196 reported queries plus four successful alias
baseline queries. Six portable cases fail before implementation and pass after;
one native Windows case executes actual installed host-ABI/x86 NTDLL leaves and
real return/stack cleanup. Full formatted-source library pass/fail/ignore/filter
is macOS7,545/0/2/0, Linux7,537/2/2/0, Windows6,933/5/2/0; selections
7,547/7,541/6,940. Linux retains two known timer assertions and Windows four BZHI
plus one FP16 assertion; historical readiness/clock evidence remains unresolved.
No unrelated assertion/skip/lowerer changed. Complete C API168/all-target builds/
locked owning Assist archives/five production C++ checks pass all hosts. Unix544
passes macOS/Linux with Windows cfg-exclusion; native memory4 passes Windows with
other-host cfg-exclusion. Owning macOS CLI/seven CTests (both manifest checks) and
protected CLI scan pass. Initial Linux rustup network refresh fails before tests;
selecting the installed verified pinned1.95.0 toolchain reruns the complete gates.
Container translation remains distinct from physical native x86-64 proof.

Private current-owning-archive saved-context/cleared-PEB-heap Ldr diagnostic
returns class62 success at11,206 and reaches unsupported NtAllocateVirtualMemoryEx
service0x78 PC0x1800017c0 at11,315: delta109 scheduler calls, not instructions.
Four ordinary Windows apps remain AV; production Ldr/RTL heap/CRT and broader
NT/POSIX/native application/package/IDA goal remain incomplete. C API1.11.0,
ABI/layout/options/defaults/schema/persistence/permissions/dependencies/packages,
metadata/discovery and ISA/lowerers are unchanged.
