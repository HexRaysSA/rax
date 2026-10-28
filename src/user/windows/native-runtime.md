# Installed Windows runtime selection

Mapped-file queries now retain the selected backing file or section identity
through allocation lifetime. Class 2's native/WoW64 layouts, copy ordering and
independent measurements are documented in
[native-mapped-filename](../../../docs/specifications/windows/native-mapped-filename/README.md).

Native image acquisition distinguishes logical PE bytes, executable extension
bytes and trailing reserved owner pages. A coalesced reserved query region is
bounded to the logical byte copy while its complete allocation lifetime and
image metadata are retained. See the independent kernel controls and limits in
[native-image-view-reserved-tail](../../../docs/specifications/windows/native-image-view-reserved-tail/README.md).

The x86 TEB allocation includes two private pages. Installed build-29695 NTDLL
writes its scheduler data pointer at `TEB+0x1018`; a one-page placement aliases
that write with `PEB.ProcessHeap`. Ordinary TEBs and WoW64 companion pairs now
own the complete extent through teardown and reuse. See the bounded trace and
regressions in [native-teb-extent](../../../docs/specifications/windows/native-teb-extent/README.md).

Installed x86 selection uses a consistent pure x86 process profile: SysWOW64
NTDLL and relative `KnownDlls32` opens select the same pure x86 image family.
The native host machine and WoW64 CPU flags retain their real ARM64 values.
Explicit CHPE namespace resources remain available; selecting their mixed-ISA
code is a separate capability. Native per-process controls and the bounded
startup result are recorded in
[native-x86-chpe-profile](../../../docs/specifications/windows/native-x86-chpe-profile/README.md).

`WindowsConfig::native_libraries = true` selects read-only installed DLLs,
the installed version-6 API-set namespace, and an immutable snapshot of the
fixed system NLS CodePage registry key and installed NLS section tables on a Windows host. Its default is
false. `host_filesystem = false` still denies general guest host-file access;
native library selection is a separate, explicit input grant. A different host
OS or unmatched installed NTDLL architecture returns an error.

Native process construction enters the selected installed `LdrInitializeThunk`
with a saved architecture `CONTEXT` for installed `RtlUserThreadStart`. Initial
public `PEB.ProcessHeap`, `PEB.Ldr` and `TEB.ThreadLocalStoragePointer` are zero;
RTL owns their initialization. Host HLE heap/module allocations remain private
mapping and parameter bookkeeping. Built-in DLL mode retains its synthetic
startup. This entry change does not establish complete native application startup.

The selector obtains the Windows and system directories through wide Win32
APIs, and obtains the actual version through `RtlGetVersion`. Canonical host
paths remain distinct from guest paths: the `\\?\` prefix added by Windows
canonicalization is not placed in guest loader/process parameters. Installed
DLL files and declared PE image bytes are bounded to 67,108,864 bytes. A selected
image extension may add up to 131,072 bytes to its allocation, as described below.
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
unimplemented NT operations stop explicitly. Guest syscall arguments are never
forwarded to host NT. Narrow native-input adapters acquire selected file and
section metadata using only host-owned handles, views and buffers.

Supported kernel operations include checked NtClose, memory allocation/free/
protection, context continuation, forced termination and bounded installed
startup queries. The native dispatch/query source and the recorded semantic
groups below own the implemented classes and their exact buffer contracts.
Other query classes remain explicit unsupported operations.
Unrecognized WoW64 encodings, remaining NT services required by RTL bootstrap,
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
| Actual written bytes | 41; final 3 bytes unchanged | ARM64: 64 with zero padding; native AMD64: fields only, padding preserved | Native canaries and inaccessible-tail probes |
| Timer / +4 | 10,000 units of 100 ns | Same | Guest 1 ms tick granularity; declared profile value |
| Page size / +8 | 4096 bytes | Same | `PAGE_SIZE` |
| Physical pages / +12 | Usable backing bytes / 4096 | Same | `VirtualMemory::commit_limit`; excludes reserved frames, no paging file |
| Physical arena bounds / +16,+20 | 0 through last backing-frame index | Same | Actual guest physical-memory extent |
| Allocation granularity / +24 | 65,536 bytes | Same | `ALLOCATION_GRANULARITY` |
| Minimum user address | +28 | +32 | `VirtualMemory::low()` |
| Maximum user address | +32 | +40 | `VirtualMemory::high() - 1`, inclusive; x86 normal/LAA limits differ |
| Affinity mask | +36 | +48 | 1, matching the single virtual processor |
| Processor count | +40 | +56 | 1, matching PEB, KUSER_SHARED_DATA and guest environment |

Processor classes 1/63 and the WoW64 native-query entry use distinct caller,
kernel and legacy views. Class114 retains a native 64-byte basic record even
for a WoW64 caller. See the [processor adapter contract](../../../docs/specifications/windows/native-system-processor-information/adapter.md)
for the measured probing order, virtual CPU policy and validation boundaries.

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


### Native extended private allocation (2026-10-10)

NtAllocateVirtualMemoryEx captures its seven arguments and guest extended
parameter records, preserving default allocation and implementing nonzero
address requirements through the existing guest VM allocator. Inclusive upper
bounds,64 KiB base granularity, power-of-two alignment, bottom-up/top-down
selection, occupied/untracked mappings, x86 PE LAA limits and null-base implicit
COMMIT reservation have portable coverage. Full16*count-byte capture precedes
type validation. WoW64 captures all low-type1 pointed requirements first;
low-type1/3 conversion supplies aligned records, while unconverted arrays need
8-byte alignment. Invalid NUMA validation follows requirement capture and
process VM_OPERATION access, before allocation/protection. Native64 retains
sequential type/requirements capture. No guest allocation reaches a host native
allocation API. C API1.11.0/layouts/defaults/options/schema/permissions/
dependencies/packages/ISA and ordinary allocator contracts are unchanged.

Independent replay verifies1,356 original ARM64/compatibility x64/x86/x86 LAA
native observations, including aligned upper64-bit NUMA payloads, mixed capture
faults and handle/protection precedence. Twelve portable tests cover the final
adapter. Six original cases and the later conditional-alignment/mixed-capture
regressions fail before their respective corrections. The installed ARM64/x86
NTDLL entry case passes exact real RET cleanup and guest reserve/commit/data
assertions. Its initial x86 caller-stack/scratch overlap is corrected by restoring
the caller frame before each invocation; production policy is not changed by
that test correction. Failed compiler/transport/helper attempts are excluded.

Final macOS library pass/fail/ignore/filter is7557/0/2/0, selection7559, with
portable12, C API168, all-target compilation and Unix544 passing. Final Linux
full library reports7550/1/2/0, selection7553, retaining the known remove/update
io_uring timer failure. The final Windows library reports6946/5/2/0, selection6953, retaining four
BZHI and one FP16 assertion; allocation13 and C API168 pass. Windows all-target compilation/native memory4 and final owning archive/five
C++ consumers pass. The final private continuation reproduces the three
allocation successes followed by unsupported NtOpenPartition at turn12,660. Linux C API168/all-target compilation and
Unix544 serial integration pass; final owning Linux archives/five C++ consumers
and macOS CLI/seven CTests/protected scan pass at rootf7ff5347. Earlier matrices
are retained by exact source phase; they do not validate subsequent semantics.
A parallel Linux integration stalls and its owned container is stopped after
process/wait evidence capture; the cause is unknown. The final serial selection
retains all fixtures and assertions. Linux container translation is separate
from physical native x86-64 proof. The evidence register records full counts,
primary sources/licenses, source/gate hashes, assumptions and affected planes:
[extended allocation evidence](../../../docs/specifications/windows/native-allocate-ex/README.md).

The earlier private owning-archive saved-context/cleared-PEB-heap Ldr diagnostic
returns allocation success at turns11,315/11,397/11,542 for reservations of
33,558,528/4,295,098,368 bytes and an intervening4,096-byte commit. It reaches
unsupported NtOpenPartition service0x131 PC0x180002350 at12,660. Delta1,345 is
scheduler calls, not instructions. The final owning-archive rerun reproduces that frontier with the identical
source. The diagnostic does not alter production startup. Four ordinary Windows
applications still return STATUS_ACCESS_VIOLATION. Production native Ldr/RTL
heap/CRT, wider NT/POSIX and the full application/package/IDA matrices remain
the overall goal's acceptance gates.

### Modern process-parameter extent (2026-10-11)

The process parameter header now reserves and zeroes the complete layout through
Windows 11 22H2 HeapMemoryTypeMask:708 bytes (0x2C4) for x86 and1096 bytes
(0x448) for x64/ARM64. The previous676/1040-byte extents ended before modern
optional fields. On the installed29683 NTDLL, a load at parameters+0x420 copied
the following image-path string into HeapPartitionName. That malformed
descriptor caused the earlier NtOpenPartition request; it did not establish a
valid default partition dependency. Existing checked zeroed allocation now
keeps the entire tail zero and disjoint from pointed-to strings.

The independent pinned PHNT declarations and four suspended-child observations
confirm exact offsets and zero defaults. The new registered regression checks
all three guest architectures with two image names, arguments, environment and
current directory; the clean old-extent baseline fails, and the correction
passes on macOS/Linux/native Windows. Native aggregate Length/MaximumLength
values include additional storage; RAX's separately allocated strings and
header extent are explicitly distinguished.

Full library pass/fail/ignored/filtered counts are7558/0/2/0 on macOS,
7551/1/2/0 on Linux and6947/5/2/0 on Windows. Linux retains a multishot-timeout
assertion with cause unknown; Windows retains four BZHI and one FP16 failure.
C API168 and all-target compilation pass on all three. Unix Windows-fixture544
passes on macOS/Linux; native Windows memory4 passes. All five owning C++
consumers pass on every host; macOS CLI/seven CTests/protected scan also pass.
Storage interruptions, the corrupted Windows archive, failed cache recovery
and subsequent successful paired rebuild are retained separately.

The identical private saved-context/cleared-heap diagnostic no longer calls
NtOpenPartition. Its three allocations still succeed; it reaches unsupported
NtQuerySystemInformationEx service0x16E, class0x6B, PC0x180002720 at turn13286.
13286-12660=626 scheduler calls, not instructions. Four ordinary native startup
probes still return STATUS_ACCESS_VIOLATION. No production bootstrap, new
partition service, public C ABI, permission, default, persistence, dependency,
package or ISA change is claimed.

Primary sources/licenses, originals, exact source/artifact/gate hashes,
assumptions and quality gates are retained in
[process parameter evidence](../../../docs/specifications/windows/native-process-parameters/README.md).

## Native processor-group query

The six-argument `NtQuerySystemInformationEx` now implements class107 /
RelationGroup4 through admitted NTDLL services. It projects the existing single
guest CPU/group, count1 and mask1, with exact76/80-byte WoW64/native64 records.
The four native profiles establish distinct alignment, span checks, partial
field conversion, alias publication, ReturnLength ordering and guard behavior;
all1490 observations and their hashes are retained. Other classes/relationships
remain explicit unsupported stops, without host kernel forwarding.

Eleven portable regressions pass on macOS/Linux and, with the selected installed
leaf test, twelve pass on Windows. Final full library pass/fail/ignored/filtered
counts are7569/0/2/0,7562/1/2/0 and6959/5/2/0 respectively. C API168, all-target
builds, affected integration and all five owning C++ consumers pass on each.
macOS CLI/seven CTests/protected scan also pass. Linux's retained timeout failure
passes in the isolated nine-test timeout run; Windows retains the four BZHI and
one FP16 failures. These are distinct limits, rather than all-suite success.

The byte-identical owning diagnostic now succeeds at the former group-query
stop13286 and reaches class197 of NtQuerySystemInformation at turn33364:
33364-13286=20078 additional scheduler calls, not instructions. Ordinary native
startup still returns STATUS_ACCESS_VIOLATION. Full bootstrap remains incomplete.
Primary definitions, native originals, assumptions, replay and owning artifact
identity are in [processor-group evidence](../../../docs/specifications/windows/native-processor-groups/README.md).

## Native hypervisor shared-page query

NtQuerySystemInformation class197 now returns a pointer-width guest null for
the existing profile with no hypervisor timing-page mapping:4 bytes on x86 and
8 bytes on x64/ARM64. All902 native observations cover lengths, pointer probes,
aliases, partial boundaries, guards and upper-user-range precedence. Native64
probes the full declared output and ReturnLength before dispatch; WoW64 performs
its converted4-byte store before ReturnLength and handles null output separately.
The selected wrapper reserves align_up(u64(length)+4,16) temporary bytes plus
16-byte heap linkage. Guest no-paging-file quota projects that backing with
4096-byte rounding, before nonnull destination probes, without caller-sized host
allocation or persistent VM mutation. Host failure threshold between captured
16 MiB success and approximately2 GiB failure is unknown.

Final portable11 and selected native Windows12 targeted cases pass. Full
pass/fail/ignored/filtered counts are7580/0/2/0 on macOS,7573/1/2/0 on Linux and
6971/5/2/0 on Windows. C API168/all-target builds and affected integration pass
on each. Linux retains the multishot timeout failure, with its isolated nine
timeout tests passing; Windows retains four BZHI and one FP16 failure. All five
owning C++ consumers pass on each host, and macOS CLI/seven CTests/protected
scan pass. Native Windows paired archives pass complete member walks and the
fresh continuation uses the same owning build's feature-empty core artifact.

The identical private cleared-heap/saved-context diagnostic now succeeds at
class197 turn33364 and reaches unsupported NtQuerySystemInformation class55
at33566:202 additional scheduler calls, not instructions. Ordinary smoke,
MSVCRT/UCRT streams and whoami still return STATUS_ACCESS_VIOLATION; production
bootstrap remains incomplete. No public ABI, dependency, permission, persistence,
default or package change is introduced. Primary contracts, original native
observations, symbol identities, falsified initial expectation, source/artifact
hashes, assumptions and final gates are retained in
[hypervisor-page evidence](../../../docs/specifications/windows/native-hypervisor-page/README.md).

## Native NUMA processor-map query

NtQuerySystemInformation class55 now projects the existing node0/group0 and
one guest processor, HighestNodeNumber0 and mask1. The full PHNT declarations
are264/1032 bytes, but selected native query output is variable: lengths4..23
write only HighestNodeNumber and report4 bytes; lengths>=24 also write a16-byte
affinity at+8 and report24 native bytes or20 WoW64 bytes. Reserved at+4 and
unused entries remain intact. Selected WoW64 forwards the original output/length
with a private native ReturnLength, converts affinity in place and publishes
caller length only after success. The native tail beyond converted20 bytes
survives. Both caller types enforce DWORD output alignment and full declared
write-span probes; caller ReturnLength is preprobed only on native64. Native64
upper output range rejection leaves a guard armed, while a crossing direct
ReturnLength consumes its first-page guard. ULONG_MAX output guards precede
later span faults without temporary capture allocation.

Four native profiles retain1584 status/byte/alias/guard observations. Matching
Microsoft DLL/PDB symbols and the class55 body independently establish in-place
mask folding and ReturnLength arithmetic. Eight portable tests and nine native
Windows targeted tests pass, the latter including ten actual installed leaves.
Full pass/fail/ignored/filtered counts are7588/0/2/0 on macOS,7581/1/2/0 on Linux
and6980/5/2/0 on Windows. C API168/all-target builds and affected integration
pass on each. Linux retains the remove/update timeout assertion, with its nine
isolated timeout cases passing; Windows retains four BZHI and one FP16 failures.
Owning Linux five C++ consumers and macOS CLI/seven CTests/protected scan pass.
The first ULONG_MAX fixture's ReturnLength guard lay inside the huge output
span; adding an inaccessible gap corrects the observation expectation without
changing product code. No public ABI, default, permission, dependency, persistence,
ISA or package change is introduced. Source hashes, primary declarations,
original captures, symbol identity, assumptions and recorded gates are retained
in [NUMA-map evidence](../../../docs/specifications/windows/native-numa-map/README.md).


Fresh native Windows owning five C++ consumers and paired Assist/core archive
walks also pass; the continuation uses the owning feature-empty core artifact.
The byte-identical private loader diagnostic succeeds at class55 turn33566 and
reaches unsupported class107/relationship6 at40500:6934 additional scheduler
calls, not instructions. Four ordinary programs retain STATUS_ACCESS_VIOLATION.
A separate observer leaves production startup/PEB/context unchanged and records
the first exception at1459, NTDLL PC0x180026528: the0x10000 HLE heap handle leads
to X8=0x80006 and a failing read at0x8000E. Terminal1500 is0xC0000005. Source
publishes the HLE heap into PEB.ProcessHeap and uses synthetic RtlUserThreadStart;
that bootstrap/heap contract remains a full-goal blocker, outside this query.
The exact internal NTDLL routine name is unknown. The evidence checker verifies
the final22 gates, exact retained failures, paired continuation and first fault.


## Installed loader startup and private HLE ownership

Native construction now keeps public PEB.ProcessHeap, PEB.Ldr and initial
TEB.ThreadLocalStoragePointer zero, while retaining the host's private HLE
allocator/module lists for mapping and process parameters. It resolves selected
installed LdrInitializeThunk/RtlUserThreadStart and enters the former with saved
architecture CONTEXT and NTDLL base. The saved main parameter is PEB; secondary
parameters and full register/FPU state are preserved. Checked bounded stack
scratch sits below saved application SP and above the loader call frame; no new
VM scratch allocation is required. Context/frame placement is O(1) for fixed ABI
sizes, with existing export lookup cost on first resolution.

Native thread attachment occurs only at the exact resumed RtlUserThreadStart PC,
releasing the existing initial-process scheduling gate without host DLL/TLS
notifications. Built-in startup remains unchanged. Native exit uses installed
RTL/NtTerminate routes. Alertable NtContinue now applies the checked replacement
context before testing guest alerts or delivering queued APCs; see the owned
continuation section below.

Six independent suspended-child initial PEB/context/TEB captures cover ARM64,
x64 compatibility and WoW64. ARM64/WoW64 child-only loader breakpoints confirm
CONTEXT/NTDLL-base arguments and successful teardown. x64 compatibility's live
callable-export capture fails; physical pure x64 entry/stack proof is unknown.
Compatibility live entry thunks differ from selected on-disk exports. The pure
x64 saved SP-8 return slot is a retained callable-ABI inference. Matching ARM64
PE/PDB/unwind metadata identifies the previous heap fault as
RtlpAllocateNTHeapInternal+0xD8, RVA0x26450..0x267B0 (exclusive end,864 bytes).

Eight portable and nine Windows startup tests pass, including installed
ARM64/WoW64 cold construction. Two observed baseline reversals fail at the old
nonzero private LDR/TLS pointer. Full macOS7596/0/2 and Linux7590/0/2
pass/fail/ignored; Windows6989/5/2 retains four BZHI and one FP16 lowering failure.
C API168, all-target builds and affected integrations544/544/4 pass with explicit
cfg exclusions. All five owning C++ consumers pass on all three hosts; macOS
CLI/MCP rebuild, seven CTests and two protected-text scans pass. These are separate
from native IDA/Qt/package execution.

Fresh owning Windows Assist/core archives have complete4673/260-member walks,
eight matching compiled source hashes and a feature-empty core. Four ordinary
programs (smoke, MSVCRT/UCRT streams, whoami) now reach explicit class107
relationship6 internal failure instead of the previous access violation. The
byte-identical unmodified observer begins with ProcessHeap0, records no exception
and reaches that stop at40500; before it faults at1459 and exits0xC0000005 at1500.
40500-1500=39000 additional scheduler calls, not instructions. C API reason5 with
exit_code0 is internal failure, not successful guest completion. Wider NT services,
alertable continuation, applications and native-platform/package coverage remain
full-userland blockers. No public ABI/default/dependency/persistence/schema or
package change is introduced. Source/capture/archive provenance,21 recorded gates,
reconciled assumptions and positive/negative replay are in
[bootstrap evidence](../../../docs/specifications/windows/native-bootstrap/README.md).

## NUMA node and extended node query (2026-10-11)

NtQuerySystemInformationEx class107 now admits RelationNumaNode1 and
RelationNumaNodeEx6 for modeled node0/group0/CPU0, alongside RelationGroup4.
Both return Relationship1, NodeNumber0, GroupCount1, active mask1/group0 and
zero reserved fields. Required size is48 B native64 or44 B WoW64:
header8 + node prefix24 + affinity(pointer-width+8). No host topology or kernel
query is forwarded. Existing six-argument transports and explicit unsupported
class/relationship stops remain. Construction uses fixed O(1) scratch/time;
declared-span probes retain the owning page-walk behavior.

Native64 retains DWORD alignment, whole-output probing and direct ReturnLength
preprobe. WoW64 publishes node DWORD, reserved SIMD16/WORD, count WORD, zero
affinity QWORD/DWORD, group WORD, folded-mask DWORD, header8, then length4.
Faulting field stores leave their partial prefix untouched; completed prior
stores persist. Bytes44..48 remain untouched. Input capture precedes aliasing
output/length publication; null optional ReturnLength, misaligned pointers,
short input/output, ULONG_MAX, page boundaries and one-shot guards match the
selected installed-build observations. Matching WoW64 DLL/PDB (RSDS/DBI age1
versus information age3) and named converter RVA0x99C8/body0x9CA8 establish
this order without redistributing the proprietary DLL/PDB.

Four native producer profiles retain1402 original observations; independent
status/byte/fault replay checks1346 relevant rows, while56 unimplemented
class/relationship matrix rows remain explicitly shape/hash-only evidence.
Twelve portable tests pass on all hosts; a thirteenth native Windows test
executes installed ARM64/WoW64 leaves and exact caller cleanup. Full
macOS7608/0/2, Linux7601/1/2 and Windows7001/6/2 pass/fail/ignored are recorded.
Linux's multishot-timeout and Windows's thread-clock tests pass separately in
isolation, preserving their full-run failures of unknown cause. The five
existing Windows BZHI/FP16 lowering failures remain. C API168, all-target
builds and integration544/544/4 pass with exact cfg exclusions. Five owning
C++ consumers pass per host; macOS CLI/MCP, seven CTests and two protected-text
scans pass. These are not package/IDA/Qt native proof.

Fresh native Assist/core archives pass4673/260-member walks, four owned plus
eight byte-identical startup source checks, and empty-core-feature selection.
The byte-identical ordinary observer receives length mismatch at40500, its
48-byte NUMA retry succeeds at41325, and it stops at NtCreateIoCompletion0xB2
at42051:1551 additional scheduler calls, not instructions. All four owning
ordinary programs report reason5/exit_code0/internal failure at that next
service, with no claim of successful process completion. At that capture,
alertable NtContinue, I/O completion, wider NT services and full
application/package/IDA validation remained outstanding. Physical pure x64 Windows proof and native x86-64 Linux
proof remain distinct from ARM64 compatibility/container translation.

Primary captures, producer/machine identities, A1-A3 reconciled assumption
register, full plane map,23 recorded gates, strict manifest/negative replay
and exact ordinary observer pairing are in
[NUMA-node evidence](../../../docs/specifications/windows/native-numa-node/README.md).

## Native I/O completion construction (2026-10-11)

NtCreateIoCompletion now constructs a real reference-counted guest IoCompletion
object with empty queue, measured access/inheritance and effective unsigned
concurrency. Zero projects to the guest CPU count1; every nonzero ULONG is
retained. Constructor and close do not forward a host completion port or imply
packet/dequeue/file-association/runnable-thread scheduling support. The observed
port flag mask0x1EE2 rejects OBJ_PERMANENT, unlike event mask0x1EF2. Shared event
capture/access/publication helpers retain event behavior and diagnostics.

Native64 probes its full8 B byte-aligned output before aligned48 B attributes;
WoW64 converts unaligned24 B attributes before its4 B output probe. Bad Length
leaves output untouched; WoW64 kernel validation failures copy zero only after
successful conversion/probing. Capture precedes output/attribute aliases, guard
consumption follows measured order, and failures/final close preserve counts.
Non-null name/security/QoS and ACCESS_SYSTEM_SECURITY remain explicit policy
boundaries rather than guest authority inferred from the SYSTEM oracle.

Four303-row constructor and four21-row RootDirectory captures retain1296 original
observations;1184 exact replay rows and112 explicit policy/privilege exclusions
are checked. Five portable tests pass on all hosts; Windows's sixth executes
installed ARM64/WoW64 creation/close leaves and x86RET16 cleanup. Event regressions
pass. Full macOS7613/0/2, Linux7606/1/2 and Windows7008/5/2 pass/fail/ignored remain
separate from selected gates: Linux's multishot-timeout fails with two expiry
records rather than one but passes alone; cause unknown. Windows retains four
BZHI/one FP16 lowering failures. C API168, all-targets and integrations544/544/4
pass; a concurrent Windows clean/doctest collision is recorded and recovered
through separate test/owning targets. Five owning C++ consumers pass per host,
with current-root macOS CLI/MCP, seven CTests and protected-text scans passing.

Fresh native archives pass4673/260-member walks,18 source hashes and empty core
feature selection. The identical10,919 B observer now gets NTSTATUS0 at42051 for
NtCreateIoCompletion0xB2/PC0x180001B60 and stops at42076 for NtCreateWorkerFactory
0xD5/PC0x180001D90:25 additional scheduler calls, not instructions. All four
ordinary programs still report reason5/exit_code0/internal failure. Worker-factory
threadpool semantics, wider NT/security/I/O/APC behavior and successful full
applications remain full-goal requirements. The strict manifest,25 gates,
primary/producer/source/archive provenance, assumptions, scope and positive/four
negative validations are in
[I/O completion evidence](../../../docs/specifications/windows/native-io-completion-create/README.md).

## Native worker-factory construction (2026-10-12)

NtCreateWorkerFactory now constructs a real TpWorkerFactory with transactional
completion-port/process dependency ownership, measured ten-argument transports,
native/WoW64 capture/probe/handle/access/alias/guard order and final-close release.
ULONG maximum0 is retained; raw entry/parameter/nonzero stack values are stored;
zero stack defaults65536 B/4096 B are independent of actual PE stack defaults.
Four-profile captures plus changed-stack probes retain3622 observations, with
1868 exact basic/order replays and112 explicit nested-policy/privilege exclusions.
Portable5/5 and native6 constructor gates pass; full7618/0/2,7611/1/2,7014/5/2
pass/fail/ignored preserve the existing Linux timeout and Windows lowering failures.
C API168, all-target builds, integrations544/544/4 and five owning consumers per
host pass; macOS CLI/MCP, seven CTests and protected-text scans pass. Native4673/260
archive member walks bind22 source hashes and empty core features. The identical
observer succeeds at42076 and stops at NtCreateTimer2 at42165,89 more scheduler
calls. Four ordinary programs still report internal failure, not guest exit.
Activation/waits/packets/security/APC and successful full applications remain
full-goal requirements; provenance, assumptions, metadata correction and limits:
[worker-factory evidence](../../../docs/specifications/windows/native-worker-factory-create/README.md).

Timer2 construction, native ID/alias order, dormant IRTimer and measured limits:
[Timer2 evidence](../../../docs/specifications/windows/native-timer2-create/README.md).

Native symbolic-link open/query (2026-10-13) now uses captured KnownDllPath
targets and grants with guest-owned immutable identity and handle lifetimes.
Native64/WoW64 input, output, guard, alias, optional terminator and descriptor
copy ordering replay 131,944 independent native rows on all three hosts.
Seventeen portable focused tests and 18 Windows tests pass, including installed
ARM64/x86 NTDLL and RET 12/16 B caller-stack cleanup. This supplies selected NT
link services; complete ordinary installed-library execution and guest exit
remain separate acceptance criteria. Exact provenance, assumptions, scope and
validation limits:
[symbolic-link evidence](../../../docs/specifications/windows/native-symbolic-link-open/README.md).


## Native absent image-extension query (2026-10-13)

NtQueryVirtualMemory class 14 now describes complete guest PE images without
kernel CFG/SCP extension owners, consistent with class-6 ImageExtensionPresent=0.
Native64 preserves valid type/flags, writes zero RVA/size, then optional 24 B
ReturnLength. WoW64 rejects the unavailable conversion after its existing optional
4 B ReturnLength preprobe. Whole SIZE_T write probes, overflow/user-range guard
suppression, pointer/handle/rights/flags/type order and aliases follow the actual
build29683 captures; no guest input is forwarded to a native host query.

Thirteen actual producers bind 83,088 mature native observations: 80,568 exact
portable replays plus 2,520 explicit native present-SCP controls. Two complete
fresh ARM64 original-entry/true-LR cases restore the exact native handle set.
Five portable tests and the sixth installed ARM64/WoW64 leaf test pass. Full
suite outcomes are recorded in the evidence table: macOS and Linux pass, while
Windows retains the exact four BZHI/one FP16 baseline failures. C API (168 tests),
all-target builds, integrations and five owning C++ consumers per host pass; macOS CLI/MCP,
seven selected CTests and protected-text scans pass in scoped frozen embeddings.
Native archives pass 4673/260-member walks, 92 actual source hashes and empty
core features. The unchanged 11,177 B observer advances 97,257->114,140:
114,140-97,257=16,883 scheduler calls. Three ordinary programs now stop at
NtSetInformationProcess class 112/service 0x1C/PC 0x1800011D0; installed whoami.exe
stops at NtTraceEvent 0x5E/PC 0x180001620. All four retain reason 5/internal failure;
exit_code0 is not a proved guest exit. Full same-host process support remains
an active incomplete goal. Kernel extension ownership, broader native builds,
physical x64 kernel and whole current-root plugin/GUI/package validation remain
explicit limits. The independent partition/provenance checker and all 17 controlled
falsifications pass; reconciled assumptions, complete plane map and evidence are
in [image-extension evidence](../../../docs/specifications/windows/native-image-extension/README.md).

## Native scheduler shared-data constructor (2026-10-13)

NtSetInformationProcess class 112 returns a guest-owned SchedulerSharedData
handle with grant 1/flags 0 for the current process. Native64 validates nonzero
output alignment/range, exact 8 B length, handle/type/SET_INFORMATION rights,
then probes before birth. WoW64 uses exact 4 B length and kernel birth before
caller copy; copy faults preserve the unreturned live process-owned handle.
Writable reached guards consume once; read-only guards deny without consumption.
Input bytes are ignored; final alias close/drain release resource identity.
Slot/data operations and other process owners remain explicit unsupported
boundaries; no guest requests reach host NT. Actual build 29683 setter evidence
resolves PHNT's query-only comment without modifying the primary snapshot.

All 16016 native constructor rows and 204 births replay; two complete fresh
original-entry/true-LR cases restore native ownership. Two portable and three
Windows focused tests pass, including installed ARM64/WoW64 ABI cleanup.
Full macOS 7737/0/2, Linux 7731/0/2 and Windows 7148/5/2 outcomes retain the exact
four BZHI/one FP16 Windows baseline failures. Scoped owning archives/consumers
and actual 95 source hashes pass; native core features remain empty.
The unchanged 11177 B observer advances114140->115067 (+927 scheduler calls).
Three ordinary programs reach NtSetInformationThread class 57/service 0xD;
whoami.exe retains NtTraceEvent 0x5E. All four stop before a proved guest exit.
Physical x64-kernel, other builds and whole current-root plugin/GUI/package
claims remain unknown or excluded. Assumptions, 21 controlled falsifications,
complete plane map and exact evidence are in
[scheduler-data evidence](../../../docs/specifications/windows/native-scheduler-shared-data/README.md).

## Native scheduler shared-data thread slot (2026-10-13)

The constructor-only frontier is superseded by NtSetInformationThread class57.
Captured native24B/WoW12B records use Action/owner/slot at offsets0/8/16 and0/4/8.
Native64 full writable probing precedes exact length; WoW64 length/read/kernel
operation precede the unconditional converted caller copy. Hidden bindings
survive copy faults. Thread grant0x20 and owner grant0x1 are required; free1
ignores owner/slot fields; assignment0 validates the owner before refusing an
already bound/noncurrent thread. Other actions retain measured NOT_SUPPORTED.

Owners reserve8192B MEM_MAPPED RW; initial commitment4096B grows to8192B for the
second64 slots. Each slot is64B; active capacity128, exhaustionC000009A.
Free preserves bytes and assignment zeroes64B. A binding pins its owner after
final handle close. Thread exit and even partially consumed table drains queue
and reclaim all views. Allocation identity prevents ABA clearing/retirement.
Explicit native unmap preserves a stale cached returned address without
recreating the mapping. No guest input reaches host NT; no TEB offset is
fabricated. Installed NTDLL owns its reached TEB store.

The corpus binds26 actual native producers,39488 independent replay rows,
two complete original-entry/SVC13/true-LR first calls, two cold8-call sequences,
whole-page snapshots, four-profile lifetime/pool/capacity/remote/unmap controls,
and25 rehashed controlled falsifications. Runtime/owning gates and ordinary
observer evidence are recorded after the final source freeze in
[thread-slot evidence](../../../docs/specifications/windows/native-scheduler-thread-slot/README.md).
Physical x64-kernel/other builds, continuing kernel counter updates and whole
current-root plugin/GUI/package validation remain explicit unknowns/exclusions.
Full ordinary process exits remain unproven; the engineering validation record
owns exact counts, baseline Windows failures, artifacts and the new frontier.

## Absent thread-token opening (2026-10-13)

`NtOpenThreadToken` validates current/local/ended thread handle/type and either
query grant0x40/0x800; the current no-attachment personality returns
STATUS_NO_TOKEN0xC000007C, mapped to ERROR_NO_TOKEN1008. Invalid/type/access
failures retain native precedence. Token objects/attachments and positive ACL
semantics remain explicit unsupported boundaries; class5 attachment refusal is
tested. No guest request reaches host NT and no token handle is fabricated.

Native64 failure leaves output untouched. WoW64 null skips caller copy;
nonnull writes zero4B even on kernel failure, with copy faults overriding status.
Writable guards consume once; readonly guards remain armed; cross-page faults
preserve caller bytes. Shared write_guard_result preserves the constructor's
existing policy; slot setters keep their distinct measured regular guard policy.
All four ABI arguments are decoded; absent tokens never reach DesiredAccess or
OpenAsSelf ACL evaluation. Original installed WoW64 RET16 cleanup is tested.

The corpus binds13 actual producer source/executable/stdout identities,26352
full native mature rows (6192 absent replays),80 absent signed/zero-extended
pseudo replays,96 boundary rows, two complete fresh original-SVC36/true-LR
cases and33 rehashed controlled rejections. Native positive/anonymous/token
level contrasts are retained to falsify unconditional NO_TOKEN support claims.
Exact full gates, scoped owning108-source/2-helper/9-consumer identities,
archives, assumptions, plane maps and the unchanged ordinary observer live in
[thread-token evidence](../../../docs/specifications/windows/native-thread-token-open/README.md).
Other kernel/DLL builds/physical x64 and whole current-root/plugin/GUI/package
validation remain unknown/excluded. Full ordinary guest exits remain unproven.

### Installed image-section opening (2026-10-13)

`NtOpenSection` now retains guest-owned typed image-section identity, captured
authorization/case/metadata and measured native/WoW64 publication. Portable tests
replay22584 open and71040 duplication rows; final installed, platform, owning and
ordinary evidence is separate in
[section-open evidence](../../../docs/specifications/windows/native-section-open/README.md).
Guest section query/mapping and full ordinary exits remain unproven.

### Selected image-section mapping (2026-10-14)

`NtMapViewOfSection` maps pinned installed image bytes into private guest frames.
[The mapping contract](../../../docs/architecture/user-mode/selected-image-section-mapping.md)
and [native evidence](../../../docs/specifications/windows/native-section-map/README.md)
record acquisition, projection, relocation, ABI, faults, lifetime and validation.
Full ordinary Windows process completion remains unproved.

### Native performance-counter query (2026-10-14)

Counter/frequency stores, host clock reuse, shared-data units and native/public
helper parity are recorded in
[the counter evidence](../../../docs/specifications/windows/native-performance-counter/README.md).
The original observer exhausts1Mturns; a budget-only3Mderivative reaches
process-information class35. Full ordinary Windows completion remains unproved.

### Compact process TLS replacement (2026-10-14)

`NtSetInformationProcess` class35 now implements captured slot/vector replacement,
startup sentinel handling, caller stores, WoW64 conversion and partial failures.
[TLS evidence](../../../docs/specifications/windows/native-process-tls/README.md)
records1040 native controls and separate platform/embedding results. The unchanged
3M observer reaches `NtApphelpCacheControl`; ordinary guest exits remain unproved.

## Installed compatibility-cache lookup

`NtApphelpCacheControl` operation 6 now queries a bounded immutable snapshot
of the installed base compatibility database. Counted UTF-16 names, actual flags,
fixed packet capture, output alignment, guards, aliases and WoW64 copyback follow
recorded native behavior. Other operations remain explicit unsupported paths.
The [contract and native evidence](../../../docs/specifications/windows/native-apphelp-cache/README.md) own the format, assumptions,
platform gates and ordinary-startup limits.

## Selected installed CSR data section

`NtOpenSection` and `NtMapViewOfSection` retain captured data-section grants,
opaque committed bytes, reserved runs and independent view lifetime. The
[contract and native controls](../../../docs/specifications/windows/native-shared-section/README.md) record532 native
controls, startup allocation flags, platform evidence and remaining frontiers.
Full ordinary Windows process completion remains an active requirement.

### Unnamed pagefile-section construction (2026-10-15)

`NtCreateSection` now creates a real process-owned, page-rounded anonymous
backing object for supported unnamed pagefile sections. All seven original
arguments use the existing ARM64/x64/x86 service transport. WoW64 attribute
conversion, early allocation/protection validation, output and 8-byte maximum
capture, deferred validation and error-handle copyback retain the independently
measured order. `PAGE=0` has a different validation stage from other invalid page
values. No guest argument is forwarded to a host NT creation call.

Native controls cover 10,920 creations across ARM64, x64, x86 and x86-LAA on
ARM64 Windows build29683: 5,544 priority controls and 5,376 protection/allocation
cross controls, with 1,516 explicitly closed section handles. The original
owned debug child supplies an unchanged seven-argument 65,536-byte read/write
SEC_COMMIT call and naturally exits41. The replay compares10,876 native statuses,
output/max-size bytes, available section metadata and grants; 44 captured cases
require explicit unsupported results for separately unimplemented modes.
NOCACHE takes precedence over WRITECOMBINE, and WC alone rejects executable
sections after maximum-size capture. Source, producer PE machine/LAA and stdout
identities are retained with the corpus.

Backing size is bounded at67,108,864bytes(64MiB), and positive maxima round up to
4,096-byte pages without changing the caller's input. Same-process duplication
retains the backing until the last handle closes; failed or unsupported calls
publish no object. Named/file-backed/custom-security, privileged permanent,
large-page/based/64K/no-change modes, larger backing requests, guest mapping and
NtQuerySection remain explicit separate frontiers. Constructor completion is
not ordinary process completion. See the native-section-create corpus for the
assumption register, scope maps, primary reference and validation records.

### Native secure-port argument capture

`NtSecureConnectPort` now captures the original nine arguments and resolves
missing endpoints through the selected immutable NT namespace. No caller
handle, pointer or message reaches a host port. The build 29683 native corpus
contains 396 independently inspected observations from eight actual producers:
ARM64, x64, x86 and x86 large-address-aware on an ARM64 Windows kernel. It
distinguishes returned NTSTATUS from caller SEH and retains all input/output
bytes. All 396 caller-exception fields are zero; all per-call handle counts
are unchanged, and twelve owned handles are explicitly closed.

The WoW64 adapter stores a zero 32-bit output handle after a reached native
failure; early wrapper capture faults leave that buffer unchanged. Missing
port lookup precedes section-handle, view-offset and view-size validation.
Client-view lengths 48 bytes and, for WoW64, 24 bytes are captured separately;
the measured missing-port remote-view input is 24 bytes. Caller data is probed
in fixed 4096-byte chunks with a 1048576-byte transient bound. Larger requests
remain explicit unsupported boundaries and publish no output.

Captured endpoint presence does not authorize success. Existing ALPC ports and
unselected namespace branches require a selected guest server and owned shared
views and remain explicit unsupported boundaries. This group does not advance
the original CSR startup frontier or establish an ordinary Windows guest exit.
See `docs/specifications/windows/native-secure-connect-capture` for producer
identities, complete native captures, assumptions and validation records.

Read-only controls additionally require writable client/remote views and
nonempty information buffers on native and WoW64 paths. The information-length
counter is read without a writability probe on a missing endpoint. WoW64
view/data write faults occur after wrapper capture and still zero its output
handle; early read-capture faults leave it unchanged.

### Secure-port capture validation (2026-10-15)

NtSecureConnectPort captures the original nine arguments and selected namespace
failure behavior without host IPC. The 396 native controls from eight actual
producers cover capture order, readonly views/data, SID validation and WoW64
copyback; twelve handles close explicitly and no caller SEH occurs. Selected
present endpoints remain unsupported in this group, with no successful guest
port or ordinary Windows exit.

Corrected-source library pass/fail/ignored counts are macOS 7814/0/2, Linux
7808/0/2 and Windows 7235/5/2. Windows retains the same four BZHI and one FP16
lowerer failures. All three hosts pass 168 C API tests, all-target compilation
and focused tests (6 on Unix, 7 on Windows); both Unix hosts pass 544 Windows
integration cases and Windows executes 4 native memory integration tests.
Scoped owning builds pass all 7 macOS CTests and both protected scans, and all 5
C++ consumers on Linux/Windows. Complete archive walks bind 274 selected RAX
inputs per host with empty core features, using frozen older Assist exports.

The initial macOS timer mismatch and native printf 30 s C API timeout remain
retained. Three unchanged timer reruns and a complete same-binary library
rerun pass; the canonical C API rerun passes with unchanged limits/assertions.
Earlier nativeTrue 30 s failures and its 42.245449 s diagnostic continuation remain
separate evidence. Other kernels and whole-current-root/plugin/GUI/package
validation are unverified; the full process-userland objective remains active.

[Checked raw evidence](../../../docs/specifications/windows/native-secure-connect-capture/validation/README.md).


## Owned LPC views and selected CSR connection (2026-10-15)

The Windows VM now maps real SharedObject pagefile aliases and accounts each
retained object page once across local aliases. Typed LPC endpoint views retire
on the final local handle, independently of internal object references; section
handle close and duplicate port handles preserve the appropriate views. An
allocation-generation token prevents stale close cleanup from freeing explicit
unmap replacements. Thirty private native LPC cases across ARM64, x64, x86 and
large-address-aware x86 profiles establish the bounded local-view behavior;
compatibility execution on an ARM64 kernel is not physical x64 kernel evidence.

A matched immutable CSR metadata selection admits the measured ARM64 Windows
build29683/session0 startup packet. A separate modeled server VM owns its peer
view over the same pagefile backing and maps the selected readonly CSR section.
The connection has real typed endpoints, validated nonoverlapping outputs,
bounded resource leases and rollback. Guest pointers and requests never enter
host IPC. Unmeasured ABI, session, build, SID/QoS, packet, protection or readonly
length-output forms remain explicit unsupported frontiers. Native remote CSRSS
endpoint close timing and general CSR messaging remain unknown.

The three-host epoch3 validation is recorded under
`docs/specifications/windows/native-csr-connect-model/validation/`. Canonical
Rust1.95.0 library results are macOS7825/0/2, Linux7819/0/2 and Windows7247/5/2
(passed/failed/ignored); the five Windows failures are the same unrelated native
lowerer failures retained in the preceding capture group. C API168 passes on
each host; CSR focus10Unix/12Windows, LPCfocus7each, all-target checks and scoped
Assist consumers pass. The native Windows success test executes installed
ARM64 NtCreateSection/NtSecureConnectPort/NtClose with matching host metadata.
No code, assertions or timeouts changed during these final runs.

Ordinary smoke startup passes the previous secure-connection frontier and now
stops at NtInitializeNlsFiles0x107, PC0x1800020b0, turn2122164 (7001 turns beyond
its earlier connection boundary). Whoami still stops at NtTraceEvent0x5e.
Ordinary Windows guest completion remains unproven. Broader full-process
userland support remains active work. The scoped frozen-embedding checks do not
claim full current-root/plugin/GUI/package coverage.


## Installed NLS initialization (2026-10-15)

NtInitializeNlsFiles now uses a fixed selection-time readonly locale.nls
snapshot and captured native locale ID. The measured Windows build29683
profile preserves native64 base-before-LCID and WoW64 LCID-before-base copies,
including aliased outputs and eight native late-copy failures that retain their
mapped views. Views remain guest-owned and budgeted until unmap or teardown.
The declared unused outputs are not probed. Actual x86 NTDLL RET12 overrides the
historical four-argument PHNT prototype: x86 exports and host FFI use three
stdcall slots; native64 retains four declared slots. Strict native leaf SP
assertions remain enabled. Other builds remain explicit unsupported; other
patch revisions and physical x64 kernels are unverified.

Primary evidence retains316 original calls,48 protection/free controls,12 actual
installed-leaf byte captures and one original native startup. All four producer
profiles are on an ARM64 Windows kernel. Native/compatibility ARM64 and x86
NtInitializeNlsFiles leaves execute in the final tests and match the actual
locale.nls file bytes before real unmap. Existing fixed readonly NLS ownership
and private-free refusal are independently measured for initialization views.

Rust1.95.0 full-library results (passed/failed/ignored): macOS7830/0/2,
Linux7824/0/2,Windows7253/5/2. The same five Windows native-lowerer failures and
two ignored microkernel tests remain recorded. C API168 on each host, final
NLS focus13Unix/14Windows, all-target checks, Unix Windows integration544 and
native Windows memory4 pass. Scoped CLI/MCP/C++ consumers and complete archive
walks bind299 selected inputs per host, with empty core features. Frozen Assist
exports and nine matching current C++ files are distinct from whole-current-root,
plugin, GUI or package proof. Source epochs and initial failures are retained;
no assertions or timeouts are relaxed.

Ordinary ARM64 smoke passes the NLS boundary and reaches NtCreateFile0x55,
PC0x180001590,turn2132074 (9910 further observer turns), requesting
\Device\ConDrv\Server. Whoami remains at NtTraceEvent0x5e. Ordinary Windows
completion is still unproven. Separate controlled detached-persona diagnostics
do not change this shipping configuration or its completion count. The full
process-userland objective remains active.

Native data, provenance, assumptions, execution-plane maps and the portable
validation checker are under docs/specifications/windows/native-nls-initialize/.


## Detached standard streams and process-owner information (2026-10-16 UTC)

The process constructor describes both Host and Captured stream routes as a
`DETACHED_PROCESS` with `STARTF_USESTDHANDLES`: pointer-width `ConsoleHandle=-1`,
`WindowFlags=0x100`, and the existing guest-owned standard handles. These routes
provide streams without a native guest console session. This avoids requesting
an unimplemented ConDrv server solely because the parameter block was zeroed.
The separate minimal function-level environment does not run this process
constructor or native-service dispatcher and remains unchanged.

The selected build 29683 class 49 `ProcessConsoleHostProcess` setter and query use
process-local guest state. Native64 set checks 8-byte alignment and the supplied
upper user span before exact length 8, requires the self pseudo-handle, reads one
pointer, accepts low tag bits `01` and stores the full-width value. WoW64 requires
length >= 4 and captures one non-NULL unaligned ULONG before handle validation;
NULL passes through and is read only after that check. Excess WoW64 caller
length does not cause a larger capture or allocation. Even a real self handle
with all process access is rejected by the setter.

Native64 query checks 4-byte output alignment and upper span, visits optional
4-byte ReturnLength, requires length 8, validates process/type/query rights,
probes output, writes the owner and finally writes return length 8. Query rights
are PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION. The measured
WoW64 query rejects the class before touching either destination. An unmodeled
peer remains explicitly unsupported. READONLY|GUARD output and ReturnLength
have distinct measured guard priority; readable prefixes at failed page
crossings and owner/length aliases are retained in the native corpus.

Native suspended children report creation owner `creator PID|2`; the standalone
guest root has no modeled parent and explicitly starts at `0|2`. Native detached
initialization then sets 1. Zero parent is a model boundary, not a native creator
identity. Guest values never trigger host process lookup or host kernel calls.
The transfer sizes are fixed 4/8 bytes plus an optional 4-byte return length, with
constant auxiliary storage and no guest-length-sized allocation.

The primary evidence independently verifies 16 native producers and 12 suspended
parameter snapshots across ARM64, x64, x86 and x86-LAA controller profiles on an
ARM64 kernel. The canonical 544 primary class 49 calls include 130 successes and
414 measured status failures; 136 repeat setters and 1,224 helper queries are
separate counts. No escaping structured exception occurred. Snapshot x86-LAA
controllers launch the same non-LAA x86 child, so they do not establish LAA child
address geometry. Executable bytes are not checked into the corpus.

The source epochs preserve the initial synthetic WoW64 SP expectation failure.
The transition pops its own 4-byte call return address; the installed NTDLL
setter/query RET instructions then complete 20/24-byte x86 stack changes. Tests
assert each boundary explicitly: transition SP+4 and installed setter/query
SP+20/SP+24. The incorrect initial zero-pop expectation remains in the frozen
first epoch. A separate regression checks WoW64 NULL passthrough versus non-NULL
capture priority. Both corrected Unix focused runs execute all 544 primary rows and 136 repeat
setters. Native Windows leaves, full libraries, scoped carrier archives and
ordinary startup have distinct validation records; controller exit 0 and controlled
parameter mutation do not establish ordinary guest completion.

Final Rust1.95.0 full libraries (passed/failed/ignored) are macOS7836/0/2,
Linux7830/0/2 and Windows7260/5/2. The exact five existing Windows AArch64
lowerer failures remain recorded. Focus6Unix/7Windows, C API168 per host,
all-target checks, Unix Windows integration544 and native memory4 complete.
Actual installed NTDLL setters/queries pass separate strict return checks.
Scoped Assist carriers bind309 inputs and empty core features on all three
hosts. They retain Assist public ABI minor184 versus the compared root749cdd3d
minor186, and do not establish whole-current-root, GUI or package validation.
The original native epoch ran and retained its exact three synthetic SP failures;
its continuation then completed the corrected core and owning gates. Ordinary
startup records preserve controller timeouts and unsupported native calls;
no successful ordinary Windows application exit is established.

The C ABI remains 1.11.0; no dependency, default-feature, schema, permission or
package-layout change is introduced. Native NtReadFile/NtWriteFile dispatch and
NtTraceEvent remain outside this owner-information group. Whole-current-root,
GUI and package validation remain separate from retained carrier checks.

[Native contract, assumptions, source maps and primary provenance](../../../docs/specifications/windows/native-console-owner/README.md).


## Native loader security-cookie ownership (2026-10-17 UTC)

The shared PE mapper validates the load-configuration cookie span but preserves
its bytes whenever an actual installed runtime is selected. Built-in DLL mode
retains its previous default-cookie seeding and entropy behavior. The change
applies to both executable and DLL mapping without adding a host call or changing
C ABI1.11.0, dependency pins, default features or guest token policy.

Sixteen independently inspected native child observations cover ARM64, x64,
x86 and x86-LAA on the recorded ARM64 Windows10.0.29683 kernel. File-default and
explicit-default controls reach child entry; preseeded and zero-cookie controls
fail with 0xC000007B before entry. A separate suspended ARM64 read verifies the
file-default cookie in both the main image and the actual NTDLL mapping. Loader
and CRT contributions after the first instruction are not separately attributed.

Rust1.95.0 full-library results (passed/failed/ignored) are macOS7839/0/2,
Linux7833/0/2 and Windows7263/5/2. The exact existing four BZHI and one FP16
Windows lowerer failures remain. C API168 per host, all-target checks, Unix
Windows integration544, native memory4, three cookie regressions and prior owner
service checks pass. Three retained Assist carriers bind310 source inputs and
empty core features to structurally walked archives. Their public ABI minor184
versus current186 remains a scoped validation boundary, not whole-current-root,
plugin, GUI or package proof. Failed timing/environment/cache attempts remain
recorded separately without weakened assertions or changed dependency pins.

Ordinary ARM64 smoke and installed whoami now both reach unsupported
NtQueryInformationToken class29 through current-process-token pseudo-handle-4,
at PC0x180001220 (turn2130489 and turn2132851 respectively). Neither observation
establishes an ordinary Windows process exit. The full process-userland
objective remains incomplete.

[Native measurements, assumptions and validation](../../../docs/specifications/windows/native-cookie-owner/README.md).


## Captured primary-token AppContainer query (2026-10-17 UTC)

`NtQueryInformationToken` class 29 now returns the primary subject's captured
AppContainer Boolean. Native WNF selection retains that property even for an
empty catalog; absence of a capture remains explicit unsupported. Process and
effective token pseudo-handles share the current no-impersonation subject.
Guest-owned primary-token objects require TOKEN_QUERY (0x0008); they contain no
host HANDLE. Other token information classes and general impersonation remain
separate unsupported boundaries.

Four native producers record 7,320 calls on one Windows 10.0.29683 ARM64 kernel.
The shared adapter preserves the measured complete-span/ReturnLength probe
order, guard consumption, handle/type/access precedence, short-buffer length
and overlapping DWORD publication. Portable replay covers all four profiles;
real installed ARM64, x86 and x86-LAA stubs replay 5,490 calls. Installed x64
guest-runtime acquisition on ARM64 is not established by this evidence.

| Host | Full library passed/failed/ignored | Token/subject/cookie focused | C API |
| --- | --- | --- | --- |
| macOS | 7842/0/2 | 2/1/3 | 168 |
| Linux | 7836/0/2 | 2/1/3 | 168 |
| Windows ARM64 | 7267/5/2 | 3/1/3 | 168 |

All-target checks pass on all three hosts, Unix Windows integration runs 544
cases, and native Windows memory integration runs 4. The five Windows failures
remain the same four BZHI and one FP16 lowerer failures. The original native
test compile failure and the corrected Windows-only module reference remain
separate source epochs. The second epoch receives fresh Unix focused/compile
checks; unchanged Unix compiled items also have the complete first-epoch runs.

The unchanged ordinary observer now reaches NtAccessCheck service 0 at
0x180001000, at turns2,135,461 and2,137,823 for ARM64 smoke and whoami. Neither
is a successful guest exit. RAX C ABI 1.11.0 and empty core features are unchanged.

[Native measurements, assumptions and validation](../../../docs/specifications/windows/native-token-query/README.md).

The final scoped Assist carriers pass on all three hosts, each with313 bound
source inputs, empty core features and two complete archive walks. macOS runs
seven CTests and two scans; Linux and Windows each run five C++ consumers.
The retained carrier public ABI minor184 versus current186 remains explicit;
these results do not establish a whole-current-root or interactive IDA build.
The complete evidence checker passes and rejects five controlled corruptions
or overstatements of the recorded results.


## Captured-subject access checks (2026-10-17 UTC)

`NtAccessCheck` now evaluates the admitted classic-DACL profile against the
captured primary subject or a guest-owned captured impersonation subject.
The existing bounded native subject acquisition also retains privileges;
querying access never forwards a guest pointer, desired mask or token handle
to a host token API. The primary subject remains available when the WNF
catalog has no records. `NtQueryInformationToken` class 29 can also report the
captured property of a typed impersonation object.

The adapter keeps native64 and WoW64 descriptor capture order separate, then
uses a common evaluator for ordered allow/deny ACEs, owner rights, absent/NULL
versus empty DACLs, maximum access and the measured security/take-ownership
privileges. It preserves distinct function and access-status outputs, the
minimum 20-byte privilege capacity, actual 8/20/32-byte header publication,
alias ordering, and the caller's successful capacity. Unsupported token/ACE/
SACL profiles stop explicitly instead of fabricating an access decision.

The native corpus has 23,640 logical/pointer calls on four producer ABIs,
1,296 additional ARM64 private-token calls, descriptor-alignment controls and
three measured RTL error translations. Real installed ARM64, x86 and x86-LAA
leaves replay 17,730 logical/pointer calls. The initial synthetic x64 fixture
placed the eighth argument at its adjacent descriptor allocation; reserving
caller stack storage fixes that test setup without changing the production
adapter. The original source epoch and failures remain in the evidence.

The unchanged ordinary observer now passes the access check and stops at
`NtQueryWnfStateData` service 0x170, PC 0x180002740: turn 2,139,682 for ARM64
smoke and 2,142,044 for whoami. Both advance 4,221 turns from their prior access
check boundary. Neither is a completed application. General impersonation,
restricted/AppContainer access evaluation and complete ordinary Windows
execution remain outside this admitted profile.

[Contract, assumptions and validation](../../../docs/specifications/windows/native-access-check/README.md).

## Selected WNF state queries (2026-10-17 UTC)

`NtQueryWnfStateData` reads immutable state selected with the native runtime.
The fixed Notifications metadata supplies state names, maximum lengths and
optional TypeIds. Bounded native acquisition uses only those validated names,
retains stable pairs of status/stamp/data, and requires an unchanged primary
subject and no host-thread impersonation. Guest calls never forward a pointer,
name, TypeId or process handle to the host.

The new process starts with independent empty process-scoped data and stamp
zero; native read admission is retained without importing host process-private
payloads. Other selected scopes retain selection-time snapshots. Name, GUID,
length and output probes preserve the measured order, byte alignment, guard
behavior and aliases. A short buffer receives current stamp and required
length. Data copies only after sufficient capacity, and the caller's capacity
does not control host allocation.

Explicit scope uses the decoded namespace: NULL for System/Machine, a DWORD
for the captured Session, the captured SID for User and a guest process handle for Process. A current
process handle with zero granted access is accepted. Uncaptured sessions/users, different guest processes,
unmeasured explicit PhysicalMachine scope and unavailable data profiles return
explicit diagnostics. Creation, update and delivery remain separate services;
no empty or successful result substitutes for an unavailable snapshot.

The original four-profile evidence contains 7,680 V3 logical and 6,240 pointer
calls. V5 adds real read denial, with 6,480 calls on three independently
inspected producers. Its additional x64 stdout is corroborative only: the
executable was quarantined before independent identity verification. The
actual installed ARM64/x86/x86-LAA leaves replay 11,160 logical/pointer calls.
Additional session/user/machine and typed-denial controls retain their native
ARM64 provenance and have four-ABI portable replay.

[Native contract, source epochs and validation](../../../docs/specifications/windows/native-wnf-query/README.md).

Final WNF-query validation binds 327 selected inputs and complete archives on
Windows, macOS and Linux. Full library passed/failed/ignored counts are
7287/5/2, 7858/0/2 and 7852/0/2 respectively; the five Windows lowerer failures
are unchanged. Ordinary smoke/whoami advance 2202 turns to System-scoped
NtSubscribeWnfStateChange 0x1cd and remain incomplete. The scoped frozen Assist
carrier ABI 184/current186 boundary remains explicit in the retained proof.

### System WNF read subscriptions

Selected System-scoped states support read subscriptions through the same
private process notification owner. The measured classic-DACL profile maps
generic read/write/all rights, admits the recorded untrusted mandatory label,
and refuses other descriptor/subject profiles. System subscription admission
requires the selected query snapshot. Shared subscriber-level notifications
remain unavailable when the caller has the corresponding rights; access denial
is reported before that unsupported boundary.

Initial data notification depends on the selected change stamp. Repeated
requests retain queued data, including when the new requested stamp matches
the selected stamp. Event registration does not retroactively signal the queue;
manual event reset does not discard it. No guest subscription registers a host
subscription or mutates existing host state.

Final System-WNF validation binds 332 inputs and complete archives on Windows,
macOS and Linux. Full library passed/failed/ignored counts are 7295/5/2,
7865/0/2 and 7859/0/2 respectively; the five Windows lowerer failures are
unchanged. Smoke and whoami advance 2596 turns past the subscription boundary,
then fail an instruction fetch and SEH frame walk. Neither completes normally.
The scoped frozen Assist ABI 184/current186 boundary remains explicit.


## Selected native image extensions

A complete selected kernel image can own two bounded CFG/SCP extension types.
The PE image size and the returned section view size exclude these pages. The
single guest allocation owns the image, its extensions, and their shared
release lifetime; class 6 and class 14 describe that same state. Partial views
omit the extensions. Each component is at most 65,536 bytes and page-aligned;
the complete tail is bounded to 131,072 bytes beyond the PE image.

Native acquisition copies only its own pinned section views. It checks class-14
metadata, allocation identity, executable page protection, and copied extents.
Two concurrently held relocated views must normalize to the same complete
image before their guard adjustments are accepted. Ordinary PE relocations
alone do not account for those adjustments. Host signing levels remain outside
the guest trust policy.

The initial exact installed NTDLL uses this selected image at its native
preferred base when extensions are present. A conflicting range fails rather
than relocating cross-image guard branches implicitly. Explicitly supplied
images retain their existing loader policy. The compatibility page policy uses
the kernel-reported machine, not the compiler target of the host executable.
Native ARM64 large-page image views omit the extension; measured compatibility
calls retain ordinary image pages even when the large-page flag is requested.

Protection changes that intersect an owned extension report
STATUS_NOT_COMMITTED and PAGE_NOACCESS in the old-protection output, matching
the selected native contract. Unmapping any interior address releases the
complete image allocation. Its extension metadata disappears with that owner.

The evidence and limits are in
[the image-extension owner specification](../../../docs/specifications/windows/native-image-extension-owner/README.md).
ARM64-host AMD64 image projection does not by itself reproduce the additional
emulated SCP page reported to a real x64 compatibility process. This remains
part of the broader incomplete cross-architecture runtime, independently of
native same-architecture image ownership.


The image-owner final gates passed on the frozen source with full library
counts macOS7878/0/2, Linux7872/0/2 and Windows7309/5/2 (passed/failed/ignored).
The five Windows lowerer failures are unchanged. Epoch6 changes only a Windows test for older-kernel absence handling; its
20 focused cases and all-target check pass. C API168, scoped C++ consumers and
complete shipping archives cover identical epoch5 production source.
The non-test selected-NTDLL path stops earlier at `NtQuerySystemTime` (0x5a),
at smoke turn97964 and whoami turn98028; neither application exits normally.
These are different startup paths, not a forward turn-count improvement.


## Native system time (2026-10-17)

`NtQuerySystemTime` uses the existing host realtime adapter and FILETIME epoch.
Four native caller profiles supply 820 cases covering four-byte alignment,
atomic eight-byte output, page crossings, readonly/noaccess/guard ordering and
preserved last error. The installed ARM64 and x86 leaves and four-profile replay
pass. Full suites: macOS 7880/0/2, Linux 7874/0/2, Windows 7310/7/2. Five Windows
lowerer failures are unchanged; two TLS fixture failures in that original run
are corrected in the final test-only epoch and pass fresh three-host TLS/heap
checks. C API 168, all-target checks, scoped C++ consumers
and complete empty-feature carrier/core archives are recorded with 354 selected
source/fixture inputs. The prior image owner's Windows-only portability test is
inherited and freshly checked without a production-source change.

The unchanged ordinary observer advances 13 instructions beyond the clock call,
then reports unimplemented `NtSetInformationProcess` class 53 at smoke turn 97977
and whoami turn 98041. Neither application exits successfully. See the
[native controls and validation](../../../docs/specifications/windows/native-system-time/README.md).


## Native process dynamic function-table ranges (2026-10-17)

`NtSetInformationProcess` class 53 now maintains a bounded process-owned range
ledger, separate from user-mode fixed unwind arrays. Native 64-bit calls validate the
current-process pseudohandle, length 16 bytes, outer alignment 8 bytes and inner alignment 4 bytes,
then reads BaseAddress before MaximumAddress. WoW64 returns success without
accessing the packet. Add/remove have distinct overflow bounds and preserve
insertion-order duplicate/empty-range behavior. No host pointer or kernel call
participates in guest registration.

The group retains 52 post-run producer identities and 712 child executions,
including a contaminated sequential range diagnostic explicitly excluded from
the contract. Clean controls record 14,864 service/status-conversion calls.
Three-host full suites are macOS 7891/0/2, Linux 7885/0/2 and Windows 7324/5/2;
Windows retains exactly the five known lowerer failures. C API 168, all-target
checks and scoped Assist consumers pass. Actual empty-feature core/carrier
archives bind 361 selected source inputs; the frozen carrier remains Rust ABI minor 184
while the paired root is Rust ABI minor 196.

The unchanged production observer now stops at `NtOpenProcessToken` (0x133),
smoke turn 2,149,659 and whoami turn 2,152,008. Neither is a successful guest exit.
See the [native contract, assumptions and evidence](../../../docs/specifications/windows/native-dynamic-function-table/README.md).


## Native primary process-token opening (2026-10-17)

`NtOpenProcessToken` now creates guest-owned handles with captured maximum
access and system-security status. Native generic mappings, rights precedence,
WoW64 failure stores, caller-buffer probing and page guards follow 65596
replayed native calls. A single process-owned token identity survives caller
closes; 106 separate native lifetime operations corroborate representative
object/duplicate/close tests. Sixteen producers cover ARM64, x64 compatibility,
x86 and x86-LAA on one ARM64 Windows kernel; no physical x64-kernel measurement
is claimed. Missing capture and other-process requests remain explicit
unsupported boundaries.

Full suites are macOS 7903/0/2, Linux 7897/0/2 and Windows 7337/5/2; the five
known Windows lowerer failures remain. C API 168, all-target checks and scoped
Assist consumers/archive walks pass. Core source verification covers 5677
inputs; owning archives cover 401 selected inputs. Frozen Rust ABI184 and the
compared/upstream ABI196/199 distinction remains explicit.

The unchanged production observer outcomes are:

- `terminal turn=2149788 Complete(Internal("native NTDLL service NtQueryInformationToken: Unimplemented(\"NtQueryInformationToken: NtQueryInformationToken class 12\")"))`
- `terminal turn=2152137 Complete(Internal("native NTDLL service NtQueryInformationToken: Unimplemented(\"NtQueryInformationToken: NtQueryInformationToken class 12\")"))`

Full ordinary Windows application completion remains unproven. See the
[native contract and complete evidence](../../../docs/specifications/windows/native-process-token-open/README.md).


## Captured TokenSessionId and process-session identity (2026-10-18)

`NtQueryInformationToken` class 12 publishes the primary token's separately
captured session DWORD, following the measured probes, handle rights, required
length and caller-byte ordering. Class 29 retains its AppContainer behavior.
Missing capture and impersonation-session requests remain explicitly
unsupported. No guest query calls a host token API. The PEB session field uses
the process session already captured by `ProcessIdToSessionId`, independently
of the token value; no guest token setter is added.

Four native caller profiles supply 7320 replayed queries. Separately, 24 private
token cases supply 72 queries and 24 setters for zero, nonzero and high-bit
DWORD values. All use one ARM64 Windows kernel; x64 is a compatibility caller.
Full suites are macOS 7906/0/2, Linux 7900/0/2 and Windows 7341/5/2 with the five
existing Windows lowerer failures. C API 168, all-targets, scoped Assist C++
consumers and two complete empty-core-feature archive walks per host pass.
Core/workspace verification binds 5713 inputs; archive verification binds 404.
Frozen Rust ABI 184 and compared root ABI 200 remain separate evidence surfaces.

The unchanged ordinary observer passes the previous class-12 frontier and ends:

- `terminal turn=2149815 Complete(Internal("native NTDLL service NtQueryInformationToken: Unimplemented(\"NtQueryInformationToken: NtQueryInformationToken class 42\")"))`
- `terminal turn=2152164 Complete(Internal("native NTDLL service NtQueryInformationToken: Unimplemented(\"NtQueryInformationToken: NtQueryInformationToken class 42\")"))`

Full ordinary Windows application completion remains unproven. See the
[native contract and exact validation evidence](../../../docs/specifications/windows/native-token-session-id/README.md).

The preserved upstream parent `e4f998244e3eec728f87a85482d4aa62566e802b` uses Rust ABI minor 203; its selected C++ sources match. Its newer Rust code is outside the retained carrier validation.


## Captured native scalar token queries (2026-10-18)

Fifteen additional `NtQueryInformationToken` selectors now follow captured native
values or explicit invalid-class capabilities. Six measured behaviors distinguish
minimum DWORD buffers, TokenElevation's exact length and early ReturnLength,
TokenHasRestrictions' byte result with four-byte alignment, and WoW64/native
unavailable-selector probe ordering. Missing capture and unmodeled impersonation
properties remain explicit refusals; no guest token mutation or host forwarding
is added. Native buffer storage is explicitly four-byte aligned.

Native proof contains 109800 matrix queries, 60 references and separately 24 private
Boolean cases / 72 queries / 24 setters. The final core/workspace binds 5718 inputs. Full
suites are macOS 7909/0/2, Linux 7903/0/2 and Windows 7345/5/2, retaining the five
known Windows lowerer failures. C API 168, all-target checks and scoped owning
consumers/complete empty-core-feature archives pass; owning records bind 409 inputs.
Frozen RustABI 184 and compared/upstream root ABIs remain distinct.

Unchanged ordinary-observer outcomes:

- `terminal turn=2149956 Complete(Internal("native NTDLL service NtOpenDirectoryObject: Unimplemented(\"NtOpenDirectoryObject: NT directory outside selected installed namespace\")"))`
- `terminal turn=2152305 Complete(Internal("native NTDLL service NtOpenDirectoryObject: Unimplemented(\"NtOpenDirectoryObject: NT directory outside selected installed namespace\")"))`

Both executed ordinary programs pass token classes 12, 29 and 42, then stop at an uncaptured NtOpenDirectoryObject namespace: smoke at turn 2149956 and whoami at turn 2152305. Neither terminal is a successful guest exit; the broader process-userland goal remains incomplete.

[Native contract and full evidence](../../../docs/specifications/windows/native-token-scalars/README.md).


## Selected native base named-object directories (2026-10-18)

The installed Windows runtime now captures `\BaseNamedObjects` and the selected
nonzero token-session ancestry. Deepest-first tree construction preserves shared
absolute/relative identity. Missing parents and unavailable case-policy samples
are explicit failures. After bounded complete-capture attempts, changing
non-image directories retain only a stable unique intersection and are marked
incomplete. An absent entry in them remains unselected; KnownDLL images still
require coherent capture. Image-section
capture remains limited to the KnownDLL families. Guest requests do not acquire
host handles. Existing public C ABI, defaults and dependencies remain unchanged.

Native proof binds 3072 access cases and 24 enumerations / 17436 entry records,
including two failed snapshot pairs. Direct replay covers 1280 selected access
rows. Full suites are macOS7921/0/2, Linux7915/0/2 and Windows7358/5/2, retaining
five known lowerer failures and two existing ignores. Focus12/12/13, C API168,
all-target checks and scoped retained Assist consumers pass. Source identities
bind 5728 core/workspace and 419 owning inputs; two actual Cargo archives per
host have complete member walks and empty core features. Frozen RustABI184 and
compared/current root Rust remain distinct.

- `terminal turn=2149970 Complete(Internal("native NTDLL service NtQueryInformationToken: Unimplemented(\"NtQueryInformationToken: NtQueryInformationToken class 44\")"))`
- `terminal turn=2152319 Complete(Internal("native NTDLL service NtQueryInformationToken: Unimplemented(\"NtQueryInformationToken: NtQueryInformationToken class 44\")"))`

Both ordinary programs open the captured BaseNamedObjects directory successfully and stop at the following unimplemented NtQueryInformationToken class44 call. Neither program reaches a successful guest exit.

[Contract and evidence](../../../docs/specifications/windows/native-base-named-objects/README.md).


## Captured TokenBnoIsolation (2026-10-18)

The installed Windows runtime captures the primary token's optional BNO prefix
into owned UTF-16 storage. Class44 queries return the captured state with a guest
pointer. Native64 probing and WoW64 ordered direct stores preserve the observed
fault boundaries, header padding and partial prefix writes. The bounded copy
planner reproduces the captured 16-byte store order; the actual native callee
identity and other kernel implementations remain unproven. No host token pointer
or handle is retained. Public C ABI, dependency pins and defaults are unchanged.

Native proof binds 161,808 observations across four ABI profiles on one ARM64
Windows kernel. Full suites are macOS7929/0/2, Linux7923/0/2 and Windows7367/5/2;
the five known Windows lowerer failures and two existing ignores remain explicit.
Focus8/8/9, C API168, all-target checks and scoped retained Assist consumers pass.
The exact final port matches 5737 compiled source/data inputs and 428 selected
owning inputs. Frozen ABI184 carrier results are distinct from current root Rust.

- `terminal turn=2150070 Complete(Internal("native NTDLL service NtCreateMutant (0xba) at 0x7ff82fad1be0 is not implemented"))`
- `terminal turn=2152419 Complete(Internal("native NTDLL service NtCreateMutant (0xba) at 0x7ff82fad1be0 is not implemented"))`

Both ordinary programs return success from class44 and advance100 observer turns to unsupported NtCreateMutant. Neither reaches a successful guest exit.

Enabled-prefix private-directory routing remains a separate unimplemented part
of complete process emulation. [Contract and evidence](../../../docs/specifications/windows/native-token-bno-isolation/README.md).


## Captured object-manager directory links (2026-10-18)

Selected base named-object directories now retain Local/Global/Session targets.
Guest parsing follows captured metadata into selected directories, preserving
alias identity without opening host handles. Native63/64 reparse boundaries and
DONT_REPARSE precedence are reproduced; DOS and uncaptured targets remain distinct.
Public C ABI, defaults, dependency pins and package layout are unchanged.

Native proof covers2432 directory opens and24 target queries on four ABI profiles
of one ARM64 Windows kernel. Full suites are macOS7934/0/2, Linux7928/0/2 and
Windows7373/5/2; five existing Windows lowerer failures and two ignores remain.
Focus5/5/6, C API168, all-target checks and scoped retained consumers pass.
The final source binds5743 inputs and434 retained-owner inputs.

Both ordinary programs still stop at NtCreateMutant; successful guest execution
and private BNO subtree selection remain incomplete.

[Contract and evidence](../../../docs/specifications/windows/native-object-reparse/README.md).


## Native guest mutants and installed named identity (2026-10-19)

NtCreateMutant, NtOpenMutant, NtReleaseMutant and NtQueryMutant0/1 use private
guest mutex state, native/WoW64 probe/copy rules and selected raw UTF-16 names.
Installed Win32 event/mutex/semaphore calls share those names; embedded behavior
remains unchanged. Private BNO and explicit security/privilege contexts remain
unsupported. No guest request opens a host synchronization handle.

Final core suites: macOS7945/0/2, Linux7939/0/2, Windows7384/5/2. The exact five
existing Windows lowerer failures and two ignores remain explicit. Focus11/11/11,
C API168 per host, all-target checks and scoped retained consumers pass. Native
proof covers25200 query,12800 create-fault and200 release rows, grant/lifecycle
and raw-name/Win32 identity cases. Selected source5762 is qualified by separately
verified native fixture/package restoration; retained-owner inputs456.

Both unchanged ordinary programs create a guest mutant successfully and then stop at unimplemented NtWaitForSingleObject (0x4). Neither reaches a successful guest exit.
Native wait services, private BNO, security and full execution remain incomplete.
Public ABI, defaults, dependency pins and package layouts are unchanged.

[Contract and evidence](../../../docs/specifications/windows/native-mutant/README.md).


## Native single-object waits and preserved synthetic ordinals (2026-10-19)

NtWaitForSingleObject now uses private guest dispatcher objects, native saved
contexts and cooperative parking. Timeout reads precede handle/access checks;
queued ordinary APCs precede signal consumption. Relative 100 ns intervals retain
an awake-time target, absolute intervals retain NT UTC, and finite extremes
remain finite. Measured low-byte alertable behavior applies to the three
Win32 alertable adapters; WaitAll keeps full BOOL semantics.

The new native export table follows all existing synthetic NTDLL families.
Every previous ordinal and symbol/trap RVA is retained on all three guest ABIs.
The primary native export body is byte-identical to the published mutant parent.

| Host | Full core passed/failed/ignored | Focus | C API |
|---|---|---|---|
| macOS ARM64 | 7961/0/2 | 16 | 168 |
| Linux x86-64 container | 7955/0/2 | 16 | 168 |
| Windows ARM64 | 7401/5/2 | 17 | 168 |

Windows retains exactly the five established lowerer failures. Both ignored
checks remain explicit. All-target checks pass; Unix runs544 integration cases
and Windows runs4 native-memory cases. Native proof retains20 producer runs
on one ARM64 kernel and four ABI profiles, including exact2240 fault/guard and
336 object/APC replay rows, provider discrepancy and13 rejection controls.
The complete final source snapshot binds22059 inputs and1510895073 bytes;
three separate overrides preserve old synthetic ordinals. Retained consumers
bind474 selected inputs and two actual complete Cargo archives per host. The
final Windows helper verifies its actual carrier before and after five C++
consumers. Frozen Assist RustABI184 is distinct from compared root8f49854b /
ABI264; eight selected C++ sources match. Whole-current-root GUI/plugin/package
validation is outside these retained-carrier results.

Both unchanged ordinary programs now return0 from native NtWaitForSingleObject,
with private mutant ownership transferred to the guest thread, and advance351
observer turns to unsupported NtOpenSemaphore(0x136). Neither reaches a
successful guest exit. Broader NT synchronization, private BNO/security contexts
and complete ordinary process support remain required by the full goal.
Public Rust Wait/NativeDeadline source types are extended; public C ABI,
dependencies, defaults and package layout remain unchanged.

[Contract, assumptions and evidence](../../../docs/specifications/windows/native-single-wait/README.md).


### Native semaphore operations (2026-10-19)

`NtCreateSemaphore`, `NtOpenSemaphore`, `NtReleaseSemaphore` and
`NtQuerySemaphore` now use the existing guest semaphore object, selected named
namespace, access grants and wait lifetime. Mutants and semaphores share
object-manager name/attribute capture and fault conversion. Existing synthetic
NTDLL ordinals and trap RVAs are preserved across all three guest ABIs.

Twelve native captures on Windows ARM64 kernel 10.0.29683 cover 40,268 cases
across ARM64, x64 compatibility, x86 and x86-LAA profiles. Nine new tests include
39,308 exact status/output/guard replays; the existing 11 mutant and 16 native
single-wait regressions pass. Full core gates report 7970/0/2 on macOS,
7964/0/2 on Linux and 7410/5/2 on native Windows (passed/failed/ignored); Windows
retains the exact five preceding AArch64-lowerer failures. The integrated C API
ABI 1.14 passes 183 tests on each host. All affected target checks pass.

Source epoch 2 incorporates the four independent C API commits through c717f9b8;
the complete source comparison leaves core and fixture inputs unchanged.
Actual integrated owning archives pass the retained Assist ABI 184 consumer
lanes on all three hosts. The Windows core remains byte-identical to the
ordinary-program observer's core. These consumer lanes do not establish whole
current-root GUI, plugin or package validation.

Both ARM64 smoke and installed `whoami.exe` handle the missing initial semaphore
open and successfully create two semaphores. Their remaining stop is
`NtOpenKey: registry key outside selected runtime snapshot`, after 27,400 and
27,336 additional observer turns respectively. Neither has a successful guest
exit. Explicit object security/QoS, permanent objects, privilege rights and
cross-process namespace equivalence remain outside this single-principal
semaphore group. See `docs/specifications/windows/native-semaphore/README.md`
for source snapshots, exact native producers, output budgets, assumptions,
consumer qualifications and the executable evidence verifier.


## Native StateSeparation registry evidence (2026-10-19)

Native-library selection now snapshots the fixed SYSTEM
`StateSeparation\RedirectionMap\Keys` subtree, using known absence only for
fixed-root `ERROR_FILE_NOT_FOUND` and complete bounded descendants when present.
Guest handles retain immutable records; arbitrary guest names do not invoke
host registry operations. IFEO and the new fixed root share the same key-tree
model and aggregate value budgets. Other keys and prefix lookalikes retain the
explicit unsupported frontier.

The native producer records 256 fixed-key/view observations across ARM64,
x64 compatibility, x86, and x86 LAA on one Windows ARM64 kernel, with stable
producer/source/module identities and handle counts. Of these, 224 lie inside
the selected root and 32 are outside-prefix controls. Twelve native-evidence
corruptions are rejected. The unchanged implementation fails the new native
presence regression (0 passed, 1 failed); the first baseline compile failed
because the guest disk filled, and the distinct retry reached the assertion.
Task-owned obsolete PDB cleanup restored 8,115,089,408 bytes without removing
sources, executables, archives, runtime libraries, or captures.

Six new shared tests pass on macOS/Linux and nine pass on native Windows.
Complete unfiltered core results are macOS 7,976/0/2, Linux 7,970/0/2, and
Windows 7,419/5/2 (passed/failed/ignored), retaining exactly the five established
Windows lowerer failures. All three C API selections pass 183 tests, and all
three all-target checks pass. The source snapshot binds 22,779 inputs and
1,583,474,670 bytes. Actual retained Assist core/carrier archives, 513 selected
inputs, full archive walks before/after C++ links, seven macOS CTests and five
Linux/Windows C++ consumers pass. Retained Assist Rust ABI184 and C++ inputs
compared to root ABI264 remain explicit limitations; this is not a
whole-current-root GUI/plugin/package result. The public RAX C API stays 1.14.0.

Both ordinary Windows programs return the native missing-key status at the
former registry stop and advance 9,296 observer turns. They stop separately at
unimplemented `NtSetTimer2` (0x1C0), without a successful guest exit. The current
Windows owning core is 503,963,010 bytes, SHA-256
`790ba7cd4d87fe35b63fdbb4aff228cb0b3996a3a2583d09537139fc029db05e`.
Sources, commands, logs, exact failure names, native captures and portable
verification are under
`docs/specifications/windows/native-state-separation-registry/`.


## Native extended timer arming/cancellation (2026-10-19)

NtSetTimer2 and NtCancelTimer2 now operate on the extended objects constructed
by NtCreateTimer2. Native64 and WoW64 input capture order, full16-byte parameter
reads, unaligned spans, guard consumption, modify access, typed handles and
native value restrictions follow18,740 captured cases on four ABI profiles
sharing one Windows ARM64 kernel. Portable replay checks18,528 exact records;
asynchronous timing samples are bounded evidence rather than exact poll goldens.
The independent checker rejects14 corrupted capture copies.

Relative/absolute native clock domains, full signed64 100ns intervals, positive
period phase/skip arithmetic and fast negative periods are retained without
narrowing or overflowing host Instants. At most one expiry is delivered per
scheduler turn. Successful rearm clears signal state; cancellation preserves
it. Existing waits and completion packets consume the same object state and
retain objects after public handle closure. Legacy timers and prior NTDLL
ordinals/trap RVAs are unchanged. Timing quantum/power guarantees and a physical
NtSetTimer2 suspend/resume experiment remain outside the demonstrated scope.

Five strategic tests fail on the missing service before implementation. Final
focus selections pass14 shared tests and15 native Windows tests, including real
installed host/WoW64 NTDLL leaves. Complete unfiltered core pass/fail/ignore is
macOS7990/0/2, Linux7984/0/2, Windows7434/5/2, retaining exactly the established
five Windows lowerer failures. C API183, all-target checks and actual retained
Assist consumers pass on all three hosts. Full archive walks before/after links
bind519 selected inputs. Retained Assist Rust ABI184 and C++ inputs compared
to root ABI264 do not establish whole-current-root GUI/plugin/package builds.
The public C ABI remains1.14.0. The complete source epoch binds23,050 inputs
and1,599,183,887 bytes; this engineering append is separately bound afterward.

Both ordinary Windows programs return timer success at the former stop and
advance695677 normally executed observer turns to an uncaptured SafeBoot/Option
registry key. Neither guest exits successfully; controller exit0 is separate.
The actual Windows owning core is503,289,084 bytes, SHA-256
`082390d8d0aca0c04aa96dc484b1111c6a3bb756ae39faad4ca75c4b4a227e76`. Sources, captures, logs, commands, assumptions, complete
counts and portable verification are recorded under
`docs/specifications/windows/native-timer2-arm/`.


## Fixed loader registry roots (2026-10-19)

Native selection additionally captures SafeBoot/Option, Srp/GP/DLL and
Safer/CodeIdentifiers as complete-or-known-absent immutable trees. All three
roots were observed during ordinary Windows execution. Existing per-root tree
bounds, aggregate value budgets, ordinal folding, raw values and retained key
handle ownership remain unchanged. Only fixed-root ERROR_FILE_NOT_FOUND means
absence; other root errors or disappearing enumerated children abort capture.
Guest queries remain read-only; host write permission is not forwarded.

Three independent native capture families bind960cases across four ABI profiles
on one ARM64 kernel;18corrupted capture copies are rejected. SafeBoot and SRP
are absent on this subject; Safer is present. The product dynamically captures
present or absent state. Eighteen shared and27total Windows focused tests pass.
Full unfiltered core pass/fail/ignore is macOS8008/0/2,Linux8002/0/2,
Windows7461/5/2, retaining the exact five established Windows lowerer failures.
CAPI183, process integration and all-target checks pass across all three hosts.
Actual retained Assist core/carrier archives and C++ consumers bind528selected
inputs with complete archive walks before/after links. The retained Rust ABI184
and C++ input comparison to root ABI264 do not establish whole-current-root
GUI/plugin/package coverage. Public RAX C API remains1.14.0.

Both ordinary Windows guests pass all three roots and advance74normally
executed observer turns to unsupported NtQueryInformationToken class1, without
successful guest exit. Native controls exit0 with stable output. The exact
validated owning core is503515446bytes, SHA256
`1e1a94d1cd59c4225dd1d85f1391083fdac087c2dcf73a5ea55b24801e170c18`. Sources, executable, modules, programs and archive remain
stable. The complete pre-gate epoch binds23283inputs/1657974640bytes; this
engineering append is separately bound. Sources, assumptions, known limits,
complete counts and portable verification are under
`docs/specifications/windows/native-loader-registry/`.


## Native TokenUser identity (2026-10-19)

NtQueryInformationToken class1 publishes captured primary or modeled
impersonation SID/User.Attributes without host handle forwarding. Native
acquisition retains opaque attributes; existing ACL interpretation is unchanged.
Native64 full-span/alignment/length probes, typed/query handles, untouched
padding and required-length-before-data differ from the measured WoW64
scratch/copy/header/optional-length-last phases. Direct faults preserve reached
copy progress and guard state. WoW64 scratch failure sets LastError8 while
preserving last-NT-status, with no guest-sized host allocation.

The independent native corpus binds22688calls across four ABI profiles on one
ARM64 kernel;12corrupted copies are rejected. Thirty-six additional native TEB
controls preserve last-NT-status. Five tests compile and fail before changes;
final five shared and six native Windows tests pass, including installed
host/WoW64 leaves versus independent native SID/attribute acquisition. Complete
unfiltered core pass/fail/ignore is macOS8013/0/2,Linux8007/0/2,Windows7467/5/2,
retaining the exact five established Windows lowerer failures. CAPI183,
integration and all-target checks pass on all three hosts. Actual retained
Assist core/carrier archives and C++ consumers bind530selected source inputs
with complete archive walks before/after links. Retained Rust ABI184 and the
prior eight-C++-input comparison to root ABI264 do not establish whole-current-
root GUI/plugin/package coverage. Public RAX C API remains1.14.0.

Both ordinary Windows guests return TokenUser success and advance2743normally
executed observer turns to an uncaptured per-user Safer registry key, without
successful guest exit. Native controls exit0 with stable output. The exact
validated owning core is 503968678 bytes, SHA256
`b3ca4f9e090a00f7421860c941c45f50f7a77b7a8373625abbc6d273662ca784`. The pre-gate source epoch binds23442inputs/1695720818bytes;
this engineering append is separately bound. Current-SYSTEM-SID native scope,
other-SID copy inference, existing guest scratch-budget limits and complete
commands/data/assumptions are recorded under
docs/specifications/windows/native-token-user/.

### Primary-user Safer policy root (2026-10-19)

Native runtime selection derives one fixed per-user Safer/CodeIdentifiers root
from the already captured primary-token SID. Complete bounded native capture
or independently established root absence feeds the existing immutable,
read-only registry model; guest names are never forwarded. Shared view behavior
is supported by stored Microsoft provenance and four native ABI profiles on
one ARM64 Windows kernel. The 1,152 native observations, six shared/nine Windows
tests, three-host gates, retained consumers, exact known failure set, assumptions,
and reproducible evidence are recorded in
`docs/specifications/windows/native-user-policy/`.

The actual retained-owner core is 504324092 bytes, SHA-256
`8aae16fe5ebdfb13a6fca0340d48f6e9eee4d4e694f4d47240151e42d493c9be`. Both ordinary native-library guests pass the former per-user
policy frontier and advance 2,873 turns to the still-unselected FileSystem
registry root. Neither emulated guest has demonstrated successful exit; the
full process-emulation objective remains incomplete. Retained Assist ABI 184
consumer validation is not a full current GUI/plugin/package build.

### Fixed FileSystem registry root (2026-10-19)

Native Windows runtime selection captures the fixed HKLM System FileSystem
subtree with the existing complete bounded immutable tree adapter. Root-only
not-found establishes absence; errors and partial capture fail. Shared registry
views, raw values, read-only grants, aggregate limits and descendant lifetime
remain unchanged; guest paths and native handles are never forwarded.
The 320 native opens across four ABI profiles on one ARM64 Windows kernel,
six shared/nine Windows tests, full three-host gates, retained consumers,
assumptions and portable evidence are recorded in
`docs/specifications/windows/native-filesystem-registry/`.

The actual retained-owner core is 503848220 bytes, SHA-256
`456955a2b903926620df54ccfdbbd3406f08683611d18b83ee41bb18db88d81c`. Both ordinary guests open FileSystem successfully and
advance 8,728 turns to unsupported `NtSetInformationWorkerFactory` class 13.
Neither emulated guest has demonstrated successful exit; the full process
objective remains incomplete. Retained Assist ABI 184 consumer validation
does not establish a full current GUI/plugin/package build.

### Dormant worker-factory flags requests (2026-10-19)

Class13/WorkerFactoryFlags captures an exact4byte ULONG before typed factory
and right0x4 validation, using the existing guarded-memory/four-argument
native/WoW64 adapter. An optional last-successful request shares alias lifetime
without changing hard/soft requests, binding count or constructor references.
None is an unrecorded request, not a guessed native flags default. Active-worker
effects remain unknown; public CAPI1.14.0/defaults/dependency pins are unchanged.
The native5236observations, six shared/seven Windows focused tests, full
three-host gates, retained consumers, assumptions and portable evidence reside
in `docs/specifications/windows/native-worker-factory-flags/`.

The actual retained-owner core is 503567976 bytes, SHA-256
`cf6535695c29c81e2154db9bdb7e92da5c8fe784140e93bfa0e8ef3fddbf196d`. Both ordinary guests returnclass13success with retained
value1 and advance496turns to unsupported NtSetInformationWorkerFactory class2.
Neither emulated guest demonstrates successful exit. Full process support and
whole-current-root GUI/plugin/package validation remain incomplete; retained
Assist RustABI184 consumers are recorded separately.


## Dormant worker-factory idle-timeout requests (2026-10-19)

Class 2 accepts the measured installed native/WoW64 `LARGE_INTEGER` contract:
native64 exact length 8, WoW64 length at least 8, 4-byte alignment and an 8-byte
capture before typed handle/right 0x4 validation. Nonnegative values fail after
access checking. Negative values clamp to [-6,000,000,000,-10,000,000] signed
100 ns ticks (relative 600 s through 1 s); `i64::MIN` is handled without negation.
The optional normalized request is shared by aliases, preserves constructor
unknowns, and remains independent of classes 3/5/13/14. Failures preserve prior
state; cross-page guard consumption matches the native records. Active worker
scheduling is outside this dormant setter contract. Public Rust enum constructors
need the new field; opaque C API 1.14.0 and defaults are unchanged.

Evidence: 8,944 observations over four ABI profiles on one Windows ARM64 kernel,
14 rebound native corruptions rejected, a compiled 0-pass/3-failure regression,
six shared tests and seven native Windows tests, including actual NTDLL/WoW64
leaves and x86 20-byte return cleanup. Complete library selections: macOS8037pass/0fail/2ignored, Linux8031/0/2, Windows7499/5/2 with exactly the five established lowerer failures. C API183 each, integration544 on macOS/Linux and4 on Windows, all-target compilation and selected retained consumers passed.
Actual retained-owner core: 503929600 bytes, SHA-256 `b912928105f461adf0bf338d7ade0815b1557f379d0fa21c2728a93856804835`.
Both ordinary ARM64 guests return class2 status0 and retain idle_timeout Some(-300000000), then advance359turns: smoke2898814->2899173 and whoami2901099->2901458. The next stop is unimplemented NtQuerySecurityAttributesToken (0x167). Neither guest exits successfully; both native controls exit0. Read-only final diagnostics capture pseudo token handle -4 and requested WIN://SYSAPPID/WIN://PKG names.
Full process objective remains active until ordinary guests exit successfully.
[Evidence, assumptions and limits](../../../docs/specifications/windows/native-worker-factory-idle-timeout/README.md).


### Captured token security attributes

`NtQuerySecurityAttributesToken` uses a selection-time owned snapshot, including
all seven PHNT version1 value types. Native and WoW64 share token rights and
name semantics while preserving their measured capture, buffer conversion,
alignment, guard, partial-zeroing and ReturnLength alias order. No guest request
queries a host token. The build29683 four-ABI observation scope, 22656 native
rows, independent checker, bounded capture policy and validation state are in
`docs/specifications/windows/native-token-security-attributes/README.md`.
Successful ordinary-program exit remains a separate required validation result.

Validation: twelve shared / thirteen Windows focused tests; 22656 independent native observations and 15 rejected native-evidence corruptions. Full selections macOS8049/0/2, Linux8043/0/2, Windows7512/5/2 (exact existing lowerer failures), C API183 each, integration544 non-Windows /4 Windows and all-target compilation. Retained ABI184 linked consumers pass; actual core 506136090 bytes SHA-256 `41fa4b161609e88a2bf24943be1755e0dea8bfb65cab1048f60e85e64e9c736f`. Both ordinary guests pass this query with STATUS_NOT_FOUND/ReturnLength0 and continue44004/64739 observer turns to NtTestAlert / NtQueryVirtualMemory class3. No successful guest exit; full process goal remains active.


### Owned native alert checks

`NtTestAlert` consumes a pending guest user alert with STATUS_ALERTED before
processing queued Win32 APCs. Otherwise it drains existing scheduler callbacks
and returns STATUS_SUCCESS, preserving interrupted register/stack context and
callback TEB writes. Native/Win32 queue arguments are not conflated: the current
guest queue retains one argument, and native three-argument queue producers
remain separate unsupported frontiers. `Thread.user_alerted` is owned Rust
state initialized false; no guest call invokes a host alert operation.
[Native observations, replay scope and validation](../../../docs/specifications/windows/native-test-alert/README.md).

### Owned alertable context replacement

`NtContinue` validates the supplied architecture context before changing alert
or queue state. `TestAlert` uses its low eight bits (`BOOLEAN`). False resumes
without an alert check. True first applies the replacement context and removes
abandoned continuations, then consumes an existing guest user alert before
considering APCs. A consumed alert leaves the APC queue pending. Otherwise the
existing scheduler captures the replacement context, drains FIFO and appended
one-argument Win32 APCs, and restores that target. No synthetic wait or status
return overwrites the supplied result registers. Callback writes to guest TEB
memory remain observable. Both native-service and HLE context replacement use
the same stack-height/frontier rule for abandoned continuations.

An APC delivery owner at the replacement SP is discarded even when the target
PC exactly equals its interrupted PC. The dispatcher recognizes that owner by
its private API descriptor identity and active callback stack marker; ordinary checked-operation/retry frames
retain their existing frontier rule. Supplemental native controls cover a
callback's direct NtContinue(FALSE/TRUE), an empty remaining queue, and a user
alert created inside the callback. The abandoned callback does not return.

The public Rust `Flow` enum adds `ResumeAlertable`; the opaque C ABI and feature
defaults are unchanged. No guest call invokes a host alert or continuation
operation. Native three-argument APC queue and alert producers remain separate
unsupported frontiers.
[Native captured-context observations and validation](../../../docs/specifications/windows/native-continue/README.md).


### Selected native directory identity diagnostics

A rejected selected directory now reports its selected path, parent path,
expected/captured name, captured type and existing-child flag. UTF-16 values
use escaped diagnostic rendering. The fixed-root/type/name/attachment checks,
permissions, capture operations and guest namespace policy remain unchanged.
This identifies which invariant failed during native runtime selection; it does
not reinterpret a captured symbolic link or case mismatch as a directory.
The added work is confined to the error path and is linear in the bounded
rendered UTF-16 extent. Public C ABI 1.14.0 and defaults are unchanged.

Native x64 CI previously failed this check before guest execution. The exact
host invariant remains unknown until the new diagnostic is captured there.
The independent four-ABI case probe uses only query handles on fixed roots and
closes its temporary private directory handles; it establishes canonical-name
behavior on the development kernel without replacing the failing-host evidence.


### Allocation-wide virtual-memory region queries

NtQueryVirtualMemory classes3/7 now expose allocation base/protection, native
legacy type or Ex flags, complete reservation size, process-private commitment,
partition0 and preferred node. Native64 class3 accepts24bytes and class7 accepts32;
WoW64 accepts16/20 respectively. Complete pointer-sized fields are copied up to
48 native or28 WoW64 bytes; the tail is unchanged. Native64 retains full declared
output probing before handle validation. WoW64 retains optional return-destination
capture and publishes0 for kernel status failures. Other-process queries remain
an explicit frontier. No guest argument is forwarded to the host kernel.

Private commitment follows committed state runs. Read-only shared/pagefile views
carry no private charge. Copy-capable image/data views combine current writable
potential with acquired private page charge: an identical-value store counts,
and a successful write probe can acquire charge even when a later syscall check
fails. Guard faults acquire no charge before a write; the WoW64 shared-guard
alias can consume the guard and then complete its output write. Initial shared
writable PE sections have no private potential until explicit reprotection,
including a same-protection request. Initial image permissions use a distinct
internal path. Reserved pages of an initially copy-on-write pagefile view also
reserve private charge without requiring guest frames.

Private copy eligibility lives in an internal VMA interval set; pending/acquired
state uses private PTE bits, outside frame/permission fields. Mapping replacement,
unmap and release clear state; protect and remap preserve it; discard drops
acquired frames while retaining eligibility. Permission checks and raw shared
read-only checks precede acquisition. The ordinary warm untracked write keeps
the existing single combined flag branch. x86/WoW64 and ARM64 instruction-level
stores, cold/warm access, concurrent probes and mapping lifecycle are covered.

Explicit NtAllocateVirtualMemoryEx node0 preference belongs to a newly created
reservation. Commit into an existing reservation does not change its preference;
decommit/recommit retain it and release/reuse clears it. Public Allocation,
Mapping and Vma fields, C ABI1.14.0, defaults and dependencies remain unchanged.
RegionInfo and basic page-run querying move to a focused sibling module while
retaining their existing public path through re-export.

The independent capture spans four ABI profiles on one Windows10.0.29683 ARM64
kernel. It does not establish a separate x64 kernel. The compiled replay compares
1608 captured prefix/status/guard/access/fixed-field observations; it masks
allocation base/size/commit bytes because the guest fixture has different
allocations. Independent private/image/shared/reserved/NUMA lifecycle checks own
those quantities. Full source, native controls, selected targets and owning
consumer validation are recorded with their exact execution boundaries; complete
process support and current-root GUI/plugin/package proof remain separate.

[Region-query contract and evidence](../../../docs/specifications/windows/native-region-information/README.md).

### Verified current-session directory alias projection (2026-10-20)

The current Windows x64 CI constructor rejection identifies a SymbolicLink entry
at `\Sessions\34651\BaseNamedObjects`, with the exact expected name and no
attached child. Its target is unknown in that trace. A private four-ABI native
probe independently establishes that following a directory link can yield the
same underlying object as a separately opened directory, while the parent still
enumerates SymbolicLink and OBJ_DONT_REPARSE returns 0xC000050B.

Selection now retains the bounded fixed directory handles until identity checks
finish. Only the current nonzero-session BaseNamedObjects alias may project to
an independently captured `\BaseNamedObjects` object. NtCompareObjects must
return success for the pinned pair and a refreshed alias open; captured link
text/access must remain stable. The export is resolved only for this profile.
Mismatch, unavailable evidence, or changed authorization/case metadata fails
with an explicit diagnostic. No arbitrary native link target is opened.

The immutable namespace keeps SymbolicLink enumeration/query metadata and
attaches a separate resolved-directory identity. Directory opens and Win32
named-object ownership reuse the selected target Arc; DONT_REPARSE, type errors,
partial-directory uncertainty, counted-name grammar and the63-reparse budget
remain enforced. The ordinary Directory type/name/attachment rejection remains
unchanged for captures without identity evidence. Native handles close before
publishing the guest namespace, including cleanup on acquisition errors.

A compiled pre-fix regression observes0passed/1failed. Three portable alias tests
cover canonical identity, unproven/wrong/duplicate pairs, missing capture/link
metadata, rights/case disagreement, partial enumeration, malformed suffixes and
reparse boundaries. A Windows-only acquisition test creates private temporary
parent/child/link objects, checks the actual adapter's positive identity and
0xC00001AC distinct-object rejection, and closes its handles. No public ABI,
feature default, dependency, guest permission or persisted schema changes.

This group does not assert that the actual CI alias resolves to the fixed target
until that lane executes it. Other alias profiles fail closed with captured
target/comparison context. Native probes use one build29683 ARM64 kernel across
four ABI views. Retained Assist ABI184 consumers and current-root ABI272 products
remain separate; the larger same-host Linux/macOS/Windows objective is active.


### Read-only NT file metadata queries

`NtQueryAttributesFile` and `NtQueryFullAttributesFile` use guest-captured
OBJECT_ATTRIBUTES and counted names, then query authorized mapped host files or
selected installed DLLs. Native 64-bit basic output is 40 bytes; WoW64 basic
output is 36 bytes and preserves its four-byte ABI padding. Full output is
56 bytes in each view. Native output alignment is eight bytes; WoW64 alignment
does not constrain the copied destination. Fixed output spans are probed before
publication. WoW64 copies name, security and QoS headers, then reachable even-length
name bytes, before probing output; native callers probe output first. Native
security validation precedes QoS semantics and name-header capture. QoS tracking
mode validation precedes impersonation-level validation in both views. Times retain
100 ns FILETIME units since 1601-01-01; sizes are bytes.

NT DOS-drive paths preserve trailing dots/spaces and do not apply Win32 dot,
parent or repeated-separator normalization. Relative names require an owned
file/directory handle. An empty name uses a retained host File where available,
including after pathname replacement. Metadata-only handles keep the existing
path-identity limitation and explicitly reject detected replacement. Native
object-manager device/UNC names, alternate data streams, NUL device metadata,
and unrepresentable host pathnames remain explicit unsupported frontiers.

`host_filesystem=false` still denies arbitrary mapped files. Native-library
selection permits only read-only DLL metadata under the independently selected
runtime directory, preserving the existing canonical-containment check. WoW64
System32 requests use the selected 32-bit runtime view. No general host scope is
implied. The original selected basename spelling survives canonical validation
so OBJ_DONT_REPARSE can reject a filesystem link. Mapped/selected roots are
admitted namespace boundaries; host aliases used to choose them are outside the
guest query's component traversal. Concurrent external host renames/reparse
replacement do not acquire a new atomic-namespace guarantee here.

The Windows adapter marshals fresh host-owned NT arguments or uses a retained
host File handle. Guest pointers, handles, security descriptors, QoS and unchecked
flags never cross that boundary. Actual NTFS allocation sizes and all four time
fields are retained. Unix adapters use actual birth/access/write/change metadata
and `st_blocks * 512` bytes; directories expose no file-data size. Missing birth
time is explicit unsupported metadata, rather than an invented timestamp.
Uncaptured case folding is ASCII only; installed profiles use their captured
UTF-16 upcase table. Ambiguous fallback matches fail explicitly.

Native producer v10 contains 426 roles for each of two services over ARM64, x64,
x86 and x86-LAA on one Windows 29683 ARM64 kernel: 3,408 observations. Of these,
1,848 observations cover 231 controlled fault pairs per service/profile. The
compiled pairwise regression compares 1,386 emulated calls across three guest
architectures against that independently captured status/output-protection oracle. This is
not independent physical x64-kernel coverage. Earlier rejected harness builds
and the corrected supplemental root-handle range remain separate evidence.
Compiled regressions establish the absent-service baseline. Complete native
platform, linked-owner and ordinary-program results belong to this group's
validation ledger; implementing these queries does not establish full Windows
process support or completion of the wider Linux/macOS/Windows objective.


## CSR qualification on the updated ARM64 kernel

The selected ARM64/session 0 CSR metadata, secure connection and USER exchange
now admit Windows 10.0 builds 29683 and 29695 through one finite build predicate.
Frozen native observers on 29695 confirm the PEB/getter identities, full 1 MiB
readonly SharedSection geometry, client USER views and request/reply layouts.
The primary projections, arithmetic, assumption register and reproduction inputs
are in docs/specifications/windows/native-csr-kernel-profiles/README.md.
This does not extend other native profiles, physical AMD64 admission, generic
CSR services or complete installed-library startup. Original fault fixtures,
assertions and execution limits remain unchanged.

## NLS qualification on Windows 29695

Initialization and query-only MUI now admit Windows 10.0 builds 29683 and
29695 through one NLS-specific predicate shared by acquisition and dispatch.
Independent native controls establish equivalent output, guard, mapping,
protection and query behavior on the updated ARM64 kernel. Corrected x86
controls use the observed three-slot `RET12` ABI; original producers remain
unchanged. Three fresh captures correlate payload generation with the shared
language count. Independent main/thread and resource controls also qualify
the existing guest-owned WoW64 companion state on ARM64 kernel 29695, allowing
the x86 installed-leaf checks to run. Sources, hashes, exact counts, bounded memory arithmetic and
assumptions are recorded in
docs/specifications/windows/native-nls-build-29695/README.md.
Other native build profiles, cache mutations and complete installed-library
execution are separate boundaries. The original hardware-fault fixture and
execution limits remain unchanged.

Selected macOS/Linux suites each pass 22 NLS, 8 MUI and 7 WoW64 tests; native
Windows passes 30, 13 and 7, plus 39 namespace tests. Complete C API suites pass
191 tests on every host, with no ignored cases. The unchanged original hardware
fault fixture completes its ARM64 case, then the x86 case reaches an unqualified
ProcessImageInformation copy on kernel29695. Overall fault-fixture completion
and the wider installed-library objective remain unproven.


## ProcessImageInformation on ARM64 kernel 29695

The installed class 37 query admits captured ARM64 Windows 10.0.29695 alongside
29683. Copy-group and guard policy still follows captured kernel identity,
not caller ISA or spoofed guest version. The AMD64 20348/26100 profiles and
built-in policy are unchanged. Four native process views contribute 2800 new
matrix calls and 45 image profiles; separate suspended-child controls qualify
directory presence independently of PE flags. Full replay retains 7708 query
rows, 126 image profiles and 20 suspended-child profiles across four kernels.
The native observer, metadata encoder, masks, rights, allocation bounds and
unqualified image-state behavior remain unchanged. Sources, byte identities,
exact counts and assumption PI95-A1 are in
 docs/specifications/windows/native-process-image-information/README.md.

The unchanged hardware-fault fixture completes ARM64. x86 advances beyond
class 37, then stops at class 63 fault reporting after an earlier access violation
at PC 0x4b314477. The earlier fault requires tracing; full exception continuation
and the overall Linux/macOS/Windows installed-library objective remain incomplete.

The selected process-query suites pass 24 cases on macOS/Linux and 28 on native
Windows, including the installed native/WoW64 leaf. Complete C API suites pass
191 on every host; all 17 pure projection checks also pass on each host.
No selected case is ignored. These are combined-frame library/C API checks;
linked current-root shipping qualification remains separate.


## WoW64 CSR BASE startup on ARM64 kernel 29695

`NtWow64CsrClientConnectToServer` now models the measured pure-x86 BASE
connection using five stdcall arguments and a scalar byte count. The installed
leaf owns its `RET20` cleanup. Admission binds both immutable process-owned
WoW64 and selected CSR kernel/session metadata; guest version fields cannot
select another native profile. No caller request reaches host CSR.

The first connection owns a private peer, a 65536-byte shared client view,
a readonly 1048576-byte selected section reservation with 20480 committed
bytes, and an ALPC port. Native64 PEB publication precedes the Boolean store;
x86 PEB publication follows it. First-call buffer faults retain two unmapped
Section handles per attempt. Boolean faults preserve the connection and native
PEB, and retries complete the pending x86 publication. An initial readonly
buffer succeeds; a connected successful-size call requires buffer writeback.
The bounded model admits ARM64 native kernel10.0.29695/session0 and BASE
server1, and rejects unmeasured profiles explicitly.

Independent native controls contribute 31 fresh/retry cases and 38 returns,
plus 336 repeated calls across pure and CHPE process families. Sources,
artifact identities, exact mapping arithmetic, copy order and assumptions
WC1-WC3 are in
`docs/specifications/windows/native-wow64-csr-connect/README.md`.
The native Windows gate passes all11 CSR cases, including the actual installed
x86 leaf. The unchanged original hardware-fault fixture completes ARM64 and
advances through the x86 CSR connection, then stops at unimplemented
`NtQueryInformationProcess` class26 (`ProcessWow64Information`). Its source,
executable, assertions and budgets remain unchanged. Full fault-fixture and
Linux/macOS/Windows installed-library qualification remain incomplete.

Final macOS/Linux CSR filters each pass10 cases; complete C API filters pass191
on all three hosts. The tail-ordinal check passes on all three, as does the
portable evidence verifier. All listed selected gates have zero failures and
ignored cases. Initial broad filters retain their original nonzero verdicts:
1476/1 macOS, 1470/1 Linux, 1602/3 native Windows (passed/failed). The stale
tail assertion was corrected and rerun; the other native failures are the
class26 fixture frontier and a volume replay whose frozen flags0x00020020 differ
from a direct native29695 result0x00220020. Those remaining failures prevent
a full-green Windows or shipping-runtime claim.

### Owned ProcessWow64Information

Class26 now reports the existing guest PEB32 for x86 and zero for a 64-bit
self-process. Native64 and WoW64 retain their independently measured alignment,
length, handle-right, alias, guard and write-order behavior; failed lengths remain
untouched. The [native build-29695 record](../../../docs/specifications/windows/native-process-wow64-information/README.md)
contains 2,522 native cases across ARM64, x64 compatibility and default/enabled/
disabled CHPE x86. Replay rebases only explicitly identified PEB32 output bytes.
Foreign-process identity and unknown installed native architecture stay explicitly
unsupported. These observations do not qualify every Windows kernel/profile or
complete the broader host-library-backed process objective.

### Permanent ProcessExecuteFlags setter

Class34 NtSetInformationProcess now implements the measured rejection path for
the existing permanent-NX guest profile. Native64 and WoW64 share alignment,
exact size and exact pseudo-handle validation, but WoW64 retries a reached input
read guard and classifies its actual flags. Query state and page permissions
remain unchanged. The [native setter record](../../../docs/specifications/windows/native-process-execute-flags-set/README.md)
binds 5286 independent calls across native64 and pure/CHPE x86, plus eight
full-width native64 handle boundaries. Mutable/default DEP and ATL behavior
remain unfinished requirements for full process emulation.


## Opening retained guest thread objects (2026-10-28)

`NtOpenThread` now resolves the current or retained peer thread in the guest
object namespace. PID zero selects lookup by TID; an explicit PID must match
its owner. Exited objects remain discoverable while handles or waits retain
references. Generic and implied rights, independent per-handle grants and
inheritance come from one shared model. Missing native access capture refuses
opening rather than inventing a grant. The new export family is appended, so
previous ordinals and trap addresses remain stable.

Native64 and WoW64 use distinct measured input/output probe order. The native
adapter creates and joins a private default-security thread, retains its native
handle during four fixed access controls, and closes every handle. Host
impersonation is not accepted as the captured primary subject. Guest addresses,
IDs, handles, masks and syscall numbers never reach those host calls.

The [thread-opening record](../../../docs/specifications/windows/native-open-thread/README.md)
binds the complete C producer, 870 retained ARM64-host observations, the 867
case replay, three explicitly bounded asynchronous-release observations, and
native AMD64/WoW64 CI collection. Dedicated installed-leaf tests verify native
and x86 service entry, caller state, guards, handle identity and RET16 cleanup;
repeated native capture checks handle-count conservation.

The unchanged installed ARM64 CMD passes its prior NtOpenThread frontier and
stops at `NtSetInformationVirtualMemory` (`0x1B0` on build29695), exiting125
before stdout. Native CMD emits the requested marker and exits0. Full
Linux/macOS/Windows installed-library process support, Windows child-process
namespaces, custom thread security and subsequent kernel services remain
unfinished requirements.
