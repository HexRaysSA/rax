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
protection, context continuation, forced termination and the installed startup
range query (`NtQuerySystemInformation`, class 50). Other system-query classes
remain explicit unsupported operations.
WoW64's alternate conditional encodings, native RTL heap/bootstrap requirements,
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
Other classes produce an explicit unsupported diagnostic, including the class.

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
| Q3 | Unimplemented system-query classes must remain distinguishable from completed queries. | Checked dispatch handles only class 50. | Caller diagnostics and bounded capability claims. | Classes 0, 1 and 0xFFFFFFFF, invalid buffers and unknown admitted service numbers. | Generic tests require explicit class-bearing failure with no fabricated successful output |

High, still blocking ordinary startup: additional system/process queries, native
RTL heap/bootstrap and the wider NT surface remain incomplete. All four tested
Win32 images now pass the range query and stop explicitly at class 0, requesting
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
