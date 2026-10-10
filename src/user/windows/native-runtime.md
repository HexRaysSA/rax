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

Supported kernel operations remain the existing checked NtClose, memory
allocation/free/protection, context continuation and forced termination APIs.
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

Primary API contracts:
[Windows API sets](https://learn.microsoft.com/windows/win32/apiindex/windows-apisets),
[LoadLibraryExW](https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw),
[GetSystemDirectoryW](https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw),
[GetSystemWow64DirectoryW](https://learn.microsoft.com/windows/win32/api/wow64apiset/nf-wow64apiset-getsystemwow64directoryw),
[RtlGetVersion](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlgetversion),
[OSVERSIONINFOEXW](https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-osversioninfoexw).
