# Installed pure x86 image-family selection

RAX selects the installed SysWOW64 x86 NTDLL and its absolute
`\KnownDlls32\ntdll.dll` image. On ARM64, the previously captured default
CHPE-enabled section profile redirected later opens relative to a
`\KnownDlls32` directory handle into `\KnownDllsChpe32`. That mixed pure
x86 NTDLL with hybrid Kernel32 and KernelBase. The hybrid Kernel32 imports
`__C_specific_handler`, which the selected pure x86 NTDLL does not export.

The unchanged build-29695 x86 hardware-fault fixture therefore reached
`NtRaiseHardError` with status `0xC0000139` (`STATUS_ENTRYPOINT_NOT_FOUND`),
three parameters, Unicode mask `3`, export `__C_specific_handler` and module
`C:\WINDOWS\System32\KERNEL32.DLL`. This was a loader failure before the
fixture's intentional access violation. The private-transition stack retained
argument zero at saved ESP plus 8 bytes; decoding was observational.

Installed x86 runtime acquisition now selects a CHPE-disabled process section
profile. Its relative opens retain `\KnownDlls32`, consistently with its
NTDLL and file adapter. The real native machine remains `0xAA64` and WoW64
CPU flags remain `2`. The captured CHPE directory, absolute image identities,
grants, case policy, handle tags, and native64 lookup behavior are preserved.
Namespace clones select their process policy independently.

## Independent native controls

The controls ran on Windows `10.0.29695`, native ARM64, using MSVC
`14.51.36231` with `/std:c++20 /MT /EHsc /utf-8 /W4 /WX`.
The ARM64 [launcher-v2.cpp](launcher-v2.cpp) creates only its owned x86
[probe-v3.cpp](probe-v3.cpp) children through `NtCreateUserProcess`.
It passes `PS_ATTRIBUTE_CHPE` (`0x6001A`), size 1 byte, inline BOOLEAN
value 0 or 1; a third control omits the attribute. No host compatibility,
registry, antivirus, desktop or VM policy changes are involved.

| Native creation profile | Loaded and relative-open image family | NTDLL handler RVA | Native / guest machine | WoW64 flags |
| --- | --- | --- | --- | --- |
| Attribute omitted in the raw NT creation call | SysWOW64 | Absent | `0xAA64` / `0x014C` | `2` |
| Attribute `1` | SyChpe32 | `0x60F0` | `0xAA64` / `0x014C` | `2` |
| Attribute `0` | SysWOW64 | Absent | `0xAA64` / `0x014C` | `2` |

The omitted raw-NT attribute is not the default Win32 `CreateProcess` profile:
the earlier ordinary Win32-created x86 control selected SyChpe32. The explicit
0/1 comparison establishes the process axis independently of that default.

Each child captures the loaded NTDLL/Kernel32/KernelBase images, then maps
three images from three absolute KnownDll directories with four machine
selectors: `3 * 3 * 4 = 36` maps. Three additional direct-root relative
maps produce 39 cases per child and `3 * 39 = 117` cases total, with 24
successful maps per child. Successful views are unmapped and handles closed;
all three children exit 0. A preceding version without the WoW64-info read
independently produced the same image-family result and three zero exits.

PE machine/magic/extent, export RVAs and code bytes identify image kinds.
`NtQueryVirtualMemory(MemoryMappedFilenameInformation)` supplies the backing
path. The 40-byte WoW64 information at x86 PEB plus `0x490` records page size,
CPU flags and native/guest machines; address and handle fields are opaque.
Native64 process-create output PEB fields were not requested and are not used.
The launcher polls each owned child for at most 30 s and closes its handles.

[local-29695-v1.json](local-29695-v1.json) binds the complete observed child
stdout, source/binary/compiler/driver identities and unchanged-input receipts.
Run `python3 -B check-evidence.py` to verify producer hashes, all 117 map rows,
image-family and WoW64 invariants, and rejection of a corrupted disabled
profile even after its claimed stdout hash is recomputed.

The native creation layout comes from primary
[PHNT ntpsapi.h at 53fbbdc5](https://github.com/winsiderss/phnt/blob/53fbbdc5b5d2b08761db1c7b26bfa8c820924356/ntpsapi.h).
The native64 `PS_CREATE_INFO` size is 88 bytes: 16-byte aligned prefix plus
72-byte union. The first diagnostic version incorrectly asserted 104 bytes
and was rejected at compilation; its executed source was retained unchanged.
Microsoft documents pure x86 execution as the alternative to hybrid execution
in its [Arm app compatibility documentation](https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-program-compat-troubleshooter).
Those sources define the control mechanism; the native capture owns the
observed DLL selection and section behavior on this kernel.
C++ is used only for these independent MSVC/native-ABI controls; production
selection and regression logic remain Rust.

## Assumption register and bounds

| ID | Assumption | Basis | Dependent result | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- | --- |
| CP1 | The selected SysWOW64 runtime requires a CHPE-disabled process section profile independently of host architecture. | Native explicit-0/1 controls with identical machine and CPU flags. | Pure x86 relative section selection. | Re-run controls on another build; observe a disabled child mapping SyChpe32 or a pure RAX runtime importing hybrid Kernel32. | Confirmed for the captured kernel; other builds remain bounded by existing installed-runtime admission. |

The change affects native runtime acquisition and section selection, plus
their tests and engineering documentation. ISA execution, host identity,
permissions, ABI layout/version, persisted state and package layout do not
change. The original CHPE-enabled 93624-row open/duplication replay is retained.
New tests cover independent namespace clones, repeated selection, absolute and
root-relative names, direct roots, handle tags, three guest architectures,
typed output/grants, stack cleanup and handle/resource restoration. The native
installed-leaf test separately requires a pure x86 direct-root identity.

High impact: complete native application startup and exception delivery require
the unchanged original fixture and broader platform qualification; this group
does not establish them. Medium impact: mixed-ISA CHPE execution is separate
from this pure x86 runtime profile. Explicitly named CHPE images retain their
captured identity; this change does not implement their ARM64 code transitions.

## Validation and unchanged-fixture continuation

| Host | Section open / duplication / profile | Namespace | WoW64 | Native start | C API |
| --- | ---: | ---: | ---: | ---: | ---: |
| macOS | 5 passed | 38 passed | 8 passed | 8 passed | 191 passed |
| Linux | 5 passed | 38 passed | 8 passed | 8 passed | 191 passed |
| Windows ARM64 | 6 passed | 39 passed | 8 passed | 9 passed | 191 passed |

These selected suites have zero failed or ignored tests. Windows additionally
executes the installed NTDLL leaves and requires the pure x86 section identity;
the unmodified CHPE-enabled replay still covers all 93624 captured rows.
The full Windows-personality filter passes 1459 tests on macOS without failures
or ignored cases. The broader Linux filter is recorded separately from these
selected gates. macOS/Windows retain the separate native-entry draft; Linux
uses the shared-runtime overlay and excludes that draft and unrelated
Windows-only leaf refinements. This changeset does not publish those files.

The original hardware-fault fixture remains failed overall: ARM64 completes,
while x86 stops during `NtMapViewOfSection` with
`selected native image region exceeds its view`. A fresh observer bound to
the rebuilt library reaches that same stop at ordinary slice 111, before the
new pure image is mapped and before import binding. The native installed-leaf
test independently establishes the corrected selected section. This does not
claim that execution has passed the previous hard-error instruction or that
complete x86 startup works. Original source, binaries, assertions and the
60 s / 16384-slice / 4096-instruction limits remain unchanged.

Source/library checks are separate from current linked Assist shipping,
package and installed-runtime qualification. No physical AMD64 kernel result
is implied by x64 compatibility execution on this ARM64 host. The public RAX
C API remains 1.15.0, with its unchanged 73534-byte header SHA-256
`baaf643f62c525d923529ccbf75a97505a31831592a8aa91ab9be71f5ec144b5`.
