# File-backed x86 SectionImageInformation on Windows ARM64 build 29708

The installed SysWOW64 CMD pipeline queried class 1 of `NtQuerySection` twice
for the x86 CMD executable before printing `rax pipe\r\n`. The native
debugger observed the WoW64 dispatcher issue each query with a 64-byte native
output and a private ReturnLength. Both returned success and 64 bytes. The
captured `Machine` was `0x014c`, file size was `0x00040000` bytes, and the
checksum was `0x00046fcd`. The debugger transcript SHA-256 was
`9a8d5338dd801473840e3212e97e171580735b1f5bb74c0f4d710cbd8098dd2e`.

An independent [native control](image-information-29708-wow64.c) opened the
installed SysWOW64 CMD file from a native ARM64 executable and a WoW64 x86
executable. Each queried both whole-file image section modes, both query
grants, and three sizes. On success, each caller received its own record
width and retained every guard byte after it. The native and WoW64 fields
following the stack sizes agreed byte for byte.

| Query case | Native ARM64 result | WoW64 x86 result |
| --- | --- | --- |
| One byte short | STATUS_INFO_LENGTH_MISMATCH, ReturnLength preserved | STATUS_INFO_LENGTH_MISMATCH, ReturnLength `0xfffffff0` |
| Sufficient buffer without SECTION_QUERY | STATUS_ACCESS_DENIED, ReturnLength preserved | STATUS_ACCESS_DENIED, ReturnLength `0xfffffff0` |
| Sufficient buffer with SECTION_QUERY | STATUS_SUCCESS, 64 bytes | STATUS_SUCCESS, 48 bytes |

Failed queries preserved the data buffer on both caller widths. The WoW64
record narrows TransferAddress and stack sizes to 32 bits, retains the
32-bit ZeroBits field, and copies the 32-byte tail from the native record.
The transfer address remains in the emulated image's coordinates. The
observed `0x003fe160` transfer address and `0x0001e160` entry RVA imply
an observed base of `0x003e0000`. The installed PE's preferred base
`0x00400000` gives the modeled transfer address `0x0041e160`.

The emulation query reads immutable metadata attached to the guest-owned
whole-file image Section. This x86 conversion applies to ordinary x86
executables with representable 32-bit fields. Named installed sections,
truncated views, DLL metadata, and WoW64 queries for other image machines
remain outside the captured profile.

The [normalized observations](image-information-29708-wow64.json) retain all
24 status and copy-back cases and both canonical records with the transfer
address replaced by its entry RVA.

| Artifact | SHA-256 |
| --- | --- |
| Installed x86 CMD | `e44c6777f63982211eb0ac7d6a2a6d53b46bff1928e5005c84b2847a25761002` |
| Native ARM64 probe stdout | `3c82be3e13b86beff831e597467f7671497adcb6a3265415e6f031887f444ab2` |
| WoW64 x86 probe stdout | `01c322b3c9771dc85f70c60b8a8f46cf26ad45082befa0bde20abeb0fac0b33c` |
