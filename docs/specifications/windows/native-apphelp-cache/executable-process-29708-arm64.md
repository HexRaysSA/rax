# Executable process-cache lookup on Windows ARM64 build 29708

`kernel32!BasepQueryAppCompat` passes operation 11 to
`CompatCachepLookupExeProcessImpl`, which calls the installed
`NtApphelpCacheControl` leaf. A console debugger observed three calls for
installed `cmd.exe` and three for installed `where.exe` during ordinary child
launches. Both commands used the installed Windows libraries and finished with
exit status 0.

The observed 392-byte request has mask `0x1f` at offset 0, flags `0x10` or
`0x30` at offset 4, and a counted UTF-16 image path at offset `0x30` with its
buffer pointer at `0x38`. The output buffer pointer is at `0x178`. The caller
sets the size at `0x180` to 4096 bytes. Each reply returned success, copied
64 bytes to the output buffer, and reported 64 at `0x180`. The fields at
`0x170` and `0x184` were zero at entry and return. The replay stores the
captured words in [executable-process-29708-arm64.json](executable-process-29708-arm64.json).

| Record type | Payload bytes | Observed payload |
| --- | --- | --- |
| 2 | 0 | Empty |
| 8 | 8 | Zero |
| 4 | 8 | Zero |
| 16 | 8 | Zero |
| 1 | 0 | Empty |

The emulator supplies this reply for those two paths under its selected
native system directory when the native ARM64 build and request fields match
and its immutable creator registry snapshot establishes absence of an
executable-specific Layers value. It checks both guest output destinations
before publishing the reply. Other executable policies, request shapes,
builds and architectures require independent capture. The guest request
queries the selected model and writes guest memory.

The installed ARM64 NTDLL SHA-256 was
`ef1c9034813e18e5fb7cf6dc44802c15952d27dcecec46813ba883adda572f44`.
The installed kernel32 SHA-256 was
`5304ce21e3dd34f62ec336e0c68e2cad3e8ad414119560e405610f72425f48ff`.
Microsoft's public PDB names the ARM64 implementation at RVA `0x3c088`.
