# Executable process-cache lookup on Windows ARM64 build 29708

`kernel32!BasepQueryAppCompat` passes operation 11 to
`CompatCachepLookupExeProcessImpl`, which calls the installed
`NtApphelpCacheControl` leaf. A console debugger observed three calls for
installed `cmd.exe` and three for installed `where.exe` during ordinary child
launches. Both commands used the installed Windows libraries and finished with
exit status 0.

The same profile also covers the captured installed `findstr.exe` and
`sort.exe` requests. A CMD batch containing `echo rax sample|find "rax"`
issued three lookups for installed `find.exe` with flags `0x10`, `0x10`,
and `0x30`, in that order. The native batch printed `rax sample` and exited
with status 0. The installed Find image SHA-256 was
`54b0648fb01de3f4ab66dc94578c18c9bd3806a3b63f904ce32059ef03ab31b2`.
The native Find caller trace SHA-256 was
`164fc0dc6de26d72d515662cacc661eb85bd5a6bc82a4dab6ce3a603578172c9`.

The observed 392-byte request has mask `0x1f` at offset 0, flags `0x10` or
`0x30` at offset 4, and a counted UTF-16 image path at offset `0x30` with its
buffer pointer at `0x38`. The output buffer pointer is at `0x178`. The caller
sets the size at `0x180` to 4096 bytes. Each reply returned success, copied
64 bytes to the output buffer, and reported 64 at `0x180`. The fields at
`0x170` and `0x184` were zero at entry and return. The replay stores the
captured words in [executable-process-29708-arm64.json](executable-process-29708-arm64.json).

A separate [native ARM64 probe](executable-process-29708-arm64.c) opened the
installed System32 CMD image and passed its handle at offset `0x18`. Flags
`0x14` and `0x34` returned the same 64 bytes as `0x10` and `0x30`. A null
handle returns `STATUS_INVALID_HANDLE` (`0xc0000008`) and preserves the size
and output buffer. The captured CMD and Findstr profiles support these flags
with a matching file handle and the same creator-registry check.

Build and run this probe on Windows ARM64 with the native ARM64 MSVC tools.

```bat
cl /nologo /W4 executable-process-29708-arm64.c
executable-process-29708-arm64.exe
```

| Record type | Payload bytes | Observed payload |
| --- | --- | --- |
| 2 | 0 | Empty |
| 8 | 8 | Zero |
| 4 | 8 | Zero |
| 16 | 8 | Zero |
| 1 | 0 | Empty |

The emulator supplies the stock reply for the five captured paths when the
build, request fields and creator-registry snapshot match. For a retained
read-only executable from the selected System32 directory on native ARM64
build 29708, it queries the installed compatibility database for flags
`0x10`, `0x14`, `0x30` and `0x34`. It checks the retained file's resolved name
against the requested path, checks the creator's executable-specific Layers
value, and builds the native request from host-owned buffers and the file's
host handle. Both guest output destinations are checked before publishing
the reply.

A native probe on build 29708.1003 opened 690 executables in System32 and two
subdirectory levels. The 2,760 requests returned 2,734 stock 64-byte replies
and 26 replies of 520 bytes. Six executables returned different 520-byte
records consistently across two processes, two flag orders and repeated
requests. The final record (type 1, 456 payload bytes) matches the field
layout of Microsoft's [SDBQUERYRESULT](https://learn.microsoft.com/en-us/windows/win32/devnotes/sdbqueryresult).
The captured built-in database ID is `11111111-1111-1111-1111-111111111111`.
The emulator checks the record types and lengths, contiguous bounded
executable references and their flags, and the database map and GUIDs. This
profile supports the built-in database without explicit layers or an AppHelp
message. A different record shape leaves the guest output and capacity
untouched.

The [native test records](installed-executable-policy-29708-arm64.json) list
the little-endian u32 words of the reply to flag `0x14`. They give two
independent stock examples and six built-in database examples. The repeat
probe's raw ledger SHA-256 was
`8858b11470f58d0c70eccfba2c38cf9ff484e313362b31f2484ad0e0d928088c`.

Run the native guest-memory comparison on the captured Windows ARM64 profile.

```bat
cargo test --locked --no-default-features --lib apphelp_executable_process_matches_installed_policy -- --ignored
```

Closed child selection can open executable basenames directly under the
selected System32 directory on this profile. Executable launches still
follow the guest PE loader and the existing guest process and file checks.
Subdirectory executables and additional AppHelp profiles require their own
runtime coverage.

The installed ARM64 NTDLL SHA-256 was
`ef1c9034813e18e5fb7cf6dc44802c15952d27dcecec46813ba883adda572f44`.
The installed kernel32 SHA-256 was
`5304ce21e3dd34f62ec336e0c68e2cad3e8ad414119560e405610f72425f48ff`.
Microsoft's public PDB names the ARM64 implementation at RVA `0x3c088`.
