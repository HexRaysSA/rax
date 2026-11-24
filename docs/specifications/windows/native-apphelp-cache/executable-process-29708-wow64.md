# Executable process-cache lookup for WoW64 CMD on Windows ARM64 build 29708

The installed SysWOW64 CMD ran the stock pipeline in the debugger and printed
`rax pipe\r\n`. At the ARM64 `NtApphelpCacheControl` boundary, the WoW64
dispatcher passed operation 11, mask `0x1f`, flags `0x10`, and the counted
path `C:\WINDOWS\system32\cmd.exe`. The service returned success and copied
a 64-byte record. The debugger transcript SHA-256 was
`16aae0a1804afc46eb8f58d9e818ebe442f1ced2a2c649cd3d2a780d86052299`.
The loaded CHPE modules were visible in that trace.

An independent x86 executable called the installed SysWOW64 NTDLL export
with the 204-byte request format recovered from the installed x86 kernel32
caller. Both `System32\cmd.exe` and `SysWOW64\cmd.exe` returned the same
record with flags `0x10` and `0x30`. Independent captures with flags `0x14`
and `0x34` matched the corresponding replies byte for byte. Each successful
call changed the output size from 4096 to 64 and preserved the canary after
byte 64. Writing the file handle at offset `0x14` left the actual handle
field zero. The native call returned `STATUS_INVALID_HANDLE` and preserved the
output and capacity.

For an installed SysWOW64 CMD launching itself as a closed guest child in
session 0, the first rejected lookup used `0x14`. With that lookup admitted,
a later lookup used `0x34`. Both used mask `0x1f` and an initial output
capacity of 4096 bytes.

| WoW64 field | Offset | Bytes |
| --- | --- | --- |
| Mask | `0x00` | 4 |
| Flags | `0x04` | 4 |
| Image file handle | `0x10` | 4 |
| Image name length and maximum length | `0x1c` | 4 |
| Image name pointer | `0x20` | 4 |
| Driver status | `0xc0` | 4 |
| Output pointer | `0xc4` | 4 |
| Output capacity and written count | `0xc8` | 4 |

The replay requires the captured build, ARM64 host profile, stock CMD path,
ordinary guest-local image file, and a captured creator registry snapshot
showing both CMD spellings free of per-image Layers values in both views.
Other executable-cache results require their own capture.

[The x86 probe](executable-process-29708-wow64.c) writes four binary records
to standard output. Each record consists of six little-endian 32-bit words,
the counted UTF-16 path, and 128 bytes of output with canaries. For the
invalid-handle control, change offset `0x10` to `0x14` on the two `0x30`
calls. For the two additional captures, use flag pairs `0x14`/`0x10`
and `0x34`/`0x30` with the handle at `0x10`. The [normalized observations](executable-process-29708-wow64.json)
contain both successful and invalid-handle replies for replay.

| Artifact | SHA-256 |
| --- | --- |
| Installed x86 CMD | `e44c6777f63982211eb0ac7d6a2a6d53b46bff1928e5005c84b2847a25761002` |
| Installed x86 NTDLL | `ac3d1f2f491437a1143c59898b2ec1dd351291c4daaae2a6c506fb7b81372eea` |
| Installed x86 kernel32 | `c9e74aba968389fc2197768c9d3a7884262b79194878f74688005577131fc9bf` |
| x86 probe stdout, all four valid | `41ee2f9e16193cf0302d60101cf5aabb3cd1ae0947ab1035cbd4a258bafd3d2e` |
| x86 probe stdout, two invalid handles | `f0c1d019bd2aebbd287e1a35d5d0beec49a9bfcfb673001e4f073af425f8fded` |
| x86 probe stdout, four valid 0x10 and 0x14 calls | `d1c82bf3d6ecc759895d51cfc4d7472d41d15bd5bdfa3b9bb73f5ee6de62763d` |
| x86 probe stdout, four valid 0x30 and 0x34 calls | `54cb4e7412f99a8e09b576dd3b89148d76732506c9f64ace25ed2b87b506d797` |
