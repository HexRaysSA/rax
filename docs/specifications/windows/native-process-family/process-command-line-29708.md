# Process command line on Windows 10.0.29708.1003

Native ARM64 and installed WoW64 x86 NTDLL ran 28 queries each against an
owned probe process. The queries used information class 60, the process
pseudo-handle, handles with limited query or VM-read access, a null handle,
and the thread pseudo-handle. Initial output bytes were `0xa5`. The native
kernel exposes the command line as a counted UTF-16 string, followed by a
terminator. The returned pointer identifies the string inside the output.

| Caller | Input command bytes | Descriptor bytes | Required bytes | Pointer field | Accepted output offsets tested |
|---|---:|---:|---:|---:|---|
| ARM64 | 294 | 16 | 312 | 8 | 0, 4 |
| WoW64 x86 | 290 | 8 | 300 | 4 | 0, 1, 2, 3, 4 |

The required length is the descriptor length plus the command byte count
plus two bytes for its UTF-16 terminator. A short buffer returns
`STATUS_INFO_LENGTH_MISMATCH` and the required length with the output bytes
preserved. Oversized buffers preserve the suffix past the required length.
The ARM64 result preserves the four bytes between the two count fields and
the pointer. An ARM64 output at offset 1, 2, or 3 returns
`STATUS_DATATYPE_MISALIGNMENT` with the length destination untouched.

The process pseudo-handle and a handle with
`PROCESS_QUERY_LIMITED_INFORMATION` can query the command line. A handle
with only `PROCESS_VM_READ` returns `STATUS_ACCESS_DENIED`. The null
handle and the thread pseudo-handle return `STATUS_INVALID_HANDLE` and
`STATUS_OBJECT_TYPE_MISMATCH`, respectively. For these three failures,
ARM64 preserved the initialized length `0x11223344` and WoW64 reduced it
to `0x1122333c` without writing the output buffer.

The measured WoW64 calls used the installed
`SysWOW64/ntdll.dll` with SHA-256
`ac3d1f2f491437a1143c59898b2ec1dd351291c4daaae2a6c506fb7b81372eea`.
The ARM64 calls used `System32/ntdll.dll` with SHA-256
`ef1c9034813e18e5fb7cf6dc44802c15952d27dcecec46813ba883adda572f44`.
The raw ARM64 and x86 observation streams have SHA-256
`52c066cd1701608228a7ac8cc22f880971a72ac6c8a2530b8a08518c30cb9fce` and
`50d1b66a587acf29aa734c3d43151e8481c20e7ecb8d839e8da03098bde96042`.

The emulator reads the live guest process-parameters record of the caller
or its modeled child. It uses the target layout when reading the command
line and the caller layout when writing the result.
