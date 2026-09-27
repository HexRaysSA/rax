# Freestanding Windows fixtures

`build.sh` builds the same C source for PE32 x86 and PE32+ x64/ARM64 with
Clang, LLD, and `llvm-dlltool`. Import libraries are constructed from the
checked-in `.def` files; no Windows SDK, C runtime, or third-party binary is
linked. `manifest.toml` records compiler/linker identity, source and executable
SHA-256 hashes, executable sizes in bytes, and the expected exit status.

Run `bash tests/fixtures/user/windows/build.sh` to regenerate. For byte-for-byte
reproduction, use the LLVM revision recorded by the manifest. The linker uses a
zero COFF timestamp, and compilation removes host source-directory prefixes.
The checked-in executables are test inputs derived solely from `src/smoke.c`.

The program returns 0 only after checking process/thread identifiers, TEB self
and PEB pointers, PEB image/heap state, last-error storage, stack alignment,
64-bit return values, eight-argument calls, aligned zero-filled heap memory,
reserved and committed virtual regions, page protection splits, decommit and
zero-filled recommit, unchanged neighboring pages, invalid release arguments,
and complete release. Nonzero values identify the failing check in the source.
Calls use x86 `stdcall`, the Microsoft x64 ABI, and the Windows ARM64 ABI.
TEB reads use FS, GS, and X18 respectively.

Expected behavior derives from Microsoft's [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format),
[x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention),
[ARM64 ABI](https://learn.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions),
[HeapAlloc](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc),
[VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc),
[VirtualQuery](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery),
[VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect),
and [VirtualFree](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree).
Primary-source copies and retrieval metadata reside in
`docs/specifications/windows/`. Native Windows execution is unknown: these
are specification-based conformance tests, not recorded differential results.
