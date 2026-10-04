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

## Guest services fixture

The separate build-services.sh builds services.exe for all three guest
architectures without changing the smoke binaries. services-manifest.toml
records four source/script hashes, compiler/linker identity, three executable
hashes/sizes, and expected exit code 0. LARGE_INTEGER by value exercises the
20-byte x86 stdcall cleanup for SetFilePointerEx.

The program checks suspended/resumed and terminated guest threads, TLS isolation,
contended critical sections and SRW locks, alertable APC delivery, condition and
address wait timeouts, abandoned mutexes, wait-all semaphore consumption,
named-object case/type collisions, restricted access grants, handle protection,
synchronous file I/O, duplicated-handle shared cursors, deferred deletion and NUL.
The runner maps C: to a unique temporary directory, imposes a 30 s external
deadline, and tests scheduling slices of 1 and 4,096 guest instructions.
Native Windows differential execution remains unknown.

## DLL lifecycle fixtures

The separately generated [lifecycle graph](lifecycle/README.md) exercises checked
native loading, forwarding, failed attachment/retry, static TLS across existing
and new threads, normal notifications, balanced unloading and EXE data mapping
for x86, x64 and ARM64. Its generator, source/artifact hashes and labeled profile
assumptions are independent of the smoke/service manifests. The existing
user_windows target reaches the lifecycle runner; native Windows differential
execution remains unknown.

## Fiber/FLS fixtures

The separate [fiber graph](fibers/README.md) checks conversion/reconversion,
fiber-local storage versus thread-local storage, synchronized migration,
call-preserved and floating-point state, normal/forced teardown, and demand
stack growth on x86, x64 and ARM64. Its source/artifact manifest and generator
are independent of the smoke/service/lifecycle inputs. The existing user_windows
target executes each of its 24 programs at two scheduler slices. Exact native
callback ordering, private fiber state and mixed floating-switch flags remain
unknown; fixtures check the explicitly documented RAX profiles.

## Vectored continue handler fixture

The separate [VCH fixture](vch/README.md) imports public KERNEL32
`AddVectoredContinueHandler` and `RemoveVectoredContinueHandler` alongside
VEH and `RaiseException` on x86, x64 and ARM64. It checks first/last
callback order, continuation, removal/repeated removal and cross-family
handle separation at scheduler slices of 1 and 4,096 guest instructions.
Its own manifest records source, tool and binary hashes. The
[retained Microsoft VCH references](../../../../docs/specifications/windows/services/vch/README.md)
define the public API surface; native Windows execution and in-flight
registration-mutation equivalence remain unknown.

## SList, processor-feature and system-time fixture

The separate [SList fixture](slist/README.md) imports the public KERNEL32
SList functions, `IsProcessorFeaturePresent`, `GetSystemTimeAsFileTime`,
`GetProcAddress` and two-thread `CreateThread`/`WaitForSingleObject` on x86,
x64 and ARM64. It checks LIFO order, depth, flush, list push, KERNEL32-to-NTDLL
forwarding identity, fast-fail availability, a CPUID-consistent SSE2 answer,
wall-clock plausibility and conserved depth under contention, at scheduler
slices of 1 and 4,096 guest instructions. Its own manifest records source,
tool and binary hashes. The
[retained Microsoft references](../../../../docs/specifications/windows/services/slist/README.md)
define the public API surface; native Windows execution remains unknown.

## Ordinary MSVC startup check

[`msvc-startup-check.sh`](msvc-startup-check.sh) is the only file this check
keeps in the repository. Run with `--accept-msvc-license`, it downloads
Microsoft's CRT and Windows SDK with xwin into a cache outside the tree
(`$RAX_MSVC_CACHE`, default `~/.cache/rax-msvc-startup`), compiles a console
program with `clang-cl /MD /GS` — the dynamic UCRT and VCRUNTIME140, as MSVC
links by default — for x86, x64 and ARM64 in a temporary directory, checks
the imports, and runs each executable under `rax-user` at scheduler slices of
1 and 4,096. Every run must exit 42 with `msvc-startup ok` and CRLF on
stdout. No Microsoft binary, header or library is committed. The script fails
when a prerequisite is missing rather than skipping; `--arch` selects a
subset.

As of this check's introduction, x64 and ARM64 start through
`__scrt_common_main_seh`, run `main` and exit through the CRT. x86 stops at
`ucrtbase.dll!_controlfp_s`, which the x86 CRT calls during startup to set
the default floating-point precision and which RAX does not implement.
