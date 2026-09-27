# CRT global registration and termination reference receipts

This archive supplies primary evidence for genuine Windows CRT imports and
the application-scoped ordinary/quick exit registries. It also records
termination and TLS dependencies that remain separate implementation work.
Baseline HEAD: `06e90d4bb41e0390a877819ed41ed98e369558a3`. Retrieval date:
2026-09-27. Native Windows execution equivalence is unknown.

The Microsoft SDK source and headers are proprietary publisher inputs.
`sources.json` retains their member names, sizes, SHA-256, ZIP CRC32, package
version, URLs, and retrieval recipes. Their raw source/header/license bytes are
retrieved into temporary inspection directories and are excluded from feature
commits. Locally inspected earlier copies under `microsoft-sdk/` are ignored by
the local `.gitignore`. Neither source availability nor an SDK package implies
an open-source redistribution license. The package's original copyright,
publisher identity, and SDK license receipt are preserved as metadata; a blanket
source redistribution grant is unknown.

## Acquisition and verification

```sh
ruby docs/specifications/windows/crt-termination/acquire.rb
ruby docs/specifications/windows/crt-termination/acquire.rb --verify
ruby docs/specifications/windows/crt-termination/acquire.rb --verify-network
```

Acquisition reuses earlier retained reference inputs by exact
SHA-256 and byte size. It downloads pinned MinGW-w64 v14.0.0 source and extracts
installed Zig producer/header bytes without normalization. Installed archive
symbol inventories distinguish genuine import members from local compatibility
bodies. Existing GCC/Zig producer object inventories are reused without rewriting
their source archive. `producer/` also preserves exact installed x86/x64/ARM64
`atexit` wrapper instructions and relocations to `_crt_atexit`, plus the cached
ARM64 TLS callback's branch relocation to the TLS registrar. These object
observations do not prove native execution or cache/source revision identity.

The Microsoft publisher input is [Windows SDK for C++ NuGet package
10.0.26100.1](https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.cpp/10.0.26100.1/microsoft.windows.sdk.cpp.10.0.26100.1.nupkg).
The script verifies the complete 155,613,545-byte HTTPS package stream against
the SHA-512 returned by the publisher CDN's `x-ms-meta-SHA512` response header.
It retains no package binary. The `.nupkg.sha512` endpoint returned HTTP 404;
the recorded digest is the CDN header value. NuGet author/repository signature
verification is not claimed.

Each source/header/export input is independently extracted with HTTP byte
ranges. The script validates the ZIP end record, complete central directory,
local member header and name, compression method, uncompressed size, and CRC32.
Temporary SDK source inspection paths are printed after acquisition. Offline
verification checks committed output bytes and available installed inputs;
it counts publisher source receipts without claiming those raw inputs are in
the repository. Network verification re-fetches every publisher source receipt,
re-observes three official DLL export sets, and repeats the full package hash.
No Microsoft `.dll` or `.lib` input is retained.

## Exact bindings and producer ownership

`symbols/microsoft-ucrtbase-{x86,x64,arm64}.txt` derives from the three genuine
publisher redistributable `ucrtbase.dll` files in that package. Every selected
named export appears in all three observed DLLs:

| Named export group | All three observed UCRT DLLs |
|---|---|
| Ordinary/quick registration | `_crt_atexit`, `_crt_at_quick_exit` |
| Full/minimal returning cleanup | `_cexit`, `_c_exit` |
| Process termination | `exit`, `_exit`, `_Exit`, `quick_exit` |
| Executable TLS callback registration | `_register_thread_local_exe_atexit_callback` |

The selected genuine export sets contain no `atexit`, `_onexit`, `onexit`, or
`at_quick_exit`. The pinned MinGW UCRT/runtime API-set DEF lists the genuine
underscored registrars without architecture-specific restriction macros.
For legacy MSVCRT, the retained DEF maps the link-time `_crt_atexit` alias to
the actual DLL spelling `atexit`; that alias is not proof of a named
`msvcrt.dll!_crt_atexit` export. MinGW's `_onexit` is a local wrapper around
its module's `atexit`; `onexit` is a local alias. SDK `_onexit` return type is
a callback pointer; its callback takes no arguments and its return is ignored.

The executable MinGW `atexit` wrapper calls `_crt_atexit`. The DLL wrapper
instead uses its own explicit table so it drains on DLL detach after the user
entry point. The `at_quick_exit` wrapper returns zero for a DLL without
registering a dangling global callback; for an EXE it calls
`_crt_at_quick_exit`. These are producer implementation facts, not permission
to expose local wrappers as native DLL exports. The current feature admits
only genuine UCRT/runtime API-set global registrar names. Legacy MSVCRT global
ownership remains separate work.

## SDK registry contract

Receipt `microsoft-sdk/onexit.cpp` identifies the publisher source member
`c/Source/10.0.26100.0/ucrt/startup/onexit.cpp`. It defines distinct ordinary
and quick global tables. A registrar appends an encoded callback under the
selected exit lock and returns zero on success or negative one on allocation
failure. A null callback is stored as an encoded null and later skipped.
The initial capacity is 32 pointers. Capacity doubles while the old capacity
is at most 512 pointers, including growth from 512 to 1,024 pointers; subsequent
growth uses a fixed 512-pointer increment. An allocation
failure attempts a four-pointer fallback increment before failure.

During a drain, the SDK marks a callback slot as visited before invoking it.
After the callback it re-reads table begin/end-of-used pointers and restarts
reverse traversal if they changed. Thus callbacks can register more callbacks
into the same live global registry. Returned integer values do not control
the drain. Locking source uses Windows critical sections; same-thread entry is
recursive and another thread waits. The SDK package omits MSVC's
`internal_shared.h`, which owns the exit-lock selector's body. Exact
application/system-isolation selector behavior is unknown.

The pre-existing explicit-table personality detaches and invalidates an active
generation before guest callbacks and requires explicit initialization for a
new generation. That compatibility profile is not the SDK's mutable live-table
algorithm. The current feature preserves that profile while sharing the exit
lock for registration/execution with the new application-scoped global
registrars; the table initializer remains unlocked as in the SDK. Tests must distinguish
those contracts; an explicit-table pass does not establish global SDK traversal
parity.

Ordinary append has amortized O(1) time during the doubling phase; with capped
growth and repeated moving allocations, total construction can be O(n²) in
the number of registered pointers. Storage is O(n) pointers. A drain without
registration is O(n); adversarial callback registration and repeated traversal
restarts can exceed that bound. Callback code and recursion are independent
execution costs. Pointer storage is 4 bytes on x86 and 8 bytes on x64/ARM64;
Windows callback reason/`unsigned long` remains 32 bits on every ABI.

## Separate termination and TLS dependencies

Receipt `microsoft-sdk/exit.cpp` identifies the genuine publisher implementation.
Full cleanup invokes the registered TLS callback as
`(nullptr, DLL_PROCESS_DETACH, nullptr)`, then drains the ordinary table.
Both `exit` and `_cexit` use full cleanup. Quick cleanup drains the separate
quick table. `_exit`, `_Exit`, and `_c_exit` use no CRT callback cleanup.
`_cexit` and `_c_exit` return; other forms terminate. Complete state is set only
after a terminating cleanup, so a returning `_cexit` can invoke the TLS callback
again. The callback's idempotence is producer-owned. Process-end policy selects
ordinary `ExitProcess` for desktop applications and `TerminateProcess` for
specified application/enclave policies; minimal/quick CRT cleanup does not by
itself imply forced OS termination.

SDK `process.h` declares a cdecl, void-returning TLS registrar taking a
`void (__stdcall *)(void *, unsigned long, void *)`. On x86 the callback has
three 4-byte stack arguments and 12-byte callee cleanup. On x64/ARM64 the
platform ABI applies with a 32-bit reason. A registered non-null callback can
be set only once; a duplicate calls `terminate()`. Registering null leaves the
encoded-null sentinel and does not consume a non-null registration. `terminate`
can call a per-thread handler, then falls back to `abort`. Retail default abort
can issue fatal-app-exit fast-fail; exit status 3 is only a non-reportfault
fallback. No universal duplicate-registration exit status is established.

MinGW `tls_atexit.c` distinguishes the EXE's CRT TLS destruction callback from
normal image TLS notifications. DLL destructors still run on ordinary DLL
detach after `_exit` or `ExitProcess`; the EXE-specific callback suppresses
EXE destructors when CRT cleanup is bypassed. Its destructor lists are not
generic FLS destructor state. The UCRT's per-thread FLS record releases CRT
private state and is distinct from C++ object destruction.

There is a material static/dynamic stdio distinction. Publisher
`stdio_initializer.cpp` places stdio uninitialization in `.CRT$XPXA`;
`_file.cpp` flushes and closes streams there. `exit.cpp` executes preterminators
only for statically linked CRT builds. A dynamic `_cexit` therefore has no
direct stdio-preterminator call in the inspected SDK code. Retail dynamic CRT
process detach separately flushes initialized stdio even for minimal/quick
CRT termination (`initialization.cpp`). Public documentation describes
unqualified `_cexit` flush/close and `_exit`/`_Exit` no-flush behavior. These
sources must not be collapsed into one unverified cleanup contract. Native
recordings for the exact CRT link/version combination remain unknown; current
registration fixtures do not claim to resolve that equivalence.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | The inspected SDK version supplies relevant application-scoped UCRT registry semantics. | Publisher package/version, exact source receipts, genuine three-ABI export observations. | Global registry design and prototypes. | Null, duplicate function, growth beyond 1,024 slots, callback registration during drain. | Execute the same witnesses against a pinned native UCRT version and compare state/order. | retained; native version equivalence unknown |
| A2 | Application-default lock selection is consistent across registrar and explicit-table registration/execution; initialization is unlocked. | Repeated SDK use of the same selector; critical-section implementation; unlocked SDK initializer; CRT application-global-state documentation. | Shared recursive exit-lock personality. | Same-thread nested tables, independent initialization, and blocked other-thread registration. | Inspect genuine MSVC `internal_shared.h` or obtain an application/system-mode native lock witness. | retained; selector body unavailable |
| A3 | Installed Zig and GCC producer inventories refer only to their hashed bytes. | Exact installed source/object/archive hashes and command replay. | Binding/call-site claims. | Installed tool/archive replacement, cache removal. | Offline verifier reports changed/missing inputs rather than silently reusing an output. | confirmed locally; upstream Zig bundle commit unknown |
| A4 | Event synchronization plus 20 ms guest sleep lets the concurrency fixture's worker reach the held CRT lock. | Deterministic guest scheduler is the fixture target; source exposes both attempted/done events. | The fixture's blocked-registrar witness; no native timing claim. | Guest scheduling slices of 1 and 4,096 instructions. | Run the owning runtime runner; a signaled done event while the owner callback holds the lock or a watchdog timeout disproves the witness. | retained; runtime evidence belongs to the owning feature runner |

## Bounded findings and acceptance limits

High: the static/dynamic stdio cleanup distinction, duplicate TLS abort policy,
managed/application termination policies, legacy MSVCRT queue ownership, and
native equivalence remain separate correctness obligations. They block broad
termination-equivalence claims but do not block genuine global-registration
implementation. High: proprietary SDK source redistribution is not established;
raw SDK inputs are excluded from feature commits.

Medium: application/system global-state isolation and the MSVC exit-lock selector
body are not supplied by this SDK package. Medium: existing explicit-table
compatibility behavior differs from the SDK traversal; retain the distinction
in tests and documentation. Low: queue stress above the growth thresholds is
possible but does not establish runtime performance.

Archive changes affect documentation/reference evidence only. ISA decode,
execute, CPU/MMU, SMIR, optimizer, native lowering, JIT, VM backend, machine,
device, and public C ABI implementations are outside this archive's ownership.
Runtime and fixture gates belong to their owning feature. Source/license
receipts, commands, byte widths, unknowns, and reused paths are covered by the
verifier; no unrelated test suite, native execution, or feature completion is
claimed by a successful archive command.
