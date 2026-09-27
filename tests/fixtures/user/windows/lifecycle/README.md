# Compiled native DLL lifecycle fixtures

These CRT-free, SDK-free inputs exercise actual guest imports, callbacks,
entry points and indirect export calls for PE32 x86 and PE32+ x64/ARM64. They
do not replace the existing smoke or services fixtures. Native Windows
execution and differential results are **unknown**.

`dynamic.exe` and `forward-miss.exe` import only KERNEL32.dll and observer.dll.
`startup.exe` also imports root.dll. The remaining graph is:

```text
startup.exe -> root.dll -> leaf.dll
dynamic.exe --LoadLibrary--> root.dll / fail.dll / forward.dll / data.exe
fail.dll / fail-ok.dll -> leaf.dll
forward.dll --GetProcAddress("Probe")--> leaf.Probe   (no import descriptor)
forward.dll --GetProcAddress("Missing")--> leaf.NoSuchExport (absent export)
all callback-bearing DLLs -> observer.dll + KERNEL32.dll
data.exe -> absent-lifecycle.dll                     (deliberately absent)
```

observer.dll has no entry point or imports. Its 128-record fixed guest buffer
survives unloading the DLLs being observed because both test executables
import it. Records contain module identity, callback kind, base, reason,
reserved pointer, TLS value, thread ID, stack pointer and a pointer-width
cookie. The nine-argument logger and exported checksum exercise x64 stack
arguments and the ninth ARM64 integer argument, as well as x86 stdcall.

leaf.dll, root.dll, fail.dll and fail-ok.dll each contain two TLS callbacks
and an explicit TLS directory. The initialized template is 4 bytes; the
zero-fill suffix is 12 bytes; total per-thread storage is 16 bytes. The linker
sets the declared template alignment to 4 bytes. Both callbacks and DllMain
access the per-thread block through the relocated TLS index and TEB TLS
array, then record their arguments. TLS storage is accessed with explicit
PE/TEB operations, not `__declspec(thread)` compiler-generated access.
Observer and TLS DLL preferred bases deliberately collide, forcing TLS VA
and callback-array relocation. The forwarder and data EXE have separate
preferred bases because they need not contain any relocations.

## Checked behaviors and expectation provenance

The dynamic executable checks LoadLibraryW/A, repeated case-insensitive
references, unchanged initialization counts, direct and forwarded
GetProcAddress calls, DLL initialization before an export can be used,
FreeLibrary until reference zero, released image mappings and absent
module/export lookup. It creates one thread before DLL loading and one
afterwards: the old thread receives no retroactive THREAD_ATTACH, while both
threads have fresh independent TLS blocks and receive normal THREAD_DETACH.
The post-unload GetProcAddress call uses a stale module handle to test explicit
personality rejection (NULL); native behavior for that invalid input is
unknown and is not treated as a public-contract conformance result.

A FALSE process attach is retried twice with an already-held dependency and
once with a fresh dependency. Each failed entry point receives PROCESS_DETACH,
its mapping disappears, and pre-existing dependencies remain usable. The
guest then copies fail-ok.dll over **only the temporary bundle's** fail.dll
using synchronous guest file I/O and retries successfully in the same process.
The original checked-in inputs remain unchanged.
The test also expects both TLS callbacks to receive PROCESS_DETACH on failed
attach rollback. That failure-specific TLS notification is a selected profile
expectation: the retained public TLS table describes termination callbacks but
does not establish this exact failure-path behavior, and native equivalence is
unknown.

The forwarder has no import directory. Resolving its export must therefore
map and initialize a fresh leaf.dll before returning its address. Final
forwarder/dependency unload checks follow this personality's documented
graph-reachability lifetime policy; no native forwarder-reference-count
measurement is claimed. The focused `forward-miss.exe` retries a forwarded
missing export twice and requires NULL with ERROR_PROC_NOT_FOUND (127), no
attach notifications, no live leaf module, a cleared TEB TLS-array pointer,
and the original forward module still mapped. It then loads leaf normally,
verifies its fresh attach/TLS state, and frees it while the forward module is
still loaded. Leaf unmapping at that point detects a residual lookup edge.
The rollback/no-attach behavior on lookup failure is selected personality
policy; native failure-path equivalence is unknown. data.exe has an executable entry point and a missing
import. LoadLibrary must load it as data without binding imports or executing
that entry point; its export is looked up but never executed.

The startup executable checks nonzero DllMain reserved pointers for static
PROCESS_ATTACH, zero TLS reserved pointers, template initialization, and
balanced extra LoadLibrary/FreeLibrary references while the EXE import edge
still owns the DLL. DllMain also validates thread reserved pointers and a
nonzero reserved pointer at static PROCESS_DETACH during ExitProcess.

Public contracts derive from Microsoft's [DllMain](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain),
[DLL entry-point function](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-entry-point-function),
[LoadLibraryW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw),
[FreeLibrary](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-freelibrary),
and [PE Format, TLS directory/callbacks](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-section).
ABI sources are the retained [stdcall](../../../../../docs/specifications/windows/microsoft-docs/stdcall.md),
[x64](../../../../../docs/specifications/windows/microsoft-docs/x64-calling-convention.md),
and [ARM64](../../../../../docs/specifications/windows/microsoft-docs/arm64-windows-abi-conventions.md)
documents. DLL service source copies/provenance are retained separately under
`docs/specifications/windows/services/dll-lifecycle/` by the implementation
group. Callback-array order is specified by PE; TLS-versus-DllMain relative
order and exact sibling teardown order are not asserted. Dependency lifetime
checks are explicitly profile-policy tests, not inferred native guarantees.
No callback invokes LoadLibrary or FreeLibrary.

## Reproduction and validation

Run from the repository root:

```sh
bash tests/fixtures/user/windows/lifecycle/build.sh
cargo +stable test --locked --no-default-features --test user_windows lifecycle:: -- --test-threads=1
```

`build.sh` uses Clang, LLD and llvm-dlltool; no Windows headers, SDK, CRT or
third-party binary is linked. Override tools with CLANG_BIN, LLD_LINK_BIN and
LLVM_DLLTOOL_BIN. Exact target triples are i686-pc-windows-msvc,
x86_64-pc-windows-msvc and aarch64-pc-windows-msvc. Common flags are `-Oz
-ffreestanding -fno-builtin -fno-stack-protector -fno-ident -fno-vectorize
-fno-slp-vectorize -fno-asynchronous-unwind-tables -fno-unwind-tables` and
`-ffile-prefix-map=<fixture-directory>=.`. ARM64 adds `-mgeneral-regs-only
-ffixed-x18`. Linking uses `/nodefaultlib /timestamp:0 /dynamicbase /nxcompat`,
explicit DLL entry points or `/noentry`, and explicit `_tls_used` retention.
The script contains each exact link/import-library command, base address and
architecture-specific export alias. Temporary outputs use a unique directory
and exact cleanup paths.

The retained toolchain is Clang/LLD 23.0.0git, LLVM revision
`b51054818b78dc395cd4d33f17cfb6e98a36a76d`. llvm-dlltool has no version flag;
its installed executable SHA-256 is recorded instead of inventing a version.
`manifest.toml` records all 18 source/script/DEF hashes and the SHA-256/size of
all 30 PE inputs. Current inputs total 98,304 bytes. Two consecutive builds
on this toolchain reproduced the manifest and all 30 inputs byte for byte.

The registered integration module has nine watchdog-backed execution tests
(two slice sizes, 1 and 4,096 guest instructions, per architecture/program),
one complete hash/PE/TLS/relocation/import/export metadata test, and one
all-architecture embedding test of initial TLS layout. Every CLI invocation
has a 30 s external watchdog and RAX_NO_JIT=1; it executes a unique copied
bundle under a C: drive mapping. The watchdog reports timeout rather than
allowing loader/wait hangs to block the test runner. No native/JIT admission
expansion is implied.

Baseline evidence at HEAD b6877559 used the parent's previously built CLI
SHA-256 `19c1d54fa8b35d2e5acd1b737a20d7881a8561f8ebfcb7025595c1c6be8bcdc3`:
all three architectures at slice 4,096 returned 125 with the explicit
`LoadLibraryW: dynamic native DLL initialization` unsupported diagnostic;
startup.exe returned 23 for its static reserved-pointer check. The parent
captured these runs in unique temporary bundles. Implementation execution
gates are coordinated by the parent; compilation/provenance evidence alone
does not establish the new lifecycle implementation passes.

The missing-forwarder regression's pre-fix lifecycle CLI SHA-256 was
`e03c00d2df908eadc825e683729f267bd4d3b01e5dcdce047716277484ea1236`.
The parent executed `forward-miss.exe` for all three architectures with
slice 4,096, seed 1, 64 MiB guest memory and RAX_NO_JIT=1 in unique temporary
drive bundles. All three exited with check code 88: the missing export had
returned, but leaf.dll remained live. This is observed red evidence for the
focused regression, distinct from the earlier unsupported-API baseline.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| F1 | Integer/pointer Windows x86, x64 and ARM64 ABIs match the retained public calling-convention documents; ARM64EC and aggregate signatures are outside this fixture. | Microsoft ABI sources; explicit fixed-width declarations and target triples. | Callback arguments, nine-argument logger/checksum and BOOL returns. | Ninth ARM64 argument, x64 stack tail, high pointer-width cookie, x86 ret 12/ret 36. | Disassemble retained PEs and compare argument placement/cleanup with ABI sources; runtime cookie/checksum mismatch disproves the compiled-call result. | retained |
| F2 | Final DLL/dependency/forwarder ownership follows this personality's graph-reachability policy. Native private forwarding ownership is unknown. | Implementation contract selected by the owning loader group, not a native oracle. | Dependency preservation on failed attach and unload after the final owning graph root disappears. | Already-held dependency versus fresh dependency; repeated loads; forward-only target acquisition. | Native Windows trace of reference roots, entry-point notifications and VirtualQuery after each FreeLibrary could disprove native equivalence without invalidating the selected profile. | retained |
| F3 | The fixture's TEB TLS-array offsets are the supplied personality profile: x86 0x2C, x64/ARM64 0x58. Modern private native-layout equivalence is unknown. | Retained PE x86 TLS explanation, existing checked personality layout, ARM64 X18 ABI. | Direct compiled TLS access and embedding layout assertions. | Old thread with no initial TLS array; replacement arrays after dynamic loads; relocated index VAs. | Independent native SDK/symbol/disassembly or executable comparison demonstrating a different TLS-array offset would falsify native equivalence. | retained |
| F4 | Tests operate on unique ASCII-named bundles and serialize mutable loader operations through one guest execution thread. | Current scheduler contract; synchronous event handshakes; isolated C: drive mapping. | Observer event log, same-process failed-file replacement and deterministic counts. | Slice 1 versus 4,096; old/new worker thread notification paths; complete two-build hash comparison. | Concurrent guest/host loader or mapping mutation, unexpected case/path alias, log overflow or a watchdog timeout falsifies applicability of this controlled fixture. | retained |
| F5 | Failed process attach delivers PROCESS_DETACH to both TLS callbacks as well as the failed DllMain. The TLS part is profile policy; native failure-path equivalence is unknown. | DllMain documentation explicitly requires its immediate detach; PE documents termination callbacks but not this exact rollback path. | Three failed-DLL detach records in each FALSE-attach attempt. | Repeated failure with a held dependency and failure with a fresh dependency. | Native Windows callback trace of a FALSE-attach DLL with two TLS callbacks would confirm or falsify failure-specific TLS notification equivalence. | retained |
| F6 | A missing forwarded export rolls back a newly mapped target without executing attach callbacks; native failure-path equivalence is unknown. | Explicit personality transaction policy, not a native oracle. | Focused NULL/error-127, notification, module, TLS-pointer and later-unload checks. | Two failed lookups followed by a fresh successful target load while the forward module remains loaded. | A residual live target, TLS pointer, initialization event, or retained dependency edge falsifies implementation conformance; a native callback/mapping trace could falsify native equivalence separately. | retained |

## Bounded limitations

- High, nonblocking for these inputs: loader-lock reentrancy through prohibited
  LoadLibrary-from-DllMain, callback exceptions, allocation-fault injection and
  cyclic initialization order require separate targeted tests. This fixture
  does not assert outcomes for those paths.
- Medium, nonblocking: native Windows notification ordering and dependency
  retention measurements remain unknown; public-contract tests and labeled
  personality-policy tests are not a differential oracle.
- Low, nonblocking: the observer's fixed capacity is 128 records. Overflow
  produces an explicit failed check; no dynamic observer allocation occurs.

Recording is O(1) time and space per event with a fixed 128-record store;
individual notification scans are O(E), E <= 128, with O(1) extra space.
Replacement copies O(B) bytes using a 128-byte guest buffer and O(1) extra
space, where B is fail-ok.dll size. The metadata test is linear in source and
artifact byte counts except its bounded relocation-membership scans, whose
cost is O(6R) per TLS image for R relocation entries. No unbounded host sleep
or guest polling loop is used; guest event waits are bounded externally by the
30 s watchdog.
