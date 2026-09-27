# Bounded UCRT process termination and explicit signals

Baseline `02f28dbb4b6cc51e394987b7784ca34de965e2f5`; retrieval 2026-09-27.
This archive records primary contracts, conflicting publisher statements, and
genuine named exports. It is not a native Windows execution oracle. The bounded
signal profile admits explicit SIGABRT (22, compatible alias 6) and SIGTERM (15).
Console signals SIGINT (2)/SIGBREAK (21), and per-thread exception signals
SIGILL (4)/SIGFPE (8)/SIGSEGV (11), with otherwise admitted signal actions remain
explicit unsupported frontiers before state changes. SDK action validation
precedes signal-number admission: SIG_SGE (3)/SIG_ACK (4) instead return SIG_ERR
and set errno=22, including for those signal numbers. Named-export availability does not claim complete signal APIs,
hardware-exception conversion, console delivery, or application/system isolation.

## Provenance and reproduction

`sources.json` contains 32 inputs: 16 retained public/derived files and 16
publisher source/header/license receipts. Five raw MicrosoftDocs Markdown files
are pinned to commit `f2355df9f7136d8a2097193fc507882a7caeb5f5`; owning
[CC-BY-4.0 prose](../crt-initializers/microsoft/LICENSE) and
[MIT sample-code](../crt-initializers/microsoft/LICENSE-CODE) licenses are reused
by exact hash. SDK raw source, headers, DLLs, and license bytes are not committed.
SDK receipt reuse includes exit.cpp, abort.cpp, terminate.cpp, initialization.cpp,
per_thread_data.cpp, corecrt_internal.h, startup/termination/process headers,
win_policies.cpp, package metadata, and license identity without duplicating raw
inputs. New receipts cover signal.cpp, signal.h, stdlib.h, and winnt.h.

The publisher input is the [Microsoft Windows SDK C++ NuGet package
10.0.26100.1](https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.cpp/10.0.26100.1/microsoft.windows.sdk.cpp.10.0.26100.1.nupkg),
with source revision 10.0.26100.0. The reused full-package receipt records
155,613,545 bytes and the publisher CDN SHA-512 digest. The range extractor
independently validates the complete ZIP central directory, local member name,
compression method, decoded size, and CRC32. NuGet signature verification was
not performed; publisher package identity is not a signature-authentication claim.
SDK source availability does not establish a redistribution permission. Native
equivalence to the selected SDK source build remains unknown.

```sh
ruby docs/specifications/windows/crt-exit/acquire.rb
ruby docs/specifications/windows/crt-exit/acquire.rb --verify
ruby docs/specifications/windows/crt-exit/acquire.rb --verify-network
```

Default acquisition preserves public documents and export observations, prints a
temporary SDK inspection directory, and writes metadata only for proprietary
inputs. Offline verification checks retained hashes/sizes and reused receipts;
network verification re-fetches public documents and SDK members, and repeats
the three export observations. The complete package digest is explicitly reused
from [crt-termination](../crt-termination/README.md), not falsely counted as a new
full-stream verification. Two acquisitions must reproduce all retained input
hashes and `sources.json` byte-for-byte; temporary paths are not persisted there.

## Genuine exports and widths

Each observed x86/x64/ARM64 publisher `ucrtbase.dll` exports all 14 selected
names: `exit`, `_exit`, `_Exit`, `quick_exit`, `_cexit`, `_c_exit`,
`_register_thread_local_exe_atexit_callback`, `abort`, `_set_abort_behavior`,
`terminate`, `set_terminate`, `_get_terminate`, `signal`, and `raise`.
See [x86](symbols/microsoft-ucrtbase-x86.txt),
[x64](symbols/microsoft-ucrtbase-x64.txt), and
[ARM64](symbols/microsoft-ucrtbase-arm64.txt). These are observed DLL export names,
not static-wrapper names or proof of native execution. This archive does not
extend its measured inventory to legacy MSVCRT or arbitrary VCRUNTIME versions.

SDK signal.h declares a cdecl handler pointer `void (*)(int)` and pointer-valued
signal return; raise returns a 32-bit int. Signal numbers, abort flags, and
reason codes are 32 bits; pointers are 4 bytes on x86 and 8 bytes on x64/ARM64.
SDK constants: SIG_DFL=0, SIG_IGN=1, SIG_GET=2, SIG_SGE=3, SIG_ACK=4, SIG_ERR=-1;
NSIG=23. The compatible SIGABRT alias shares the action but explicit raise(6)
passes 6 to the callback; abort itself raises 22.

## Source contracts and conflicts

| Subject | Publisher source/contract | Conflict or admission boundary |
|---|---|---|
| Signal ownership | SDK signal.cpp stores SIGINT/SIGBREAK/SIGABRT/SIGTERM actions in application-selected process globals; SIGILL/SIGFPE/SIGSEGV actions use per-thread exception tables. SIGABRT aliases share one action. | The selected profile is application-default; selector/private table identity and nonadmitted console/hardware delivery are not inferred. |
| Global signal registration | Returns the old disposition. SIG_GET queries without mutation; SIG_SGE/SIG_ACK take the error path. Invalid signals normally set errno=22 and return pointer-width -1; compatibility values 1/3/13/16/17 return -1 preserving errno. | [signal](microsoft/signal.md) describes invalid-parameter-handler invocation and omits SIGBREAK/compat alias from its valid-value table. SDK signal_failed does not dispatch that handler. The SDK error path is the named source profile; no general public-doc parity claim. |
| Explicit raise | Reads the chosen action atomically under the global signal lock, releases the lock before guest code, resets an ordinary custom action to SIG_DFL before invoking it, preserves SIG_IGN, and returns 0 after a returning callback. An invalid signal uses invalid-parameter dispatch, then errno=22/-1 if resumed. | Callback recursion, callback re-registration, explicit SIG_GET and ignored signals require distinct probes; nonreturn does not imply a fabricated successful return. |
| Default raise | This SDK calls _exit(3) for every supported SIG_DFL signal, including SIGTERM. | [raise](microsoft/raise.md) says default SIGTERM is ignored; [signal constants](microsoft/signal-constants.md) says it terminates with 3. Retain the conflict; the selected SDK profile uses 3, not a universal Windows guarantee. |
| FP handler reset | SDK explicit raise(SIGFPE) resets all FP actions and temporarily substitutes exception pointers/_fpecode, calling the handler with two int arguments. | signal.md says FP handlers are not reset for an FP exception. Explicit raise versus hardware-filter behavior is not interchangeable. This group admits neither FP signal path. |
| Abort | SDK abort checks the SIGABRT action and only calls raise when nondefault. A returning or ignored action does not cancel abort. Retail defaults to _CALL_REPORTFAULT; debug defaults to _WRITE_ABORT_MSG. | An old source comment says multithread abort does not raise; executable source and [abort](microsoft/abort.md) agree it checks/raises. No debug UI/reporting implementation is claimed by a retail profile. |
| Abort policy | Flags are unsigned 32-bit values: WRITE=1, REPORT=2; setter returns old flags and computes `(old & ~mask) | (flags & mask)`. Retail WRITE has no effect. ARM64 REPORT invokes FAST_FAIL_FATAL_APP_EXIT=7; x86/x64 check PF_FASTFAIL_AVAILABLE=23 before fast-fail/reportfault fallback. With reporting disabled, fallback is _exit(3). | [_set_abort_behavior](microsoft/set-abort-behavior.md) broadly describes a default message; SDK stdlib.h labels it debug-only. WER/debugger/UI side effects and pre-Windows-8 fallback equivalence remain unknown. |
| Fatal versus fallback | [fast-fail](../crt-foundation/allocation/fastfail.md) gives noncontinuable second-chance status 0xC0000409 and reason parameter 7, bypassing in-process handlers. SDK winnt.h separately defines reportfault STATUS_FATAL_APP_EXIT=0x40000015 and NONCONTINUABLE=1. | These statuses are not aliases. Reason observability, reportfault, and normal DLL-detach fallback must not be silently conflated. |
| Terminate | SDK stores a per-thread terminate handler; getter/setter substitute abort for a null handler. terminate catches any escaping structured exception from a nonnull handler, then falls back to abort if the handler returns or faults. | This is not C++ unwinding, and a swallowed handler fault must not unwind unrelated outer callers. Native private per-thread/FLS identity remains unknown. |
| Cleanup | Reused exit/initialization receipts distinguish returning cleanup, full/quick/no CRT cleanup, desktop normal process exit, and dynamic-DLL stdio detach. | Public unqualified no-flush/flush descriptions and source static/dynamic stdio behavior differ; see the parent archive. Broad exit-equivalence and ordinary compiler startup are not established here. |

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| E1 | The selected SDK source version supplies the source profile, not a universal native contract. | Exact package/member receipts and genuine three-ABI export observations. | Default SIGTERM, abort, signal errors and callback ordering. | Default/ignored/custom actions, recursive raise and returned/faulting handlers. | Run the same probes against an identified native UCRT build and compare statuses, callbacks and state. | retained; native equivalence unknown |
| E2 | Application-default state is the admitted isolation mode. | SDK dual-state globals and reused CRT global-state contract. | Process-wide SIGABRT/SIGTERM versus per-thread terminate state. | Two guest threads, runtime-local state and reentrant callback mutation. | A pinned native application/system-mode probe or source selector contradicts the chosen isolation. | retained; private selector identity unknown |
| E3 | Console/hardware signals with otherwise admitted actions remain unsupported rather than defaulting or succeeding; rejected actions 3/4 retain the earlier SDK errno/SIG_ERR path. | Explicit bounded feature selection and SDK action-before-number validation; complete console/filter infrastructure is outside this group. | Named signal/raise partial-profile admission. | Each of 2/21/4/8/11 with actions 0/1/2 and rejected actions 3/4. | An admitted call mutates signal state or returns success instead of the selected frontier, or rejected actions bypass their earlier error path. | retained; runtime verification belongs to owning tests |
| E4 | Publisher HTTPS/ZIP receipts identify inspected bytes without signature authentication. | Existing full-stream digest receipt; current CD/member CRC/hash replay. | Source/export provenance. | Changed package, member, observer or removed prior archive. | Hash/CRC/directory comparison or acquisition replay fails; an independent signature verifier supplies stronger evidence. | confirmed for inspected bytes; NuGet signature unknown |

High bounded risks: nonadmitted console/hardware signal conversion and synthetic
handler exception boundaries can invalidate broad signal/terminate claims; their
runtime correctness belongs to implementation owners. High: source/public-doc
conflicts require the explicit selected profile above. Medium: native WER/UI,
private state isolation, and exact SDK source-to-binary equivalence are unknown.
No neighboring APIs, ordinary startup completion, or native Windows execution
is inferred from export presence or acquisition success.

Acquisition work is O(B) time and O(M+D) host space for inspected bytes B,
maximum uncompressed member M and central directory D; export observer cost is
additional. No implementation, Cargo, fixture, Git, or runtime validation is
performed by this archive workflow.
