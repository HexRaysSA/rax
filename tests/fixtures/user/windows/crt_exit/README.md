# Dynamic retail UCRT termination and explicit software-signal witnesses

Baseline `02f28dbb4b6cc51e394987b7784ca34de965e2f5`. These compiler-produced
guest PEs are custom-entry machine-ABI probes, not ordinary compiler startup.
Six graph executables and six companion DLLs cover x86/x64/ARM64 and UCRTBASE /
runtime API-set bindings. Twenty-one modes per executable give 126 semantic cells;
both instruction-slice sizes 1 and 4096 require 252 executions. Native Windows
execution is unknown. x86 uses ILP32, x64 and ARM64 LLP64; WCHAR is 16 bits.

The literal expectations are specified by `MODES` in build.rb, independent of
the engine. `manifest.json` exposes `fixtures` and `cases` separately; no cases
are inferred from a run that merely exits successfully. Per-case observations
include exact full 32-bit status, shell low-eight-bit status, stdout trace,
pending.bin bytes, and whether a real compiler-produced companion DLL detached.
API-set CRT termination uses api-ms-win-crt-runtime-l1-1-0.dll; stream functions
use api-ms-win-crt-stdio-l1-1-0.dll. No fake fopen, UCRT atexit/_onexit import,
ordinary startup object, or __C_specific_handler implementation is substituted.

Each case creates pending.bin with CreateFileW, transfers its handle into
_open_osfhandle(O_BINARY|O_RDWR), wraps it with genuine _wfdopen, installs a
64-byte caller-owned buffer, and writes one B. GetFileSizeEx proves the byte is
still pending before termination. The companion exports configure(counter),
checks exactly one PROCESS_DETACH, increments the counter, and writes D through
WriteFile. It never overwrites the requested exit status. Forced exits have no
detach trace and no pending-byte flush. Raw ExitProcess is deliberately tested
without invoking a newly admitted CRT termination export, exposing the old CLI's
real pending-flush mismatch rather than merely an unresolved-name failure.

| Modes | Independent witness |
|---|---|
| 0–3 | Full ordinary/TLS/live-registration, quick-only/live-registration, and two minimal spellings; distinct status codes. |
| 4–5 | Raw normal OS exit versus forced termination, observed DLL notification and pending-byte boundary. |
| 6–7 | Returning full cleanup twice retains executable TLS registration but drains ordinary functions once; returning minimal cleanup runs neither. No DLL notification or stream flush occurs before return. |
| 8–9 | Duplicate executable TLS registration invokes actual custom terminate handler or default retail fast-fail, never an idempotent fabricated success. |
| 10–13 | Returned/faulting terminate handler and returned/ignored SIGABRT behavior; callback can change reporting policy before abort reads it. |
| 14–15 | Signal alias6/22, query/reset-before-call, callback re-registration, ignored action, SIGTERM, invalid signal compatibility values, genuine invalid-parameter callback; SDK default SIGTERM source profile3. |
| 16–19 | Escaped CPP code goes through synthetic terminate scope, non-CPP searches actual outer guest handler, actual inner guest handlers precede synthetic scopes. |
| 20 | A real inner guest cleanup handler emits U only on the second EXCEPTION_UNWINDING pass before the selected synthetic terminate handler; the outer scope is not unwound. |

T=executable TLS callback; B/C/A=ordinary callbacks (B registers C live);
R/S/Q=quick callbacks (R registers S live); D=companion DLL PROCESS_DETACH;
H=terminate handler; S=SIGABRT policy-changing handler in mode12;
I=invalid callback in mode14 or actual inner SEH handler in modes18/19;
O=outer guest SEH handler; X=raising exit callback; V=verified returned cleanup;
U=inner second-pass unwind cleanup; F=forbidden return after a fault. All failure paths use forced nonzero exits, so
normal DLL detach cannot mask a failed assertion with a new status.

The assembly declares actual FS:[0] registration records on x86 and LLVM
exception-handler unwind metadata on x64/ARM64, with direct four-argument guest
handlers, plus a distinct exception/unwind scope in mode20. Compiler-produced C unwind metadata permits table walking through
nonleaf callbacks. No language-handler import or private scope-table layout is
assumed. The inner handler returns ExceptionContinueExecution for a continuable
RaiseException; the outer handler terminates with25 rather than pretending to
unwind or resume. These are synthetic HLE crossing/ownership acceptance probes,
not a full C++/C language-personality implementation or native unwind oracle.

## Reproduction and provenance

```sh
ruby tests/fixtures/user/windows/crt_exit/build.rb
ruby tests/fixtures/user/windows/crt_exit/baseline.rb /tmp/rax-crt-exit-baseline.zmJmwp/rax-user
```

The build records tool versions/executable hashes, exact source hashes, producer
flags, PE hashes/sizes, and independent llvm-readobj header/IAT/unwind output.
Two builds must reproduce the complete manifest, all twelve PEs and all twelve
observations byte-for-byte. Every baseline execution uses a separate temporary
directory containing only exact copied graph.exe/companion.dll bytes, verifies
both inputs unchanged after execution, and removes its temporary directory.
The 30 s watchdog records expiration separately; it never substitutes success.
The preserved CLI hash is mandatory. Reference contracts and version/source
conflicts are retained in [crt-exit](../../../../../docs/specifications/windows/crt-exit/README.md).
Public prose/license reuse, proprietary SDK metadata-only retention, and NuGet
signature-verification absence remain explicit there.
The observed baseline consists of 228 exact unimplemented-export failures
(84 executable-TLS, 96 set_terminate, 48 signal), twelve actual normal OS exits
with D but no pending B (the flush defect), and twelve correct forced exits with
neither D nor B. No watchdog expired. Forced-exit correctness is an unchanged
negative-control result, not mislabeled as a pre-feature rejection.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| F1 | SDK10.0.26100.0 dynamic retail desktop source defines this profile, not every native UCRT. | Retained publisher source receipts and three-ABI genuine names. | Cleanup/TLS/abort/signal status and order literals. | Full/quick/minimal, returning cleanup, handler mutation/fault. | Execute the same corpus against a version-identified native Windows UCRT and compare. | retained; native equivalence unknown |
| F2 | The modern fast-fail profile uses status0xC0000409; reason7 is not independently observable here. | Primary __fastfail contract and SDK abort path. | Mode9 terminal status/no callback/detach. | Duplicate TLS registration without handler. | Native profile reports another terminal status or execution reaches a callback. | retained |
| F3 | Each binding reaches one UCRT runtime identity, not a new runtime per API-set alias. | Genuine API-set routing and selected engine profile. | Shared stream/termination state across separate runtime/stdio imports. | Buffered file setup through stdio API-set followed by runtime termination. | Pending B is lost or state differs solely because API-set host identity split. | retained; native routing execution unknown |
| F4 | Real guest search handlers precede a crossed synthetic HLE scope and unrelated outer handlers follow it. | Explicit feature acceptance plus existing guest SEH ABI. | Modes16–19. | Inner handler, escaped CPP, unrelated non-CPP and nested terminate fault. | Trace includes O/H/F at a forbidden frontier or misses a required I/H. | retained; runtime verification belongs to root gates |

High bounded limitations: native console delivery, hardware signal conversion,
full C++ unwinding, ordinary compiler startup and static-CRT stdio cleanup are
outside these probes. Medium: WER/debugger/UI behavior and exact native private
state/FLS identity are unknown. No opaque SDK implementation bytes are included.
Fixed corpus generation is O(B) time/space in generated bytes B; execution cost
is the sum of guest instruction counts with bounded 30 s per-run observation.
