# Freestanding vectored-continue-handler fixture

`build.sh` produces one custom-entry Windows PE per guest ABI: PE32 x86,
PE32+ x64, and PE32+ ARM64. The C source is compiled without a Windows SDK or
C runtime. Only `KERNEL32.dll` is imported; x86 import-library names use
`stdcall` decorations, while x64/ARM64 names do not. The three executables
exercise the actual public `AddVectoredContinueHandler` and
`RemoveVectoredContinueHandler` imports alongside a vectored exception handler
and a continuable `RaiseException` call.

The guest checks first/last VCH ordering, handler return values, removal,
repeated removal, and separation of VCH and VEH registration handles. A
callback validates the exception code, flags, record count, non-null
exception-context pointer, and a common exception-pointers address across
handlers for one raise. Each failed check exits with a distinct nonzero
code; successful execution exits with 0.

The [integration runner](../../../../suites/user/windows/vch.rs) is registered
in the existing `user_windows` Cargo target through
`tests/suites/user/windows/main.rs`. It runs each binary at scheduler slices
of 1 and 4,096 guest instructions, seed 1, a 64 MiB guest arena, and
`RAX_NO_JIT=1`, with a 30 s external watchdog. A separate test checks the
generator/source hashes, tool identities, artifact hashes and sizes, PE
architecture and timestamp, and the six named KERNEL32 imports.

## Rebuild and provenance

From the repository root:

```sh
bash tests/fixtures/user/windows/vch/build.sh
```

This standalone generator writes only its own `bin/{x86,x64,arm64}/vch.exe`
files and `manifest.toml`; it does not regenerate smoke or other fixture
groups. `manifest.toml` records the SHA-256 of the build script, C source,
both `.def` files, three binaries, and installed compiler/linker/dlltool
binaries, plus executable byte counts. The zero COFF timestamp and source
prefix remapping support reproducible output with the recorded toolchain.

Primary public API contracts are Microsoft's
[AddVectoredContinueHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredcontinuehandler),
[RemoveVectoredContinueHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-removevectoredcontinuehandler),
and [vectored-handler callback](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nc-winnt-pvectored_exception_handler)
documents. The repeated-raise sequence through a continuing VEH into the VCH
list, and cross-family handle rejection, are explicit RAX-profile checks.
Native Windows execution of these binaries is **unknown**; the fixture is not
a recorded differential oracle.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| V1 | Returning `EXCEPTION_CONTINUE_EXECUTION` from a VEH for a continuable `RaiseException` reaches the VCH list before resuming the call. | Current RAX dispatch path; the cited public API pages do not specify this precise sequence. | Three expected callback sequences. | Raise three times with two, one, then zero VCH registrations. | Execute these PEs on native Windows and compare the callback sequence. | retained; native sequence unknown |
| V2 | A VEH handle passed to VCH removal, or a VCH handle passed to VEH removal, returns failure and leaves the registration intact. | Each public remove API names its corresponding add API; exact cross-family behavior is not stated. | Cross-family rejection checks. | Both directions before any valid removal. | Native Windows run returns success or changes the subsequent callback set. | retained; native cross-family result unknown |

## Bounded scope

- Medium: Native Windows differential callback ordering and cross-family
  rejection have not been recorded; this does not prevent RAX-profile coverage.
- Low: Noncontinuable exceptions, frame-handler continuations, and callback
  registration during dispatch are outside this one-program API probe.
