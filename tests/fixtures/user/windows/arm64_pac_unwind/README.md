# ARM64 signed-return unwind probe

This is one freestanding, custom-entry ARM64 Windows PE built by `build.sh`
with Clang 23, LLD 23 and `llvm-dlltool`. It imports only `ExitProcess` and
`RaiseException` from KERNEL32. It does not link a CRT, use a Windows SDK
library, or claim execution against native Windows. `manifest.toml` records
exact tool, source and PE SHA-256 digests and PE byte size. Rebuild with:

```sh
bash tests/fixtures/user/windows/arm64_pac_unwind/build.sh
llvm-readobj --unwind --coff-imports tests/fixtures/user/windows/arm64_pac_unwind/bin/arm64/pac.exe
```

The PE has two actual `.pdata` entries, not just annotated source. The outer
handler-bearing frame uses full `.xdata` with `E1 81 FC E4` unwind bytes;
LLVM 23 reports `pacibsp`/`autibsp` for `FC`. The inner frame uses packed
`CR=2`, frame size 16 bytes. The code calls `RaiseException` from the inner
frame; the outer guest handler verifies exception code `0xE1234567` and
continues. Handler, inner and outer each update a marker once with values 1,
2 and 4; `ExitProcess(0)` occurs only when the final marker is 7. The
integration runner checks both metadata forms, exact imports, artifact/source
hashes, immutable input bytes, and exit status at 1 and 4,096 instructions per
slice. Expected status comes from this independent assembly control flow, not
from the emulator result.

The primary [Microsoft ARM64 exception-handling specification](../../../../../docs/specifications/windows/microsoft-docs/arm64-exception-handling.md)
defines full unwind opcode `pac_sign_lr` as `0xFC` and packed `CR=2` as a
chained frame with `pacibsp`. RAX currently selects an ARMv8.2 guest CPU
without PAuth. Its PACIBSP/AUTIBSP hint encodings are no-ops, but each is still
one instruction when locating a partial prolog or epilog. This is a selected
guest-CPU profile, not authenticated-return equivalence on a PAuth-enabled
Windows machine. Native Windows execution is unknown.

## Reproduction evidence

Two consecutive builds produced identical `manifest.toml` SHA-256
`2ec81317a1b70966cd4e474ffa82c436ef80b13f428cb4e81b75bf0c2bb61448`
and `pac.exe` SHA-256
`6d560bf74c454fd9924fc037d08b71882a3ff6cb38c06494a58824c2936f1efb`
(3,072 bytes). With only the new 0xFC and CR=2 unwind admission branches
temporarily reversed, the integration execution failed at slice 1: the
unhandled guest exception exited with `0xE1234567` rather than 0. After
restoration, the focused integration module passed 2/2 tests, including both
slice budgets; the focused ARM64 unwind units passed 10/10. The control was
reversible and changed no fixture bytes.

## Assumption Register and bounded scope

| ID | Assumption | Basis | Dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|---|
| P1 | Windows `WinCpu::new(Arm64)` continues to select the non-PAuth ARMv8.2 CPU. | `A64UserCpu::new` and `ArmFeatures::armv8_2_base`; a unit directly inspects the resulting Windows CPU. | PAC unwind markers are counted hints, not authentication. | Enable PACA/PACG in the Windows CPU and rerun the profile assertion; feature state must then reach the unwinder or the feature must be rejected. | confirmed for current source |
| P2 | The LLVM-produced metadata is stable for the pinned toolchain. | Exact binary and tool hashes plus `llvm-readobj` observation. | Full and packed integration coverage. | Rebuild twice, compare hashes, inspect both `.pdata` entries. | confirmed for recorded toolchain |

High-impact boundary: actual PAuth signing/authentication and key state are
unimplemented; enabling PAuth without extending this unwind contract would
invalidate the selected profile. ARM64 SVE and custom-stack unwind records
remain deliberately rejected. The fixture adds no native Windows oracle and
no ARM64EC or raw Windows SVC service-table claim. Generation takes O(B) time
and O(B) output space for B PE bytes; the selected unwind operations take O(U)
time and O(U) decoded space for U unwind bytes.
