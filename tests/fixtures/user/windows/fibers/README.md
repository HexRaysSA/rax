# Freestanding Windows fibers and FLS fixtures

Eight actual PE executables for each of x86, x64 and ARM64, built without a CRT,
Windows SDK, or auxiliary DLL. The only imported DLL is `KERNEL32.dll`.
Native Windows execution is **unknown**; expected results derive from retained
Microsoft API/ABI documents, with the explicit profile assumptions below.

| Program | Observable checks |
| --- | --- |
| `core.exe` | Conversion/reconversion, public GetCurrentFiber/GetFiberData macros, FLS value persistence, independent slots/fibers, thread-shared ordinary TLS, unscheduled creation, suspended-fiber deletion and stack release, FlsFree callbacks across caller/suspended fibers and event-held threads, no duplicate callbacks after free. |
| `migrate.exe` | One fiber migrates parent→worker→parent under event synchronization. FLS, fiber data, local address/value and continuation persist. TID, TEB and ordinary TLS follow the executing thread. Worker exit must not destroy the inactive parent-created fiber. |
| `state.exe` | Nonvolatile GPRs, unchanged SP and live local canary. x64 XMM6–XMM15 (128 bits each), ARM64 V8–V15 low 64 bits. x86 MXCSR/x87 control with `FIBER_FLAG_FLOAT_SWITCH` set and clear; x64 nonvolatile MXCSR/x87 controls; ARM64 FPCR FZ/RMode. Original FP controls restored. |
| `stack.exe` | CreateFiberEx with 4096-byte initial commitment and 262144-byte reservation; 32 descending 4096-byte page probes without __chkstk, reserve→commit transition, distinct saved tags, FLS callback on a page-boundary-adjacent stack with a 192-byte local buffer, switch/resume, balanced SP restoration and inactive-fiber deletion. No private guard-growth quantum assertion. |
| `thread-exit.exe` | Guest FLS callback for thread-procedure return, ExitThread, fiber-procedure return, and DeleteFiber(current). Exact value pointer/cookie is checked; execution must not resume after terminating paths. |
| `thread-forced.exe` | TerminateThread of a parked fiber causes no FLS callback, no user-code resumption, and no delayed callback at subsequent FlsFree. |
| `process-exit.exe` | ExitProcess invokes the sole calling-thread FLS callback; callback writes a second record to a guest file before teardown closes its handle. |
| `process-forced.exe` | TerminateProcess(current) invokes no FLS callback or subsequent user code; only the initial record remains. |

The runner is [fibers.rs](../../../../suites/user/windows/fibers.rs), registered
through `tests/suites/user/windows/main.rs` in Cargo's declared `user_windows`
target (`autotests = false`). There are 24 execution tests, each using slices of
1 and 4096 guest instructions, seed 1, a 64 MiB arena, interpreter isolation via
`RAX_NO_JIT=1`, and a 30 s external watchdog. One additional test verifies every
source/artifact hash, byte size, PE architecture/timestamp, import DLL, actual
fiber/FLS import coverage, and public `State` export on process-exit inputs.
The temporary guest exit log contains five little-endian DWORDs per record,
`{magic, callbacks, seen, entered, returned}`: 20 bytes initially; 40 bytes after
one normal process-exit callback. Input executables are checked unchanged.

## Rebuild and tooling provenance

From the repository root:

```sh
bash tests/fixtures/user/windows/fibers/build.sh
```

`build.sh` is the generator. It records exact source/artifact SHA-256 values,
artifact sizes and compiler/linker identities in `manifest.toml`. Tool binaries
are also hashed: Clang/LLD 23.0.0git, LLVM revision
`b51054818b78dc395cd4d33f17cfb6e98a36a76d`; `llvm-dlltool` has no version option,
so its executable hash is the exact identity. Used installed tools are
`/Users/int/local/bin/{clang,lld-link,llvm-dlltool}`. The manifest is authoritative
for exact artifact sizes.

Compiler triples are `i686-pc-windows-msvc`, `x86_64-pc-windows-msvc`, and
`aarch64-pc-windows-msvc`. C flags are `-Oz -ffreestanding -fno-builtin
-fno-stack-protector -fno-ident -fno-vectorize -fno-slp-vectorize
-fno-asynchronous-unwind-tables -fno-unwind-tables -ffile-prefix-map=<fixture>=.`;
ARM64 C additionally uses `-mgeneral-regs-only -ffixed-x18`. Assembly is compiled
separately for explicit FP/vector probes. `llvm-dlltool -k` uses i386,
i386:x86-64, or arm64 and architecture-appropriate decorated DEF names.
Linker flags include `/nodefaultlib /timestamp:0 /dynamicbase /nxcompat
/entry:entry /subsystem:console /stack:1048576,4096 /heap:1048576,4096`.
The x86 assembly object declares `@feat.00=1`: it has no handwritten exception
handlers and is SafeSEH-compatible, not an exception-handling test.

Final two-build determinism and runtime status are recorded below. Compilation
is not evidence of guest execution.

## Independent contract and bounded comparisons

Primary source copies and metadata are in
[the fiber/FLS reference set](../../../../../docs/specifications/windows/services/fibers/README.md).
The Microsoft Fibers concept explicitly permits synchronized switching to a
fiber created by another thread and states that ordinary TLS belongs to the
thread running that fiber. FlsFree documents callbacks for all non-NULL values;
PFLS_CALLBACK_FUNCTION identifies fiber deletion, thread exit and index free as
callback triggers. The API documents do not establish callback ordering or the
callback execution thread/fiber for cross-fiber FlsFree; fixtures compare value
sets and counts without those assertions.

The [public layout probes](../layout/README.md) and installed MinGW/Zig
`winnt.h` architecture-selected inline definitions supply NT_TIB.FiberData offsets: x86 `FS:[0x10]`, x64
`GS:[0x20]`, ARM64 `[X18+0x20]`; GetFiberData dereferences the first pointer cell
of the resulting fiber address. This is public-header evidence, not a claim to
the full native private fiber structure.

ABI expectations use retained
[x64](../../../../../docs/specifications/windows/microsoft-docs/x64-calling-convention.md),
[ARM64](../../../../../docs/specifications/windows/microsoft-docs/arm64-windows-abi-conventions.md),
and [stdcall](../../../../../docs/specifications/windows/microsoft-docs/stdcall.md)
contracts. The assembly helpers restore their original nonvolatile registers
before returning to C. x86 tests callee cleanup of SwitchToFiber's one 4-byte
argument. x64 reserves 32 bytes of call shadow space and 16-byte call alignment;
ARM64 preserves 16-byte SP alignment. FP helpers have an explicit private
agreement to change rounding controls across switches. Volatile MXCSR status
bits, ARM64 high vector halves and arbitrary volatile registers are not used as
nonvolatile preservation oracles. ARM64 has no x87 state: its shared C x87
helpers are inert, not coverage of an ARM x87 facility.

Self-switching, deletion of another thread's currently executing fiber, invalid
fiber handles, callback ordering/repopulation/reentrancy, maximum native FLS
slot count, and exact native error codes for unsupported input are not asserted.
No fiber function calls LoadLibrary or other prohibited loader-lock operations.
Callback/value traversals are bounded by eight fixture values. Guard-growth
probes use 32 pages × 4096 bytes = 131072 bytes, within the 262144-byte reserved
fiber stack; one store/check per page is O(P) time and O(1) auxiliary space for
P=32, with 131072 bytes of guest stack span. Callback local storage uses another
192 bytes near the lower touched boundary. A blocked guest cannot bypass the
external 30 s watchdog. ISA/JIT admission, native backends, SMIR, C ABI and
hardware/device behavior are unchanged by this fixture-only group.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| F1 | FLS values survive conversion from thread to fiber and back without implicit clearing/destruction. | Requested profile; FLS acts as TLS when no switching occurs. The conversion pages do not explicitly describe this transition. | `core.exe` persistence checks. | Convert, reconvert, then allocate/switch/delete other fibers. | Run the same PE on native Windows and observe value loss or callback at conversion. | retained; native transition oracle unknown |
| F2 | Forced thread/process shutdown discards FLS without running callbacks, including no delayed callback on a freed thread at FlsFree. | TerminateThread/TerminateProcess forbid additional target user-code execution; explicit profile cleanup extends that prohibition to discarded storage. | Forced-exit fixtures. | Park an active fiber with a non-NULL value, terminate, then free the index. | Native Windows callback log differs for the same target/API. | retained; forced cleanup detail not independently measured |
| F3 | Normal ExitProcess runs the calling thread's registered FLS callback while its guest file handle remains usable. | Public FLS callback thread-exit trigger and retained Microsoft FLS thread-exit troubleshooting evidence; profile exact shutdown ordering. | `process-exit.exe` two-record log. | Callback executes WriteFile during process teardown. | Native Windows produces no second record or rejects the write. | retained; exact native ExitProcess ordering unknown |

## Validation record

- The final scoped integration gate passed: 25 tests, 0 failed, 0 ignored,
  41 filtered out; 48 actual PE runs across all three ABIs and both slice sizes.
- All 24 PE artifacts compiled with the recorded tools. Two builds of the final
  sources produced byte-identical artifacts and manifest; manifest SHA-256:
  `ce7599500d1c25e795a5af88f48254740b3988bfa6b14eddf429f45d1b81b130`.
  All 35 source/artifact checksum checks passed. `bash -n build.sh`, exact-file
  Rust formatting, and `git diff --check` passed.
- Runtime integration and broad Cargo gates are root-coordinated. No native
  Windows differential run is claimed.
