# Custom-entry CRT constructor fixtures

This group contains 34 compiler-produced PE programs for x86, x64, and ARM64.
Clang emits `.CRT$XI*`/`.CRT$XC*` pointer contributions and LLD sorts them into
mutable, non-executable `.CRT` sections. A custom `entry` invokes a handwritten
`main` and the real named initializer imports. These are **not ordinary compiler
CRT startup**, MSVC startup-object, or native Windows differential tests. No SDK
header, CRT startup object, or runtime implementation blob is embedded.

| Family | MSVCRT | UCRTBASE | Runtime API set | Observable checks |
|---|---|---|---|---|
| `traverse.exe` | All 3 ABIs | All 3 ABIs | All 3 ABIs | Ordered NULL skipping, ignored void return, future-slot mutation, nested traversal/allocation/string calls, cdecl stack/GPR preservation |
| `errors.exe` | ARM64 only | All 3 ABIs | All 3 ABIs | First positive/negative failure returned exactly, no later callback, subsequent success, nested void/int traversal |
| `terminal.exe` | All 3 ABIs | All 3 ABIs | All 3 ABIs | Initializer `ExitProcess(42)` never resumes traversal or its caller |
| `repair.exe` | All 3 ABIs | All 3 ABIs | All 3 ABIs | Later-slot NOACCESS/GUARD faults repaired by VEH without replaying prior callbacks |

MSVCRT x86/x64 `_initterm_e` is excluded because the installed import libraries
provide a compatibility implementation rather than a genuine import. The pinned
MinGW v14 DEF explicitly admits `F_ARM_ANY(_initterm_e)`, so ARM64 is tested.
This distinction is not a universal native-export absence claim. Microsoft’s
combined `api_location` metadata does not establish every name on every listed
DLL/architecture. Retained raw documentation, import inventories, DEFs, source,
licenses and versions are in [the constructor archive](../../../../../docs/specifications/windows/crt-initializers/README.md).

`traverse.c` uses an eight-slot `.CRT$XC*` region: one NULL start sentinel,
five callbacks, one internal NULL, and a callable excluded-end tripwire. Its
first callback returns `0x76543210` through the integer return register, which a
void traversal must ignore. Its integer-to-void callback cast is a machine-ABI
probe, not evidence of strictly typed C language conformance. The mutation
callback replaces a future tripwire
before it is read. The nested callback uses the matching runtime's `malloc`,
`free`, and `strlen`, then invokes another imported traversal with NULL slots.
An assembly caller checks the actual full traversal and 32 empty traversals.
On x86, 16 saved bytes place function/begin/end at offsets 20/24/28 bytes; the
caller removes 8 argument bytes. On x64, entry RSP modulo 16 is 8; 64 saved
bytes plus 72 local bytes align the call and reserve 32 shadow bytes. ARM64 uses
a 128-byte, 16-byte-aligned frame and preserves x19–x30 without modifying x18.
The probe checks call-preserved GPRs and SP, not FP/vector state or assembly
exception unwinding.

`errors.c` uses six `.CRT$XI*` slots. It returns `0x13579bdf`, then −17, then
zero in three separate invocations. The later callback is a tripwire on both
error passes. A successful callback changes the future slot and invokes nested
void/int tables before returning. `terminal.c` has distinct subsequent-callback
and post-traversal exits 182 and 183, preventing shell exit 42 from being
mistaken for normal return.

`repair.c` places its first pointer in the last pointer-width slot of one
4,096-byte page, and its second pointer at the start of the next page. The first
callback executes once and invokes an assembly helper that overwrites all
volatile integer argument registers. The second page is first PAGE_NOACCESS,
then PAGE_READWRITE|PAGE_GUARD. The actual VEH checks the exception code,
first/second callback counters, and access-fault address before restoring access
with `VirtualProtect` and returning `EXCEPTION_CONTINUE_EXECUTION`. Each pass
requires one handler, one first callback, one second callback, and normal outer
return. The page interval is 8,192 bytes and is released explicitly. Resuming
this internal HLE slot frontier is a selected emulator fault-recovery profile;
native exact internal fault/restart behavior is unknown.

## Reproduction and evidence

```sh
bash tests/fixtures/user/windows/crt_init/build.sh
bash tests/fixtures/user/windows/crt_init/baseline.sh /absolute/path/to/preserved/rax-user
```

The generator writes only the owned `bin` directory and `manifest.toml`, uses
Clang/LLVM dlltool/LLD, zero timestamps, `/nodefaultlib`, and the exact triples
and flags recorded in `build.sh`. ARM64 uses `-mgeneral-regs-only -ffixed-x18`.
All three bindings use real named imports; the API-set matrix routes initializer
calls through `api-ms-win-crt-runtime-l1-1-0.dll` and nested work through heap or
string contracts. The registered runner verifies the complete 14-source input
set, all 34 artifact hashes/machine kinds, exact IAT sets, exported bounds,
table widths/NULLs/excluded non-NULL end, and mutable `.CRT` permissions. It also
checks every retained constructor/ABI source and license hash.

Two final builds produced identical manifest and all 34 PE hashes. Artifacts
total 126,976 bytes. Manifest SHA-256:
`e4a5279ddebdcfef2459a6d0cce3c55ddc097a886ca28c606dead39b49e5b171`.
The final [baseline receipt](baseline.json) records all 34 programs at slices
1 and 4,096 instructions: 68 observed failures, no timeout, seed 1,
67,108,864-byte arena, `RAX_NO_JIT=1`, 30 s external watchdog. Each execution
uses a unique temporary drive containing only one copied PE; its bytes are
checked after execution. The preserved old CLI is source revision
`b7498e58030bc0317cfa96845b509c9335c8fb30`, executable SHA-256
`8ab3fbeafd5f8cf379fcdf0f826ffd89eb573a3db00c97558df151c278253fc5`.
Every old run exits 125 with an exact unimplemented `_initterm` or `_initterm_e`
diagnostic. The CLI does not expose an NTSTATUS for that emulator failure, so
the receipt records it as unknown (`null`), not an invented loader status.
The root agent owns Cargo execution, main-module registration, final green
counts and CI evidence; this fixture author invoked no Cargo command.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| I1 | The x86 ILP32 and x64/ARM64 LLP64 data models use 32-bit and 64-bit pointers respectively; `int` is 32 bits in both models. | Retained Microsoft calling conventions and emitted PE machine kinds. | Callback declarations, pointer slots, signed returns, assembly offsets. | Negative −17, high positive return, page-boundary pointer slots. | Compile SDK prototype/sizeof probes or observe a conflicting call ABI on the admitted target. | confirmed for configured fixtures |
| I2 | End-exclusive traversal, first exact nonzero return, and lazy future-slot reads define the selected profile. | Pinned independent MinGW `_initterm_e` loop; Microsoft prose specifies NULL skipping and zero/nonzero outcomes but not all edges. | Non-NULL end tripwire, error cutoff, mutation expectations. | Callback replaces a future slot before traversal reaches it. | Run these PEs on an identified native CRT and record a different read/return trace. | retained source-derived profile; native equivalence unknown |
| I3 | The MSVCRT initializer subset is architecture-sensitive. | Genuine x86/x64 import inventories and pinned ARM DEF macro. | ARM64-only legacy error family and compile-time exclusions. | ARM64 direct legacy `_initterm_e` versus x86/x64 omitted name. | Capture exact exports/IAT resolution on a pinned native DLL/architecture set. | confirmed toolchain distinctions; native inventory unknown |
| I4 | A repaired internal table read resumes the pending slot without repeating completed callbacks. | Selected checked HLE continuation policy, not a native CRT fault oracle. | NOACCESS/GUARD recovery and volatile-register clobber probe. | Fault after one completed callback, then VEH repairs and returns to execution. | Native internal CRT trace or engine regression replays a prior callback or loses the current slot. | retained personality fault profile |

High-impact non-blocking gaps: argv/environment/data exports, ordinary MinGW or
MSVC startup, locale/new-mode/stdio, onexit/atexit/CRT exit, C++ exception runtime,
and native Windows replay remain outside this constructor group. No CPU decoder,
ISA execution, SMIR/JIT admission, backend/device, oracle API, or public C ABI is
modified by these fixtures. They exercise existing CPU/memory/SEH and HLE planes.
Each guest workload has fixed-size tables and bounded calls: time/space O(1) in
the checked-in inputs; generic traversal is O(n) time and O(d) continuation
space for n slots and nesting depth d. Fault passes and retries are finite.
