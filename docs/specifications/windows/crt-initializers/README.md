# CRT constructor and termination dependency evidence

This archive supports constructor-table traversal, not complete compiler CRT
startup or CRT termination. Its implementation baseline is
`b7498e58030bc0317cfa96845b509c9335c8fb30`. The baseline tracked tree/index were
clean. This task owns only this directory; no implementation, fixture, Cargo or
Git mutation is attributed to the archive task.

## Reproduction and provenance

[sources.json](sources.json) records 38 retained inputs, 206,910 bytes in total,
with local SHA-256, input hash or pinned upstream URL, source revision,
extraction/observation command, and license classification. There are twelve
Microsoft Markdown documents and two owning Microsoft licenses; eleven MinGW-w64
14 inputs; nine installed Zig-bundled MinGW inputs; and four derived import
archive observations. Byte-exact acquisition preserves the upstream licenses'
absent terminal LF. Selected header/DEF line subsequences preserve the original
bytes and order. Neither observations nor excerpts are mislabeled as raw full
sources.

```sh
ruby docs/specifications/windows/crt-initializers/acquire.rb
```

The script downloads MicrosoftDocs/cpp-docs commit
`f2355df9f7136d8a2097193fc507882a7caeb5f5`. It downloads MinGW-w64 tag `v14.0.0`
at resolved commit `9b3dd0125792fe94d16cacdc596dbd42fca1b369`, rather than a mutable
branch. The annotated tag object is
`e25dbe3428ce40d7321606a5642623a5a6e3da73`. This is the upstream release source;
the exact source commit used by the installed Homebrew `14.0.0_3` build remains
unknown. Zig `0.16.0_1` installed source is captured separately: it is not
substituted with the newer MinGW release or attributed to a known producer
commit. These copies differ, notably in EXE startup stream preparation.

The four symbol observations use installed LLVM `llvm-nm` 23.0.0git, SHA-256
`20e1aa425fda511df6d594ba6ff5298871644a6a74dea8d6da38ea0b3ad2c94f`.
The manifest contains the exact x86/x64 archive paths and SHA-256. An `I
__imp_*` archive member indicates an import symbol; `T` implementation plus
`D __imp_*` in an extra/common compatibility member is a local shim, not proof
that the named function is exported by the native DLL. An import symbol can
also be an alias: the DLL's imported name must follow its DEF/import member,
not blindly follow `nm` spelling.

No native Windows executable oracle ran. No SDK/CRT binary was downloaded. The
primary public document and independently authored MinGW sources are distinct
evidence classes, not two measurements of the same Microsoft implementation.

Observed archive checks on 2026-09-27: all 38 retained SHA-256/byte-size checks,
all 15 original installed-input hashes, and all 23 fresh pinned upstream byte
comparisons passed. Repeating the final acquisition preserved all 38 snapshot
byte hashes and the manifest hash. The unmarked `cinitexe.c` uses the owning
ZPL-2.1 fallback license. `ruby -c acquire.rb` passed. All local link targets in this
README exist. No Cargo command or guest/runtime verification was run by this
archive task; runtime acceptance belongs to the implementation/fixture owners.

Raw retained Markdown has unmodified upstream-relative links. Those links refer
to the upstream documentation tree and are not a promise that every linked
page is also retained here. The manifest supplies canonical URLs for each
retained Microsoft document.

## Constructor contract and admitted binding evidence

The pinned [Microsoft contract](microsoft/initterm-initterm-e.md) specifies
`__cdecl`, void-returning versus int-returning callback tables, NULL-entry
skipping, and zero/nonzero error results. Its combined `api_location` metadata
does not distinguish each function's DLL/version/architecture availability.
The prose does **not** explicitly specify end exclusion, immediate first-error
termination, rereading of mutated future entries, malformed/reversed ranges,
fault retry, partial completion, or the exception/unwind behavior of a failing
callback. Exact native behavior for those cases is unknown.

The independent [MinGW `_initterm_e` implementation](mingw14/initterm_e.c)
uses an ascending `[first,last)` pointer loop, rereads an entry when reached,
skips NULL, and returns the first exact nonzero `int` immediately. This is
source evidence for the selected traversal profile, not Microsoft native
equivalence. The [Microsoft CRT initialization description](microsoft/crt-initialization.md)
and [MinGW section sentinels](mingw14/cinitexe.c) explain the `.CRT$XIA/XIZ` and
`.CRT$XCA/XCZ` boundary inputs; they do not by themselves resolve hostile-input
or mutation semantics.

| Binding | `_initterm` | `_initterm_e` | Evidence and limit |
|---|---|---|---|
| MSVCRT x86/x64 | Genuine IAT | Local compatibility shim | `symbols/msvcrt-os-{x86,x64}.txt`; no universal native export-absence claim |
| MSVCRT ARM64 | Common DEF entry | ARM-conditional DEF entry | `mingw14/msvcrt.def.in` plus `func.def.in`; no installed ARM64 import archive or native export-table observation |
| UCRT x86/x64 | Genuine IAT | Genuine IAT | `symbols/ucrtbase-{x86,x64}.txt` |
| UCRT ARM64 | Common DEF entry | Common DEF entry | Installed `zig/ucrtbase-startup-def-excerpt.def.in`; native version-specific table unknown |
| UCRT runtime API set, all three guests | Common DEF entry | Common DEF entry | `zig/api-ms-win-crt-runtime.def.in`; routing is a separate loader responsibility |

In particular, MinGW14 `msvcrt.def.in` includes
`F_ARM_ANY(_initterm_e)` and explicitly marks x86/x64 replacement by emulation.
`func.def.in` expands the ARM condition for `__aarch64__`. Conflating the
x86/x64 shim observation with all-architecture absence would lose supported
binding evidence. Conversely, common header declarations alone do not prove
named imports on each architecture.

Callback signatures from the retained public header excerpts are
`void (__cdecl *)(void)` and `int (__cdecl *)(void)`. Windows C `int` is 32 bits
on all three admitted ABIs. Table pointer width is 4 bytes for x86, 8 bytes for
x64/ARM64. For a valid span, `N = (last - first) / P`, where both the difference
and `P` are in bytes; `N` is dimensionless. An implementation with lazy reads
performs O(N) table reads and O(1) host auxiliary storage per invocation,
excluding callback work. D genuinely nested guest/HLE calls require O(D)
continuation state. Reversed or misaligned spans are not valid C array ranges;
any emulator response is an explicitly configured fault/profile policy.

## Current continuation coupling

The relevant source surfaces are
[`hle/mod.rs`](../../../../src/user/windows/hle/mod.rs),
[`hle/dispatch.rs`](../../../../src/user/windows/hle/dispatch.rs),
[`process/sched.rs`](../../../../src/user/windows/process/sched.rs),
[`process/lifecycle.rs`](../../../../src/user/windows/process/lifecycle.rs),
[`process/fls_exit.rs`](../../../../src/user/windows/process/fls_exit.rs), and
[`dll/crt.rs`](../../../../src/user/windows/dll/crt.rs).

`Cont` is a boxed `FnOnce(&mut Ctx,u64) -> ApiResult`. `Flow::Call` leaves a guest
callback and a continuation on the HLE frame; dispatch takes that continuation
exactly once at the callback-return trap. Thus a table walk can hold its
current cursor, endpoint and return policy in an independent closure without a
process-global iterator. Consecutive callbacks need not add host recursion:
each transition returns a `Flow`. The checked guest-call path prepares the
stack, uses cdecl-compatible zero-argument callbacks on x86, reserves x64
shadow space/alignment, and uses the ARM64 return trap. This describes the
source mechanism, not an independent full register/FP/unwind oracle.

At the baseline, a lazy pointer fault after a callback returned had already
taken its `FnOnce`. Resuming the original export entry could therefore reparse
clobbered arguments and repeat prior callbacks unless the exact logical walk
frontier was retained separately. A repaired guest SEH continuation must retry
the pending pointer read, not restart the whole initializer table. Faulting
callback execution itself remains guest CPU/SEH behavior. Dropped HLE frames
abandon their continuations on stack unwind/context transfer; a pure local
constructor cursor has no process-global busy state to leak. Persistent
onexit-drain ownership would require separate abandonment bookkeeping.

Normal `ExitProcess` stages DLL notifications and then caller FLS cleanup.
Forced process termination discards continuations and bypasses guest DLL/FLS
cleanup. These are OS-personality lifecycle mechanisms, not complete CRT
termination. FLS callbacks are not a substitute for C++ thread-local object
destructor registration. Guest `ExitProcess`, a custom-entry EXE return, and
CRT `exit` cannot be conflated into one global CRT callback trigger.

The direct decode/execute, ISA CPU state, memory/MMU, SMIR, optimizer, native
lowering/JIT, backend, machine/device, oracle and C ABI planes are not changed
by this archive task. A future implementation uses existing checked memory,
HLE callback and scheduler mechanisms; new native/JIT admission is not implied.
Executable tests, HLE state and DLL routing are implementation-owned planes.

## Termination/onexit audit: subsequent semantic groups

The [onexit infrastructure contract](microsoft/execute-onexit-table-initialize-onexit-table-register-onexit-function.md)
requires initialization before registration/execution, append registration,
execution/clear/return, and reinitialization before reuse after execution.
Success is zero; failure is negative, without an exact errno/status contract.
Its table members are explicitly opaque implementation details. The MinGW
header's three pointer fields establish that header's public storage size
(12 bytes x86, 24 bytes x64/ARM64), not a native encoding or pointer-identity
oracle. Native callback reregistration during a drain, recursive execute,
reinitialize-while-draining, preexisting-table reinitialization and concurrent
table ownership are unknown from this public contract.

[MinGW's compatibility onexit implementation](mingw14/onexit_table.c) snapshots
the old endpoints and resets the table before invoking reverse-order
callbacks. Registrations performed during a callback therefore enter a
different buffer and are not part of that outer snapshot. This is a concrete
comparison implementation, not authority for native UCRT reentrancy. Copying
this behavior without a declared profile would not establish exact native
behavior; clearing an already-populated table can also lose its allocation.

The [atexit](microsoft/atexit.md) and [_onexit](microsoft/onexit-onexit-m.md)
contracts establish no-argument LIFO normal-termination callbacks.
`atexit` returns zero on success/nonzero on failure; `_onexit` returns its
function pointer or NULL on storage failure. The pinned `_onexit` page
explicitly describes DLL-local cleanup after the DLL's PROCESS_DETACH entry.
One process-wide `Vec<u64>` is insufficient to model every runtime/module
ownership and unload path. At the baseline, `CrtState::atexit` is explicitly a
dormant compatibility field, not an implemented exit registry.

Installed `nm` observations show genuine `_crt_atexit` import symbols in both
runtimes, but MinGW14's DEF maps legacy `_crt_atexit == atexit`: the native
MSVCRT import name is `atexit`. Its EXE startup provides the C `atexit` wrapper
locally. UCRT's native name is `_crt_atexit`. `_onexit` and UCRT
`at_quick_exit` appear as local compatibility members in these archives;
that does not disprove native names in other versions. UCRT onexit infrastructure
is genuine IAT; legacy versions in these x86/x64 archives are local shims.

[exit/_Exit/_exit](microsoft/exit-exit-exit.md) distinguishes complete cleanup
from minimal cleanup. Complete `exit` includes current-thread object
destruction, LIFO registered routines, stream flush, and process termination.
[_cexit/_c_exit](microsoft/cexit-c-exit.md) returns instead of terminating;
`_cexit` includes stream flush/close. Calling either returning API cannot be
implemented by an exit Outcome. Minimal CRT cleanup does not, by itself,
specify that the OS must use forced termination rather than its normal process
notification path. Exact DLL/FLS interactions therefore need primary source
or native evidence before choosing that mapping.

[quick_exit](microsoft/quick-exit1.md) uses a distinct `at_quick_exit` LIFO
registry, then `_Exit(status)`, without ordinary atexit/onexit callbacks.
Repeated quick_exit, combining it with exit, or longjmp out of its registered
callback is explicitly undefined; such cases do not supply a required native
continuation oracle. No quick-exit binding is synthesized from a static shim.

[MinGW14 EXE startup](mingw14/crtexe.c) shows why constructor traversal alone
cannot establish ordinary main/wmain acceptance: startup calls setvbuf on
stderr, registers safe_flush (which calls fflush(NULL)), configures arguments,
environment, FP and handlers, executes the constructor tables, calls main,
then exit. The installed [Zig startup](zig/crtexe.c) differs and is retained
byte-exact rather than substituted. [MinGW DLL startup](mingw14/crtdll.c)
owns a separate onexit table and runs it at DLL detach. These sources are
dependency graphs, not evidence that missing stream/argv/termination services
may return fabricated success.

The retained installed [narrow UCRT startup wrapper](zig/ucrt__getmainargs.c)
and [wide wrapper](zig/ucrt__wgetmainargs.c) expose additional leaf dependencies:
environment initialization, argv configuration, argc/argv/environment pointer
accessors, and `_set_new_mode`. Their local compatibility symbols do not turn
`__getmainargs` into a genuine UCRT named import. The pinned
[argument parsing contract](microsoft/parsing-c-command-line-arguments.md)
separates the executable-name rule from later arguments and specifies quote/
backslash cases. [getmainargs](microsoft/getmainargs-wgetmainargs.md) also defines
wildcard expansion and NULL-terminated outputs. Neither an existing OS command
line string nor a constructor callback table implements that parser or output
publication.

[Environment documentation](microsoft/environ-wenviron.md) describes initial
narrow/wide creation and conversion dependencies. The installed
[stdlib excerpt](mingw14/stdlib-startup-excerpt.h) explicitly branches for
legacy ARM/ARM64 `_get_environ`/`_get_wenviron` functions rather than assuming
the same data export/accessor graph as x86/x64. This is retained header evidence,
not a native DLL measurement. The pinned
[internal CRT interface index](microsoft/internal-crt-globals-and-functions.md)
identifies argv/environment functions as version-variable implementation
details; it does not supply their complete failure, encoding, identity or
mutation contracts. These facts delimit subsequent startup work and do not
extend this constructor group's implementation claims.

For a subsequent onexit group, a live registry should consume an entry before
guest execution, hold no host mutable borrow/lock across a callback, retain
table/runtime/module identity through a checked generation/ownership token,
and retire that token on completion or abandoned HLE continuation. This is a
design proposal, not an implemented or native-measured policy. Registration
is amortized O(1), a K-entry drain is O(K) plus callback work and uses O(K)
registered storage; reentrant insertion/iteration limits require an explicit
convergence/resource policy, not a silent fabricated success.

Strategic subsequent tests must distinguish ordinary versus quick registries,
duplicate registrations, LIFO ordering, callback integer return disregard,
returning `_cexit`, invalid-table success/error contracts, table reinitialize
after execute, explicit concurrent/draining profiles, callback registration
during drain, nested execution, fault/exception/longjmp abandonment, blocking
callbacks, DLL unload ownership, dual runtime isolation, allocation failure,
and stream flush/close failures. Actual guest callbacks must run on x86/x64/
ARM64; host-ledger tests alone do not establish guest callback ABI correctness.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| R1 | Installed import archives and pinned DEFs determine this evidenced binding subset, not every native DLL release | I/T/D distinction, architecture macros and DEF aliases | Binding table and exclusion of x86/x64 legacy named `_initterm_e` | ARM64-only DEF entry; renamed `_crt_atexit` | Capture exports and exact imports on a pinned native Windows build | Confirmed input distinctions; native inventory retained unknown |
| R2 | MinGW `_initterm_e` loop behavior may define an explicit emulator traversal profile | Independent primary implementation; Microsoft prose lacks precise edge semantics | End exclusion, first exact failure and lazy future-entry reads | Callback changes an entry or makes a later page inaccessible | Native trace differs from the selected frontier/order | Retained source-derived profile; native equivalence unknown |
| R3 | Guest fault retry must preserve the logical constructor frontier independently of clobbered original argument storage | Existing FnOnce/HLE frame ownership and architectural exception continuation | No duplicated earlier callbacks or reparsed range after repair | Repair a late table fault after callback register/stack argument clobber | Actual repaired guest execution repeats a callback or uses changed original endpoints | Confirmed required emulator invariant; native fault details unknown |
| R4 | Opaque onexit-table reentrancy requires a declared later profile or stronger oracle | Public documentation defines ordinary lifecycle but not in-flight mutation | No current claim of exact recursive/register-during-drain semantics | Register/reinitialize/execute the same table from its callback | Pinned native/source behavior resolves one exact policy | Retained unknown; outside this constructor group |
| R5 | Constructor-only custom-entry probes do not prove complete ordinary compiler startup | Retained EXE/DLL startup dependency graph | Completion boundary and missing I/O/argv/exit claims | Unmodified compiler main/wmain returns normally | Genuine startup runs all dependencies with correct observations | Confirmed boundary |

## Bounded findings and quality gates

| Impact | Finding | Constructor-group blocker? |
|---|---|---|
| High | Treating all legacy `_initterm_e` names as absent contradicts the ARM DEF | Resolved evidence supplied to implementation/fixture owners |
| High | Replaying an initializer after a repaired late fault can duplicate callbacks | Must be covered by exact-frontier implementation and actual guest regression; archive does not claim the runtime test passed |
| High | Global atexit/DLL ownership, stream cleanup and thread-local destructors are not modeled by OS exit staging alone | Blocks complete CRT exit/startup claims, not constructor-only acceptance |
| Medium | MinGW and Zig startup versions differ; opaque table reentrancy/native private encoding are unknown | Explicit later-group provenance/oracle boundary |
| Low | Retained section-boundary sources can support compiler-generated constructor dependency probes | No separate compatibility claim |

QG1: no normative judgment required. QG2: R1–R5 include stress and falsification
probes. QG3: constructor contracts, future termination/onexit audit, source
coupling, inventory, edge tests and provenance are covered. QG4: byte widths,
dimensionless entry count and complexity are explicit. QG5: source/metadata
conflicts and unknown native cases are separated rather than resolved by
assertion. QG6: pinned publisher/author source and exact installed observations
are retained. QG7: high/medium/low adjacent dependencies are bounded; no missing
startup or exit service is represented as implemented by this archive.
