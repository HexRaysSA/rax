# DLL lifecycle analysis

Baseline inspected: `b6877559f7edbf306aaecea139854497f3d399f5`.
Analysis date: 2026-09-27. The initial source pass was read-only. A subsequent
authorization adds startup and normal thread/process notifications confined to
`src/user/windows/process/lifecycle.rs`; separate agents own loader state,
dynamic DLL APIs, continuation abandonment, scheduler integration, and fixtures.
No native Windows execution oracle is available in this pass.

## Acceptance criteria and change surface

The lifecycle group requires: completion of process attach before a successful
native LoadLibrary returns; attach-once and reference accounting; distinguished
FALSE/exception initialization failures; unload after detach; serialized DLL
notifications without holding a loader lock across ordinary user entry; static
TLS integration for current/existing/new threads; normal thread/process detach;
and explicit rejection of unsupported reentrant/path/flag branches. This
analysis alone does not establish implementation or runtime validation.

Affected planes: CPU state through existing guest callback ABI marshalling;
Memory/MMU through image/TLS allocation, publication, protection and release;
Windows loader, process scheduler, HLE continuation/exception frontiers;
tests/docs and retained API provenance. ISA decode/execute, SMIR
lift/IR/interpreter/optimizer/native lowerers, JIT admission, backend adapters,
machine/device, static oracle and C ABI are unaffected: this feature consumes
their existing user-mode execution and checked memory interfaces.

## Documented public contract

| Event | Required public behavior | Primary evidence |
|---|---|---|
| First dynamic DLL load | DLL entry point receives process attach on the caller; successful attach completes before the handle returns | [LoadLibraryW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw), [run-time linking](https://learn.microsoft.com/en-us/windows/win32/dlls/run-time-dynamic-linking) |
| Repeat load | Acquire another process-local module reference; do not repeat process attach | [run-time linking](https://learn.microsoft.com/en-us/windows/win32/dlls/run-time-dynamic-linking) |
| DLL attach arguments | Module base; reason 1; reserved non-NULL for startup/static load and NULL for dynamic load | [DllMain](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain) |
| Attach returns FALSE | Dynamic load returns NULL; the failing entry receives process detach before unload. Startup failure terminates process initialization | [DllMain](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain) |
| Attach throws | The failing DLL entry does not receive process detach | [DllMain](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain) |
| New thread | Attached DLL entries receive thread attach on that new thread before its routine; existing threads are not retroactively notified by dynamic loading | [DllMain](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain), [ExitThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitthread) |
| Normal thread exit | Attached DLL entries receive thread detach while the exiting thread can still execute its code | [ExitThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitthread) |
| Forced thread exit | TerminateThread does not deliver DLL thread detach | [DllMain](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain) |
| Final module release | Detach with reason 0, reserved NULL; unmap only after entry returns; no per-thread detach fan-out | [FreeLibrary](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-freelibrary), [DllMain](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain) |
| GetModuleHandle | Does not acquire a reference; passing that handle to FreeLibrary can nevertheless reduce the module's references | [GetModuleHandleW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlew) |
| Unload-and-exit | Decrement DLL reference then end caller; do not return through potentially unmapped caller code | [FreeLibraryAndExitThread](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-freelibraryandexitthread) |
| Suppress thread calls | DisableThreadLibraryCalls fails for active static TLS or invalid module; never silently suppress required static TLS notifications | [DisableThreadLibraryCalls](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-disablethreadlibrarycalls) |

The DLL entry point means the PE entry address, not an exported symbol named
DllMain. Compiler CRT entry wrappers remain guest code.

The retained [PE TLS specification](../../microsoft-docs/pe-format.md) specifies
null-terminated callback arrays, callback execution in array order, a VOID
return type, and Reserved=0. DllMain reserved arguments therefore cannot be
reused verbatim for TLS callbacks. Its TLS table excludes the original thread
from thread-reason notifications, whereas DllMain explicitly permits thread
detach for a thread that previously received process attach. These are distinct
contracts; exact first-thread TLS teardown traces need an oracle, not inference
from the DllMain text.

For ExitProcess, other threads stop without thread-detach notifications and
their objects become signaled before DLL process-detach entries run; the caller
remains available for those callbacks. The process/calling thread are ended
after callbacks, and the supplied exit code applies to the process and all
threads. Process-detach Reserved is non-NULL.
[ExitProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess)

## Ordering and reentrancy: specified versus unknown

Entry-point execution is process-wide serialized. New threads created during
DLL initialization do not begin execution until initialization completes.
Already running application threads are not specified to stop all ordinary
execution whenever another thread holds the loader lock.
[ExitThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitthread)

Microsoft documents LoadLibrary/FreeLibrary calls from DLL entrypoints as unsafe
and identifies dependency cycles and deadlocks; these texts do not specify a
universally successful nested-loader transaction. Consequently nested calls
need either explicitly restricted admission or tested version-specific
semantics. A reentrant host continuation by itself does not establish a valid
native-loader contract.
[DLL entry-point function](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-entry-point-function),
[DLL lifecycle restrictions](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices)

Unknown from the consulted normative/API sources:

- Exact TLS-versus-DLL-entry relative ordering for every attach/detach/failure
  case. RAX's TLS-before-entry attach order, entry-before-TLS detach order and
  reverse-ready-native detach order are personality profiles, not confirmed
  native traces. TLS callback arrays remain in documented array order.
- Total order within cyclic import components, or independent modules; precise
  reverse dependency cleanup after an attach failure.
- Exception interception/last-error details across all native builds and
  architectures, including TLS callback exceptions.
- Exact last-error values for callback reentrant loader rejection,
  reference-count exhaustion, or corrupted private LDR state.
- Full NtTerminateThread behavior and NtTerminateProcess NULL-handle behavior.
  The retained ZwTerminateProcess page establishes current-process non-return
  and the supplied final status, but does not specify NULL semantics or all
  user-mode callback/handle cases. RAX preserves its existing NULL/self-pseudo
  admission and rejects other NT handles; this is a restricted profile, not
  complete native-service equivalence.
- Native terminal-SEH DLL notification ordering. Public process termination
  documentation establishes fatal-exception exit status, not every callback
  stage. RAX treats unhandled exceptions and failed dispatch-stack writes as
  forced termination, so no DLL cleanup can replace the terminal status.
- Static TLS slot reuse after unload, treatment of suspended preexisting threads,
  and callback-array mutation during the notification sequence.

These unknowns do not license fabricated success or invented native statuses.

## Baseline source evidence and implementation dependencies

| Surface | Evidence at baseline | Consequence |
|---|---|---|
| Dynamic native admission | `dll/kernel.rs:330–341` maps through load_dll then rejects native initialization | Existing rejection is explicit; mapping side effects still require future transaction ownership |
| Dependency preparation | `loader/mod.rs:893–904` binds imports before appending initialization order | Existing dependency-before-parent preparation is reusable; callback state must be per module |
| Module state | `loader/mod.rs:136–143` has load_count, thread_calls and initialized only | Mapping/attaching/ready/detaching/dead/failed require distinct admission states |
| Startup callbacks | `process/lifecycle.rs:18–60` snapshots callbacks, TLS first; static DllMain Reserved=0 | Static reserved argument contradicts public contract; callback arrays need checked arithmetic and bounded termination |
| Startup completion | `process/lifecycle.rs:66–74` exits immediately on FALSE and marks all modules initialized only at the end | Partial initialization and failing-entry cleanup need explicit module transitions |
| Secondary startup | `process/lifecycle.rs:26–32` visits load order and skips whole module if thread_calls=false | Ready/live admission and static TLS suppression rules need separate handling |
| Loader serialization | `process/sched.rs:198–207` selects only the startup-frame owner, then main initializer | It does not model dynamic attach/detach; it also freezes already-running ordinary CPU threads during secondary startup |
| Continuation ownership | `hle/dispatch.rs:243–253` stores FnOnce; setup faults pop the frame; `63–66` prunes abandoned frames | Loader transaction/lock cleanup must survive callback failure, unwind, NtContinue, longjmp and termination |
| Existing TLS | `process/thread.rs:114–159` allocates only at thread creation | Dynamic static-TLS images require preparation/publication for current and existing threads before callbacks, plus rollback |
| Thread teardown | `process/thread.rs:377–412` signals/frees directly; `sched.rs:174–179` calls it directly | Normal detach must finish before destroying TLS/TEB/stack; forced termination stays distinct |
| Process teardown | `process/sched.rs:151–171` destroys all threads and drains handles | ExitProcess needs guest detach stage with the caller and process resources still available |
| Guest loader lists | `loader/ldr.rs:179–211` exposes checked link/unlink helpers | Unload/rollback must cover LDR publication as well as VM and host registry state |

Line ranges identify a baseline source interval, not a claim that concurrent
implementation keeps the same line numbers.

A callback-safe lock cannot live solely inside a success continuation: guest
exception transfer, frame pruning, thread termination, or process exit can
discard the continuation. Parent-owned LoaderGuard therefore needs a Drop or
equivalent abandonment mechanism with host-authoritative ownership; cleanup
cannot trust mutable guest LDR/TLS pointers. The callback thread is temporarily
removed from Proc::threads while HLE runs and must participate explicitly in
TLS preparation and rollback.

Do not hold initialization ownership while executing the user's normal start
routine. Finish notification guard, publish successful attachment, then issue
the final Flow::call into user code.

For normal thread exit, DLL callback targets and TLS blocks must remain mapped
until callbacks complete; thread object signaling follows completion. For
ExitProcess, other threads are terminated first without per-thread callbacks,
then process detach runs on the current thread, then final resource destruction.
Each synthetic exit dispatch requires a stage marker to avoid redispatching
detach when its final Outcome is processed. FLS callback delivery is outside this
group; existing absence remains explicit.

## Arithmetic, algorithms, and test criteria

Guest pointer width is 4 bytes on x86, 8 bytes on x64/ARM64. Callback slot `i`
is `callbacks + i × pointer_bytes`; multiplication/addition must be checked for
64-bit guests and respect the admitted x86 truncation policy. The TLS callback
scan is bounded at 4096 entries; a missing terminator is an explicit personality
image rejection, not a claim of the native scanner's bound.

For M admitted modules and C callback entries, preparing/stepping the
notification plan itself requires O(M+C) host time and O(M+C) cumulative plan
space; guest callback execution cost is additional. The current loader's
attach_succeeded uses Vec::contains and detach_completed uses Vec::retain on
the completion ledger, so a full M-module notification sequence has worst-case
O(M²+C) host bookkeeping time. An indexed membership/order ledger could reduce
this to O(M+C), but is not implemented in this lifecycle edit. Static TLS preparation over T existing
threads and B template bytes requires O(T×(M+B)) time; copied TLS arrays use
O(T×M×pointer_bytes) bytes, with separate template storage O(T×B). An
implementation may reject dynamic TLS explicitly instead of claiming this work.

Required strategic tests, all three guest ABIs where applicable:

- Static versus dynamic DllMain Reserved; TLS Reserved always zero; callback
  array order; DLL entry before user routine and no retained loader guard there.
- Ready attach exactly once on repeat LoadLibrary; references and dependency
  sharing survive balanced FreeLibrary and failed attach rollback.
- FALSE versus guest exception; failing-entry detach differences; previously
  ready modules/resources remain unchanged.
- New-thread attach, no retroactive thread attach, normal thread detach before
  object signal/TEB release, TerminateThread skips callbacks.
- ExitProcess peer signaling before detach; no peer thread-detach fan-out;
  caller TLS/TEB valid during callbacks.
- Attach/detach waiting, recursive calls, callbacks changing module sets,
  callback stack write faults, guard faults, and abandoned continuations.
- Unload invalidates lookup/unwind/callback reachability; protected guest LDR/TLS
  storage faults do not become host panics or silently ignored publication.
- Current/existing/new thread static TLS, suspended threads, empty templates,
  zero fill, alignment rejection, allocation exhaustion and rollback.

Native falsification fixture: log (module ID, current thread ID, reason,
Reserved==0, TLS variable value) from two TLS callbacks and PE DLL entry;
exercise startup, dynamic load/repeat load, new worker, original-thread
ExitThread, unload, attach FALSE and caught/unhandled exceptions; then compare
ordered traces per Windows version and guest ABI. Separate A→B, shared B,
cyclic A↔B, and DllMain→LoadLibrary graphs. Record exact OS build, compiler/linker,
image bytes and GetLastError. No such oracle ran here.

## Owned implementation and validation status

The authorized lifecycle module now sequences startup notifications through the
parent-owned loader lock/guard, uses per-module attach transitions, and releases
the notification guard before user entry. Static DLL entry Reserved is the
nonzero process-parameter address; TLS Reserved is always zero. Executable
initialized state is cleared at initial startup and published after its TLS
notifications, so a preceding startup failure does not detach unstarted EXE TLS.

FALSE startup attachment first detaches the failing DLL entry, then its TLS
callbacks, then prior successful modules in reverse completion order. Module
ready state is cleared after each completed process-detach sequence, preventing
normal process exit from repeating rollback notifications. A thrown callback is
not converted into FALSE; parent-owned fault/abandonment handling is required.
Before the first process-detach callback for a module, detaching admission is
marked while public lookups remain visible. Reentrant FreeLibrary(self) therefore
cannot start a duplicate detach plan. Normal thread detach does not mark that
process-wide retirement state.

Normal thread/process exit entrypoints return scheduler Outcomes only after
guest notifications complete and the guard is released. The scheduler owns
stage markers, peer termination, forced-termination bypass, and final object/
TLS/TEB/stack destruction. Normal notification plans use the loader's actual
successful completion order, not the image-mapping post-order: inner loads can
finish between outer module attaches. DLL thread-call suppression is honored;
the original thread's TLS thread-reason callbacks are excluded by the retained
PE table profile. FLS callbacks remain outside this group.

Five lifecycle unit tests explicitly step HLE continuations across x86, x64 and ARM64:
static/TLS Reserved and lock lifetime; FALSE rollback/no repeat; normal resource
lifetime, process Reserved and reentrant unload rejection; actual completion-order reversal; original-thread
TLS exclusion/thread-call suppression. They do not execute guest callback
bodies and are not a native ordering oracle. Executable validation of the
combined tree, including compiled PE fixtures and full feature gates, is
recorded in [the architecture task record](../../../../architecture/user-mode/windows-dll-lifecycle.md).

### Forced versus normal termination

`Flow::ExitThread`/`ExitProcess` and `Outcome::ThreadExit`/`ProcessExit` retain
normal DLL notification stages. Separate `Flow::TerminateThread`/
`TerminateProcess` and `Outcome::ThreadTerminate`/`ProcessTerminate` carry
forced termination through the HLE and scheduler frontiers. NtTerminate*
restricted self paths, Win32 TerminateThread/TerminateProcess, fail-fast,
terminal SEH and the existing configured fatal heap-corruption policy use the
forced variants. FreeLibraryAndExitThread remains a normal exit.

Win32 TerminateProcess admits only the current-process pseudo-handle or an
existing current-process object handle with PROCESS_TERMINATE (`0x00000001`).
Missing rights or an already-ended current-process object return error 5;
NULL, wrong-type and foreign-process handles fail closed with error 6 in this
restricted single-process profile. Success preserves last-error and does not
return to the dying caller. No cross-process termination/I/O-cancellation model
is added. Public sources establish the no-DLL-notification distinction and
requested final exit codes; precise invalid/type/foreign-process native error
priorities remain outside this profile.
[TerminateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess),
[Terminating a Process](https://learn.microsoft.com/en-us/windows/win32/procthread/terminating-a-process),
[TerminateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminatethread),
[ZwTerminateProcess](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwterminateprocess)

Forced process termination clears every guest continuation, discards only host
loader journals/lock receipts, cancels host wait registrations, and proceeds to
ordinary thread/object resource shutdown without guest rollback writes or DLL
callbacks. Requested terminal status is retained even when a loader callback
was active. Image/private arena allocations, including abandoned transaction
reservations/guest blocks not recorded as thread-owned TLS, remain process-owned
for postmortem inspection until Proc is dropped; they are not claimed to be
native-address-space teardown. Ordinary forced thread termination signals its
object and frees its stack/TEB/TLS without DLL callbacks. Terminating a thread
inside an active loader continuation retains the explicit fatal abandonment
diagnostic profile rather than fabricating a native initializer result.

Fast-fail uses status `0xC0000409`; Microsoft documents no exception-handler
invocation for the architecture-specific fast-fail mechanism. Failed exception
dispatch-stack writes retain the existing STACK_OVERFLOW/BAD_STACK status
selection; its exact native equivalence is unknown.
[__fastfail](https://learn.microsoft.com/en-us/cpp/intrinsics/fastfail?view=msvc-170)

Six new cross-ABI regression units cover normal/forced HLE distinctions, NT
self admission/status preservation, Win32 current handles/access/error behavior,
terminal SEH/failed-stack selection, forced-thread signaling/resource cleanup,
and forced-process abandonment of a held notification guard. They inspect
admitted RAX behavior, not a native Windows oracle.

Observed scoped commands on the shared combined tree, 2026-09-27:

| Command / temporary condition | Observation |
|---|---|
| `cargo test --locked --no-default-features --lib forced -- --nocapture` | 7 passed, 0 failed, 0 ignored: five new forced units, existing peer-signal unit and host-receipt discard unit |
| Exact `user::windows::dll::kernel::tests::terminate_process_checks_current_handles_and_remains_distinct_from_exit_all_abis` filter with the same Cargo feature/lock flags | 1 passed, 0 failed, 0 ignored; all three guest ABIs exercised inside the unit |
| Only NtTerminateProcess helper temporarily changed back to `Flow::ExitProcess` | New exact NT regression failed (exit 101), first failing case `x86: NtTerminateProcess` |
| Process helper restored; only NtTerminateThread changed back to `Flow::ExitThread` | Same exact regression failed (exit 101), first failing case `x86: NtTerminateThread` |
| Both production forced helpers restored by exact patches; `cargo test --locked --no-default-features --lib user::windows::dll::native::tests::nt_termination_self_paths_are_forced_all_abis -- --exact` | 1 passed, 0 failed, 0 ignored; x86, x64 and ARM64 self/pseudo/NULL/invalid-handle cases executed |
| Exact owned-file `rustfmt --edition 2024 --config skip_children=true --check` and `git diff --check` | Passed; source then frozen for parent full gates |

The two temporary reversals stopped at their first x86 assertion; they are
observed pre-fix regressions, not three native-ABI red traces. Final restored
units cover all three emulated guest ABIs. These filtered gates do not establish
full-library or feature-enabled coverage; those results belong to the combined
architecture task record. No stage, commit or index mutation occurred here.
Forced terminal dispatch is O(1); the process frontier's frame/receipt discard
is O(T + F + J), with T threads, F total retained frame/capture contents and J
transaction receipt contents. Existing shutdown additionally scans the object
table for owned mutexes once per destroyed thread: O(T × O + R), with O object
entries and R cumulative heap/VM resource-release work. No linear whole-process
teardown or total host-allocation/OOM bound is inferred.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| L1 | Guest execution/mapping changes remain serialized on one host thread | Current scheduler design | Checked TLS publication preflight and callback plans | Callback switches context or changes mappings | Introduce concurrent CPU execution or a mapping mutation outside the scheduler | confirmed within current profile |
| L2 | Existing module init_order is dependency-postorder for admitted acyclic imports | bind_imports precedes init_order insertion | Static startup preparation only; normal notifications now use actual ready completion order | Shared dependencies, cyclic imports and nested inner-load completion | Compare ordered traces from A→B/shared-B/cyclic/nested fixtures | retained; total native order unknown; mapping order rejected for normal detach |
| L3 | TLS-before-entry attachment, entry-before-TLS detachment and reverse-ready-native module detachment remain explicitly named profiles until an oracle | Existing attach code; public sources lack full relative ordering; parent selected consistent detach profile | Lifecycle implementation ordering | Multi-callback DLL; FALSE/exception/normal exit | Native ordered notification traces disagree | retained, not claimed native-equivalent |
| L4 | Personality-owned TLS/LDR allocations are not guest-freed and recycled | Existing system-allocation ownership contract | Host-authoritative teardown identity | Guest HeapFree of genuine system allocation followed by reuse | Allocation-generation fixture exhibits reuse freed by teardown | retained restricted admission; generation model absent |
| L5 | Restricted NT NULL/self-pseudo admission, terminal-SEH forced cleanup and normal last-thread notification staging remain personality policies until a native oracle | Public contracts do not establish these complete private native paths | Explicit terminal variants, callback suppression and final-thread staging | NULL versus current NT handle; unhandled filter; last normal/forced thread | Versioned native trace shows different handle or callback behavior | retained; native equivalence unknown |
| L6 | Historical module indices are never reused and admission stops at 4,096 slots | Stable tombstones prevent stale module-index reinterpretation; bounded metadata profile selected by parent | Finite module-history bookkeeping | 4,096 slots followed by a fresh load; repeated live lookup at the cap | New module admitted beyond cap or stale index resolves a new image | retained profile; not a native limit or total host-OOM proof |

## Bounded scope and self-red-team

High, blocking feature completeness: dynamic static TLS and abandoned callback
transactions are independent of callback sequencing; omit neither nor claim
support. High, blocking exact native-equivalence: relative TLS/DLL-entry ordering,
cyclic-graph cleanup and nested-loader outcomes remain unknown without native
probes. They may remain explicit rejected/profiled branches.

High, preexisting: guest-writable LDR/TLS allocation identity can be freed and
recycled; address-only host ownership lacks allocation generations (L4).
The new group must preserve existing restriction or introduce generation-aware
ownership with authorization.

Medium, outside this group: full loader search policy (SxS, packaged apps,
redirection, modern LoadLibraryEx flags), non-ASCII ANSI conversion and advanced
resource APIs. Basic LoadLibrary(EXE) data-kind mapping is admitted without
import binding, TLS initialization or entry execution; this does not implement
LoadLibraryEx datafile/image-resource flags. Existing LoadLibraryA lossy UTF-8 decoding is not a proven
Windows code-page implementation. These are independent admission limits.

Medium, outside this group: FLS callbacks and CRT cleanup are not supplied merely
by delivering DLL notifications; keep absent behavior explicit. No ISA/JIT/C ABI
expansion is necessary.

Medium, non-blocking within the present module-count profile: completion-ledger
Vec membership/removal makes all-module attachment/detachment O(M²) rather than
linear. The source-level complexity above includes this helper cost; no indexed
ledger performance claim is made.

The historical-module bound is H ≤ 4,096, including executable, builtin,
native/data modules and tombstones. Retained name/path metadata is O(H × L),
where L is retained string length in bytes. Live repeated loads do not create
new history slots. The bound is a RAX admission profile, not native Windows
semantics and not a proof against all host allocation exhaustion (L6).

Quality gates for this analysis: source/code facts separated from profiles and
unknowns; seven-field register present; requested lifecycle categories covered;
pointer arithmetic/complexity specified; no unlabelled contract conflict;
Microsoft provenance and licenses retained; scope items classified. Full runtime
quality gates are recorded by the combined-tree architecture task record, not
inferred from this source analysis.
