# Windows threads and object waits

This document defines RAX's admitted Win32 thread/synchronization profile. It
does not establish equivalence with an arbitrary Windows kernel build. The
baseline for this feature group is repository commit
`4312bb48ec169c48c67ea8ab55bbacda702e5e93`. The existing process personality,
HLE argument marshalling, TEB/static TLS construction, exception delivery, and
cooperative scheduler are reused rather than replaced.

## API surface

Every export is described with `WINAPI`/x86 `stdcall` scalar arguments. The
same implementation is reached through Windows x86, x64, and ARM64 HLE
marshalling; pointer arguments are 32 bits on x86 and 64 bits on x64/ARM64.

| Group | Exports | Admitted behavior |
|---|---|---|
| Thread creation | `CreateThread` | Local process; optional inheritable handle; checked stack-size arithmetic; `CREATE_SUSPENDED`; `STACK_SIZE_PARAM_IS_A_RESERVATION`; initial static TLS and serialized DLL/TLS startup |
| Thread control | `GetExitCodeThread`, `SuspendThread`, `ResumeThread`, `TerminateThread` | Per-handle access checks; current-thread pseudo/real handles; bounded suspend count; asynchronous external termination; persistent signaled thread object and exit code |
| Scheduling | `SwitchToThread`, `Sleep`, `SleepEx` | One guest processor; equal priorities; yield, finite millisecond deadlines, `INFINITE`, optional alertable APC completion |
| APC | `QueueUserAPC` | Local-thread queue; pointer-sized argument; FIFO delivery before initial entry or during an alertable wait; no routine execution in a nonalertable wait |
| Events | `CreateEventA/W`, `OpenEventA/W`, `SetEvent`, `ResetEvent` | Manual/auto-reset state; existing-name property preservation; modify/synchronize access separation |
| Mutexes | `CreateMutexA/W`, `OpenMutexA/W`, `ReleaseMutex` | Initial ownership, recursive acquisition/release, ownership checks, abandonment when the owner ends |
| Semaphores | `CreateSemaphoreA/W`, `OpenSemaphoreA/W`, `ReleaseSemaphore` | Checked signed 32-bit counts; positive release; maximum enforcement; optional previous-count output |
| Waits | `WaitForSingleObject`, `WaitForSingleObjectEx`, `WaitForMultipleObjects`, `WaitForMultipleObjectsEx` | Admitted event/mutex/semaphore/thread/process objects; wait-any lowest index; atomic wait-all; `SYNCHRONIZE` access; 1–64 objects; alertability, timeout, abandonment |

Handle closure, duplication and inheritance/protection flags are provided by
the separately owned handle API group. Closing a thread handle does not
terminate the thread. A thread's internal object reference lasts until
teardown; a handle or parked wait can retain the exited object afterward.

## Explicit profile boundaries

RAX runs all guest threads on one host thread. Each CPU execution is bounded by
the configured instruction slice. An HLE operation is atomic with respect to
other guest threads, but not with respect to an external embedder misusing the
public address-space API concurrently. No processor affinity, scheduling
priority, thread pool, I/O completion callback, remote thread, token,
impersonation, or cross-process object sharing is implemented by this group.

`SwitchToThread` reports whether another currently ready thread is eligible
under the same loader-serialization rule used by the scheduler. Timed waits
use the host monotonic `Instant`; native Windows timer tick rounding and
low-power-state accounting are not reproduced. A finite deadline that cannot
be represented by the host clock is rejected with `ERROR_NOT_SUPPORTED`.

Only `CREATE_SUSPENDED` (`0x00000004`) and
`STACK_SIZE_PARAM_IS_A_RESERVATION` (`0x00010000`) creation flags are accepted.
Other bits return `NULL`/`ERROR_INVALID_PARAMETER` before allocation. Invalid
start addresses are not synchronously rejected; an eventual guest instruction
fetch raises the guest exception. No successful executable-address validation
is fabricated by `CreateThread`.

### Fixed stacks

The existing stack layout reserves a 64 KiB-granularity region, leaves its
lowest 4096-byte page reserved, commits the next 4096-byte page as a terminal
guard, and commits all higher pages read-write. Touching the terminal guard
raises `STATUS_STACK_OVERFLOW`; demand commitment/growth is not implemented.
This differs from the native reserve/initial-commit policy described in
[Thread Stack Size](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-stack-size).

`dwStackSize == 0` uses the executable's reserve size (1 MiB fallback).
Reservation-flag calls select that reservation directly, subject to existing
64 KiB rounding and minimum. Non-reservation calls interpret the size as a
minimum usable commitment request. The executable reservation is retained
when it can contain that request and the two low pages. Otherwise a checked
1 MiB-granularity reservation is selected, including those two pages. Initial
commitment remains the fixed-stack profile, and can exceed the requested
commitment. This deliberately does not claim native initial commitment or
native exact reservation sizes near the reserve boundary.

For a 1 MiB default reservation and a 1 MiB commitment request:

```text
request                    = 0x100000 bytes
reserved/terminal guard    = 2 × 4096 bytes = 0x2000 bytes
required profile region    = 0x102000 bytes
round up to 1 MiB           = 0x200000 bytes
usable committed region    = 0x1FE000 bytes
```

Both page/granularity roundups use checked `u64` addition. The supplied size
is truncated to the guest pointer width by the ABI before this arithmetic.

### Security and namespaces

The admitted namespace contains one emulated process and one session.
Names are case sensitive. An unprefixed name and `Local\name` identify the
same session object; `Global\name` is a distinct namespace within that process.
Global objects are not shared between independent `WindowsProcess` instances.
The prefix keywords themselves are case sensitive, as specified by
[Kernel object namespaces](https://learn.microsoft.com/en-us/windows/win32/termserv/kernel-object-namespaces).

Names are bounded to 260 UTF-16 units excluding the terminator. `W` APIs accept
valid Unicode scalar strings; unpaired UTF-16 surrogates are explicitly
unsupported. `A` APIs accept ASCII only; no ANSI code-page conversion is
invented. Empty names and empty/nested `Local\`/`Global\` remainders are
rejected. Private/system namespaces and other backslash-containing names
return `ERROR_NOT_SUPPORTED`. Inputs without a terminator within the bounded
scan return `ERROR_FILENAME_EXCED_RANGE`. A checked guest read can instead
raise an access/guard/stack exception at the API call.

Optional `SECURITY_ATTRIBUTES` supports the ABI-specific structure length and
`bInheritHandle`. A non-NULL custom security descriptor is rejected with
`ERROR_NOT_SUPPORTED` for new objects and threads. When a same-type named
object already exists, Win32 ignores the descriptor and the original object's
properties are preserved. No token-derived default DACL, ACL comparison, SACL
privilege, or protected-process security behavior is claimed.

Within that restricted one-principal profile, create handles receive the
documented type-specific full access mask. Open handles retain the requested
explicit standard/type bits. Subsequent APIs check those handle grants.
`GENERIC_*`, `MAXIMUM_ALLOWED`, and `ACCESS_SYSTEM_SECURITY` requests are
explicitly unsupported rather than assigned unverified mappings/security
decisions. Other unrecognized rights fail with `ERROR_ACCESS_DENIED`.

A name occupied by a different synchronization-object type yields
`ERROR_INVALID_HANDLE`; a matching type returns a new handle to the original
object and `ERROR_ALREADY_EXISTS`. Initial ownership/state/count options are
ignored on that existing-object path. Opening a missing name returns
`ERROR_FILE_NOT_FOUND`.

### Waiting and teardown

The complete handle array, object types, access grants, count bound, duplicate
objects and deadline are checked before any signaled state is consumed.
Wait-any consumes only the lowest-indexed signaled object; wait-all consumes
all objects only when all are signaled simultaneously. Waiting acquires a
mutex, decrements a semaphore, or consumes an auto-reset event. Manual-reset
events and exited thread/process objects remain signaled.

The public Windows contract prohibits repeated handles and leaves closing a
handle during a pending wait undefined. RAX additionally rejects distinct
handle aliases to the same object with `ERROR_INVALID_PARAMETER`, and pins
object references while parked. Closing the last guest handle therefore
cannot destroy an object still referenced by a parked RAX wait. Shared
scheduler cleanup releases those references exactly once on completion,
timeout, APC interruption, cancellation or process shutdown. This is a
defined RAX profile extension, not a native Windows result for undefined input.

Alertable object waits currently prefer an already-signaled object over an
already-queued APC; alertable sleeps prefer APC completion over expiry. Exact
native ordering for simultaneous readiness/APC/timeout is **unknown** from
the consulted public contracts. Queued APCs are FIFO, delivered in guest
context, and return `WAIT_IO_COMPLETION` after callback completion. Invalid
APC targets fault when invoked, not when queued. A terminating or exited target
rejects queuing with the documented `ERROR_GEN_FAILURE`.

External `TerminateThread` requests are applied at the next scheduling
frontier, including for suspended/waiting threads. It does not run
`DLL_THREAD_DETACH` or FLS callbacks. The existing normal thread-exit path also
does not yet deliver detach/FLS callbacks; that pre-existing lifecycle
limitation remains outside this group. Mutexes owned by an ended thread are
abandoned, its thread object becomes signaled, and its TEB, stack and static TLS
resources are released. Successfully published dynamic TLS expansion arrays
are tracked by host-owned allocation addresses and freed at teardown without
trusting a guest-writable TEB pointer. `GetExitCodeThread` reports `STILL_ACTIVE` (259) before
completion, and the actual exit value afterward, including an exit value of
259. Object signaling, not inequality with 259, establishes completion.

On explicit process exit, shared shutdown cleanup releases parked wait pins
without attempting guest critical-section/SRW storage updates, destroys the
remaining threads and signals their objects. The process exit code is assigned
to every remaining thread, as specified by the `ExitProcess` parameter
contract. Shutdown then closes all guest handles, including protected handles,
and drains the object table. No process or thread DLL/FLS detach-callback
completion is claimed by this shutdown path.

Suspend counts are bounded at the SDK's `MAXIMUM_SUSPEND_COUNT == 0x7F`.
Attempts above it leave the count unchanged and return `(DWORD)-1`.
`ERROR_SIGNAL_REFUSED` (156) is the RAX profile's failure code; the exact native
Win32 error mapping for that boundary is **unknown**. Control of an already
exited/terminating target is rejected with `ERROR_ACCESS_DENIED`; exact native
repeat-termination behavior is **unknown**. Recursive mutex count overflow is
an explicit diagnostic, not wraparound or a fabricated successful acquisition.

## Fault and transaction boundaries

- `CreateThread` probes an optional thread-ID output before allocating. A
  failed handle allocation or output publication destroys the unpublished
  thread and releases its object, TEB, stack and static TLS allocations.
- Object creation validates name/security input and the last-error output
  before publishing its new handle. Handle-capacity failure releases a newly
  created, unreferenced object. Existing object properties are never replaced.
- `ReleaseSemaphore` checks positive release and signed-count overflow/maximum,
  then probes/writes its previous-count output before mutating the count.
  An output fault preserves the original count.
- Wait arrays are at most `64 × 8 = 512` bytes. Scalar guest-width arithmetic
  and cross-page reads remain checked. Ordinary/guard/terminal-stack faults
  are classified by the shared HLE dispatcher rather than ignored.

## Complexity and execution planes

For `n <= 64` wait objects, validation, wait-any polling, wait-all polling and
reference cleanup take O(n) expected time and O(n) extra space. Hash-based
duplicate validation has O(n²) worst-case collision behavior, with `n` fixed
at 64. The shared scheduler polls all parked threads before each selection;
this is not a kernel wait-queue scalability claim. Names use O(L) time/space
for `L <= 260` UTF-16 units. Handle allocation scans existing handles and
inserts in a `BTreeMap`: O(H + log H) time. Thread creation additionally costs
the existing TEB-slot scan, page commitment, static TLS copying, and CPU state
construction; cost depends on reservation pages and loaded TLS template bytes.

| Execution plane | Change surface |
|---|---|
| CPU state | Existing Windows thread initialization/context/APC paths reused; no new architectural register layout |
| Memory/MMU | Checked user accesses, existing VM allocation/rollback/guard classification; no new MMU implementation |
| HLE/scheduler/object table | New API descriptors/handlers; shared access grants, exact-case names, wait references and cancellation |
| Direct ISA decode/execute, SMIR lift/IR/interpreter/optimizer/native lowerers, JIT, backend, machine/device, oracle, C ABI | Unaffected: new behavior is entirely in the existing Windows user-personality/HLE frontier |
| Tests/docs | Descriptor-driven x86/x64/ARM64 API regressions, shared scheduler tests, separately owned integration fixtures, retained primary references |

## Assumption register and bounded findings

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | Existing fixed-stack profile is retained | No scheduler demand-growth contract exists | Commitment/reservation behavior | Boundary requests `0xFF000`, `0x100000`, `u64::MAX` | Native query of initial stack commitment would disprove native equivalence, which is not claimed | Retained, explicit limitation |
| A2 | One guest processor, equal priorities, one host execution thread | Scheduler/configuration source | Yield and atomic wait semantics | Suspended peers and loader initialization | Introducing affinity, priorities or concurrent guest execution requires a changed contract | Confirmed |
| A3 | One principal/session/process-local object table; no ACL/token state | Object table and absence of token/security implementation | Explicit access grants and namespace scope | Reduced-grant open/set/wait | Cross-instance named sharing or token/ACL APIs would falsify this scope | Retained; custom security rejected |
| A4 | Undefined duplicate-alias/pending-close input can have an explicit RAX result | Public contracts prohibit repeated handles and leave pending closure undefined | Alias rejection and pinned references | Alias wait leaves state unchanged; close-last-handle while parked | Native results would characterize undefined/native-specific behavior, not prove RAX equivalence | Retained profile extension |
| A5 | Consulted public contracts do not resolve simultaneous readiness or exact boundary-error values | No native Windows execution oracle used | Tie-breaking and suspend/repeat-termination errors | Explicit tests for the RAX branches | Native probes at those exact frontiers | Unknown native results labeled |
| A6 | ASCII `A` and valid-scalar `W` names are the admitted encoding subset | No ACP or UTF-16-code-unit object-key model exists | Exact-case string keys | Non-ASCII byte and unpaired-surrogate rejection | Native ACP/UTF-16 probes plus a broader implementation | Retained; excluded encodings rejected |

High-impact retained limitations: no demand stack growth, no custom ACL/token
semantics, and incomplete normal-exit DLL/FLS notification. These prevent
claims of general Windows thread compatibility but do not prevent execution
within the explicit profile. Medium-impact limitations: polling cost scales
with all parked threads, host-clock timeout behavior, process-local Global
namespace, and unknown native error/tie-breaking edges. No adjacent ISA/JIT
or cross-process implementation is included.

## Provenance and validation

Primary Microsoft documentation and SDK excerpts are retained in
[`services/thread-sync`](../../specifications/windows/services/thread-sync/).
Its `sources.json` records source/canonical URLs, retrieval date, licensing,
normalization, unknown mutable-branch revisions, and SHA-256 for each retained
file. Function documentation supplies API flags, access prerequisites,
existing-name rules, wait results and APC ordering; SDK declaration excerpts
supply the 64-object bound, 127 suspend bound and modern thread access mask.
The retained Thread Stack Size page and TerminateThread page conflict about
whether forced termination frees the initial stack; the latter explicitly
distinguishes old Windows XP/Server 2003 behavior. RAX uses the modern
TerminateThread behavior and frees the stack, with no native differential
verification implied.

The `dll::threading::tests` group contains 18 regression tests, 17 of which
exercise all three guest ABIs; the remaining arithmetic test includes x64 and
ARM64 overflow probes. They check publication rollback, security rejection,
thread handles/state/APCs, names and restricted access, events/mutexes/semaphores,
wait atomicity, hostile pointers, aliases and parked object-reference lifetime.
Build/test commands and observed pass/skip counts are reported by the root
agent for the combined shared worktree; source presence is not execution
evidence. A native Windows differential oracle has not been run.
