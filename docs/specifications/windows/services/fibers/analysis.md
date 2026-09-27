# Windows fibers/FLS source assessment and admitted profile

Date: 2026-09-27. Baseline HEAD `28aa423b11beea024c5bebbcccdd5dcd1d0312b4`;
tracked/index clean at assessment start, unrelated untracked material preserved.
Guest ABIs: PE32 i386, PE32+ AMD64, PE32+ ARM64. No native Windows oracle was run.

## Primary public contracts

| Surface | Verified contract | Retained primary source |
|---|---|---|
| FlsAlloc | Process-wide index, optional callback, zero initial per-context values; failure FLS_OUT_OF_INDEXES and GetLastError | [FlsAlloc](flsalloc.md) |
| FlsFree | Reusable index, freed across all process FLS instances; associated callback for each non-NULL fiber value; does not free pointed-to memory itself | [FlsFree](flsfree.md) |
| FlsGetValue/SetValue | Selected fiber's slot; NULL/zero failure; SetValue lists ERROR_INVALID_PARAMETER and ERROR_NO_MEMORY | [Get](flsgetvalue.md), [Set](flssetvalue.md) |
| FLS callback | VOID(pointer value); called on fiber deletion, thread exit and index free | [PFLS_CALLBACK_FUNCTION](flscallback.md) |
| FLS without conversion | Behaves as thread-local storage; switches with the fiber | [Fibers](fibers.md) |
| ConvertThreadToFiber[Ex] | Current thread becomes its current fiber, using supplied fiber data; pointer or NULL/error | [Convert](convertthreadtofiber.md), [Ex](convertthreadtofiberex.md) |
| ConvertFiberToThread | Releases conversion resources; afterward the caller cannot use fiber functions | [ConvertFiberToThread](convertfibertothread.md) |
| CreateFiber[Ex] | Creates fiber object and stack but does not schedule it; first start receives parameter; sizes in bytes, zero uses PE stack defaults | [Create](createfiber.md), [Ex](createfiberex.md), [FiberProc](fiberproc.md) |
| SwitchToFiber | Caller must be a fiber; saves/restores state; synchronized migration across threads is permitted; self-switch has unpredictable problems | [Switch](switchtofiber.md) |
| State/TLS | Saved state is stack, call-preserved register subset and fiber data; TLS belongs to the currently running thread; routine return exits that thread | [Fibers](fibers.md) |
| DeleteFiber | Deletes fiber data/register state/stack; deleting self calls ExitThread; deleting another thread's selected fiber may cause abnormal termination | [Delete](deletefiber.md) |
| Floating point | Ex flag zero does not switch x86 floating-point state; FIBER_FLAG_FLOAT_SWITCH switches it; exact mixed-source/target behavior not specified | [CreateFiberEx](createfiberex.md), [ConvertThreadToFiberEx](convertthreadtofiberex.md) |
| Identity/data | IsThreadAFiber is a BOOL; GetCurrentFiber/GetFiberData are header macros exposing current fiber identity and original parameter | [Is](isthreadafiber.md), [Current](getcurrentfiber.md), [Data](getfiberdata.md) |
| Consulted public headers | Actual x86/x64/ARM64 inline accessors read NT_TIB.FiberData; GetFiberData dereferences the first pointer at the resulting identity; the separate `#define` forms are IA64-only | [Installed MinGW 14 excerpt](mingw14-winnt-fiber-excerpt.h), [installed bundled 13 excerpt](zig-mingw13-winnt-fiber-excerpt.h), recorded public layout probes |
| Stack | Initial commit rounds to page size; reserve rounds to allocation granularity; PE defaults apply; native stacks grow through reserved pages | [Stack size](thread-stack-size.md) |
| Guard pages | One-shot access raises STATUS_GUARD_PAGE_VIOLATION (0x80000001) and clears PAGE_GUARD; a system service encountering the guard generally fails that first access | [Creating Guard Pages](creating-guard-pages.md) |
| Conversion errors | ERROR_ALREADY_FIBER = 1280 (0x500); ERROR_ALREADY_THREAD = 1281 (0x501) | [System Error Codes](system-error-codes--1000-1299-.md), independently matching retained MinGW-w64 winerror.h |
| Process-exit FLS evidence | A documented Visual C++ CRT failure includes an FLS callback through LdrShutdownProcess/ExitProcess; this is concrete evidence, not a universal ordering specification | [Microsoft troubleshooting article](fatal-error-thread-exit-fls-callback.md) |

Public sources do not establish FLS slot-zero reservation, a universal 4080-slot
limit, callback order/reentrancy pass count, successful FlsGetValue last-error
clearing, callback fault/abandonment status, or FLS-versus-DLL teardown ordering.
Do not infer those from names, current code or a self-comparison test.
The stack conceptual page contains an older forced-thread stack-lifetime claim;
the retained version-specific TerminateThread API takes precedence for modern
stack release. General Win32 fiber pages contain legacy 32-bit fiber-count
examples, not universal AMD64/ARM64 capacity guarantees.

The installed header excerpts preserve 108 verbatim lines each, selected by
recorded inclusive ranges without added separators. Both installed MinGW 14
inputs match the v14.0.0 full-header hash. The Zig-bundled declared MinGW 13
input has its own verified hash and differs from the v13.0.0 release header;
the exact installed upstream commit is unknown. Installed COPYING notices
specify ZPL-2.1 as the default for these unmarked header ranges, separate from
Microsoft prose CC-BY-4.0/code MIT scopes. Public FiberData offsets and the
first-pointer accessor do not establish the remaining native private fiber
record, floating-point state or termination semantics.

## Baseline evidence and implementation partition

Baseline `tls.rs` stored callback pointers in a Vec and values by tid, not fiber.
Its internal helpers had unit coverage but no DLL export registration. Free
made the index reusable before callback execution; normal destroy directly
removed values without calling the internal exit helper. No conversion/create/
switch/delete fiber APIs or fiber engine existed. `layout.rs` already described
NT_TIB.FiberData, while thread creation did not publish a selected fiber there.
These are newly admitted APIs, not evidence of an existing reachable FlsFree
guest defect. Earlier threading/services docs' absent-DLL-detach claim became
stale after the previous DLL lifecycle group.

| Owner / files | Acceptance responsibilities |
|---|---|
| FLS registry: tls.rs + tls/fls.rs | Typed Thread/Fiber keys; zero initial values; checked generations; transactional context move; deferred free; live-generation cleanup; bounded rearming and abandonment receipts |
| FLS frontend: dll/fls.rs + tests | All four exports/ABIs, pointer-width values, last-error profile, VOID guest callbacks, cleanup continuation helper; registration parent-owned |
| Fiber engine: process/fiber.rs and semantic siblings | Host-authoritative identities/stack ownership; save/restore current stack/context/frame state; conversion/migration publication and checked rollback; source/target FP profile |
| Parent shared integration | Thread/Proc fields, HLE fiber terminal flow, normal DLL-then-FLS stages, forced bypass/discard, callback continuation ownership, fiber DLL exports |
| Fixtures/docs/provenance | Compiled x86/x64/ARM64 fiber/FLS traces; public-source archive and explicit profiles; unfiltered build/test gates parent-owned |

CPU state, callback ABI/context marshalling, memory/stack ownership and public
Rust personality state are affected. ISA decode/execute instruction semantics,
SMIR lift/IR/interpreter/optimizer/lowerers/JIT, machine/device/backends, static
oracle and C ABI are unaffected: this group uses existing direct user CPUs.

## FLS implementation contract

FlsKey::Thread(u32) and Fiber(u64) are disjoint, host-authoritative identities.
Fiber identities are validated externally by the fiber engine. Conversion and
reconversion move values without callbacks and without overwriting a nonempty
destination. Busy cleanup keys reject movement. FLS pointer values are opaque;
SetValue never dereferences them. Static/dynamic TLS remain thread-local rather
than switching with FLS.

Slots have checked u64 generations and Free/Allocated/Closing admission states.
FlsFree snapshots all generation-matching non-NULL values, clears them, and
keeps the index Closing until its VOID callbacks complete. Callback-induced
FlsAlloc cannot recycle that index mid-plan. Nested FlsFree/Set/Get of Closing
indices reject invalid input. A later allocation increments generation so stale
data cannot become a value or callback for a recycled index. Deferred release
timing is an explicit profile; the public page does not specify reentrant reuse.

Context cleanup removes one live value before each callback and reads the live
slot generation again on its next step. Callback-created/rearmed values are
drained; stale generations and null/non-callback values are removed without a
callback. Cleanup stops with an explicit diagnostic after 4096 callbacks for
one context rather than looping forever or inventing successful cleanup. Index
order and sorted typed-key Free order are deterministic profiles, not native
ordering claims. All registry borrows end before guest code runs.

Free/deletion callbacks execute on the invoking caller's current thread/fiber,
without temporarily selecting the context whose value is being drained. Values
created by a callback therefore belong to its actual selected context. Native
callback-context identity details are unknown. Normal exit uses DLL notifications
first, then FLS cleanup, before freeing TEB/stack/TLS; values created during DLL
detach are consequently included. Normal ExitProcess stops peer threads first
without their FLS/DLL_THREAD_DETACH callbacks; only the live caller gets the
normal cleanup stage. Forced exits skip guest cleanup. These teardown stages
are profiles; public sources do not establish their exact relative ordering.

Tickets carry owner-tid abandonment receipts. An unfinished continuation Drop
releases Closing/busy host ledgers and queues a diagnostic receipt, not a
successful API return. A callback deliberately invoking ExitThread, ExitProcess
or TerminateThread retires its own unfinished receipt without replacing the
terminal action/status; the abandoned API never fabricates a successful return.
Nonterminal NtContinue/longjmp escape still reports a diagnostic. Forced process
termination discards all receipts. Separate loader-receipt abandonment remains
an explicit fail-closed profile. Receipt capacity is pre-reserved for all active tickets so Drop does
not allocate. FlsGetValue success clears last-error to zero as an explicit
profile; other successful FLS calls preserve it. Invalid/unallocated/Closing
indices return ERROR_INVALID_PARAMETER (87). Registry allocation/cap exhaustion
uses ERROR_NOT_ENOUGH_MEMORY (8); the cap's exact native error is unknown.

The engine parks whole CPU state, exceeding the public call-preserved subset;
volatile-register preservation is not promised as a native guarantee. On x86,
a target without FIBER_FLAG_FLOAT_SWITCH inherits the outgoing enabled XSAVE
FP/SIMD payload (XSAVE mask 0xE7, excluding APX integer component 19); a flagged
target restores its parked payload. Exact mixed-flag/XSTATE
semantics are unknown. AMD64/ARM64 always preserve whole CPU state regardless
of the flag, with native flag effects unknown. New fibers clone creator CPU/FP
state; native initial floating-point state is unknown. Stack ownership transfers
Thread→Fiber→Thread, and a dormant converted/migrated stack can outlive its
creator. Exact native teardown in that case is unknown. Cross-thread migration
rejects arbitrary thread-bound HLE receipts, while plain application and the
RtlUserFiberStart/RtlUserThreadStart wrapper continuations are admitted. An
inactive-Delete continuation abandoned through nonterminal escape is a diagnostic,
not successful deletion. A deliberate terminal callback cancels that API return;
the already-deleting dormant target retains host ownership until final process
teardown instead of reporting successful deletion.

The shared stack helper now consumes the selected controlled guard, commits one
new lower guard, and publishes StackLimit after checked TEB preflight. Commitment
rounds to 4096-byte pages, with a 4096-byte minimum. Rounded commitment at least
the selected reserve promotes reservation to a 1 MiB multiple; otherwise reserve
rounds to 64 KiB. Zero arguments select PE defaults (with a 1 MiB reserve fallback).
The requested reservation is not enlarged merely for private guard/bottom pages.
An initial guard adds 4096 committed bytes only when that much slack fits below
the usable commitment. With at least 8192 bytes of slack, the allocation's bottom
page is initially reserved and growth preserves it. Exactly one page of slack
has only the initial guard and cannot grow; full commitment has no private guard
or reserved bottom page. Native full-commit guard layout is unknown. Guard growth
rejects a new guard below allocation base + 4096 bytes; bottom/quota exhaustion
produce stack overflow. Fiber stacks use requested/default initial commitment;
the older ordinary-thread
creation path still eagerly commits its usable reservation. Exact native stack
growth quantum, reserve margins and private layout remain profile details.

## Arithmetic, complexity and acceptance tests

The retained numeric admission ceiling is 4080 table entries with index zero
excluded: indices 1 through 4079, hence 4079 usable slots. This is a RAX bound,
not a verified native limit. Generation g advances by checked g + 1; u64::MAX
exhaustion is a diagnostic, never modulo-2^64 identity reuse. Fiber pointer/data
arguments use 4 bytes on i386 and 8 bytes on AMD64/ARM64; index is always u32.

For S slots, K contexts, V values in a context and C callbacks, allocation scans
O(S); Get/Set are expected O(1); Free snapshots O(K) plus O(C log C) deterministic
sort and O(C) space. Context cleanup chooses the least index per step: O(V²)
without rearming, bounded by admitted slots; repeated callbacks are explicitly
bounded at C ≤ 4096. Generation checks are O(1). Metadata is O(S + total live
context values + retained callback plans). Context conversion reserves the outer
map before mutation; allocation failure leaves source/destination values intact.
This is not a proof against all host OOM: process/CPU/frame construction and
other preexisting host allocations retain their existing contracts.

Source-level registry units cover typed-key isolation/move/occupied destination,
all-context non-NULL free, Closing admission and deferred reuse, live generation
replacement during cleanup, callback rearming, nonconvergence, abandoned free,
slot capacity and generation overflow. DLL units cover all three ABIs, pointer
values, invalid indices, successful-last-error profile, multiple callbacks,
reentrant allocation, dormant-context cleanup, callback abandonment and guest
TEB faults. They are not native Windows ordering probes. Executable validation
is parent-owned; no Cargo command was run by this subtask. There are seven
registry tests and four cross-ABI frontend tests, including a finished-ticket
Drop regression that preserves a newer same-key cleanup admission. Final
combined execution results are recorded in the parent
[fiber feature record](../../../../architecture/user-mode/windows-fibers.md).

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| F1 | One host execution thread serializes mapping/context publication | Current scheduler | Checked move/publication preflight | Callback changes fiber/thread/mapping | Concurrent guest execution or mutation outside scheduler invalidates preflight | confirmed current profile |
| F2 | Externally validated Fiber identities remain unique while live contexts/tickets exist | Host-authoritative engine ownership | Typed-key values and callback snapshots | Delete/recreate/migrate while callback active | Old ticket observes a newly reused live identity | retained dependency |
| F3 | Closing-slot deferment, deterministic callback order and 4096-call cleanup bound are personality policies | Public sources do not specify reentrancy convergence/timing | Free and normal/deletion cleanup | Recursive free/alloc and perpetual rearming | Native versioned callback trace differs; units validate only profile | retained; native semantics unknown |
| F4 | Callback target context is drained without changing invoking caller identity; DLL stages precede normal FLS drain | Selected integration profile, not a public ordering contract | Delete/Free/normal exit integration | Callback reads current fiber or sets FLS; DLL detach rearms FLS | Native trace shows different identity/order | retained; native equivalence unknown |
| F5 | Numeric slot bound/slot-zero exclusion and successful Get last-error clear are retained/selected profiles | Existing registry bound; public API pages lack these exact guarantees | Capacity and error behavior | 4079 slots, reused slot, valid NULL with prior last-error | Native same-build/architecture probe disagrees | retained; exact native outcomes unknown |
| F6 | Whole CPU parking, x86 target-flag XSAVE selection and unconditional AMD64/ARM64 parking are selected profiles | Public contracts specify a call-preserved subset and x86 flag, not all mixed/extended-state effects | Fiber context/FP switching | Mixed flags, vector state, migration | Versioned native raw-state trace disagrees | retained; native extended-state details unknown |
| F7 | New-fiber CPU/FP state starts as a creator clone | Engine requires a defined initial state; public pages omit initial FP state | First fiber selection | Creator changes rounding, exception flags and SIMD before creation | Native first-entry raw-state probe differs | retained; native initial FP unknown |
| F8 | Transferred dormant stacks may outlive their creator, and only admitted plain continuations can migrate across threads | Host-authoritative engine ownership; thread-bound HLE receipts cannot safely rebind | Stack release and cross-thread switching | Exit creator, migrate converted stack, park loader/FLS callback | Versioned native teardown trace or newly proven receipt-rebinding implementation differs | retained; restricted migration profile |
| F9 | Initial guard exists only when 4096 bytes of slack fit; growth advances one 4096-byte guard page without entering the bottom page; full commitment has no private guard | Primary guard/stack concepts; checked VM helper defines exact policy | Fiber commitment and callback/SEH probes | Full commit, one-page slack, hard bottom, skipped guard, protected TEB, commitment quota | Native VirtualQuery/StackLimit trace differs in initial guard or growth layout | retained; exact native full-commit layout/growth unknown |

## Bounded risks and self-red-team

High, blocking broad fiber compatibility: stack ownership, x86 exception-list
state, continuation frames/loader receipts and FLS must move consistently across
switches/migration; restoring only registers is insufficient. High, blocking
native equivalence: mixed floating-switch flags, private fiber layout and
teardown/callback identity/order remain unknown. Explicit profiles/rejections
are required instead of success inferred from public names.

High, retained profile limitation: ordinary-thread creation remains eager-commit,
whereas fiber controlled guards now grow. Exact CreateFiber commitment/reserve
margins and growth quantum cannot claim native equivalence. Medium:
invalid/current-other-thread DeleteFiber,
self-switch, callback exceptions, nested cleanup and conversion of created
fibers require explicit branches; public void APIs do not define fabricated
failure status values. Medium: O(V²) cleanup order selection is bounded here
but no indexed linear-cleanup claim is made. Low: performance/native-oracle
coverage is not established by source or emulated fixture agreement.

Quality-gate scope: primary facts/profiles/unknowns separated, typed generation
ownership and arithmetic recorded, seven-field assumptions and bounded risks
listed, no unrelated files or index mutated. Runtime gates remain parent-owned
and must be reported by their actual counts, not inferred from this analysis.
The 32-entry primary-source/license manifest passed its declared SHA-256 checks:
22 Markdown sources, two installed header excerpts, three CC-BY-4.0/MIT license
pairs and two installed ZPL-2.1 COPYING notices. License scopes distinguish
Microsoft documentation prose/code samples from installed MinGW header excerpts.
