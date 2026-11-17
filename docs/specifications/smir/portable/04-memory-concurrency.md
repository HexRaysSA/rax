# Memory and parallel execution

This chapter defines the portable compiler/runtime contract. The executable
reference models are independent protocol witnesses; they do not enable portable
execution in the existing RAX interpreter or JIT. Experimental envelope 0.1 is
framing only. Candidate executable profile 0.2 requires admission of all ten
sections, including execution, source ABI, runtime and exception metadata.

The exact ordered declarations are in [candidate.json](schema/runtime/candidate.json).
The authoritative helper shapes/options are [helpers-v1.json](schema/runtime/helpers-v1.json),
instantiated by `tools/smir-runtime-contract/candidate/helpers.py`. Legacy
`*.schema.json` records and the 87 legacy fixtures describe the earlier local
runtime-draft-v1 protocol; they are not executable profile-0.2 payload roots.
All sizes below are mathematical integers in bytes (B), with 8 bits/B.

## Addresses, source objects and authority

MEM-001: Portable data pointers have 64 address bits and little-endian representation.
Address 0 is null. Callable tokens, opaque exception/journal/stack handles and
host pointers are separate authorities. A source object has positive base `b`,
size `n <= 2^61-1 B`, and representable one-past address: `b+n <= 2^64-1`.
Zero-sized allocations have distinct runtime identities where source semantics
requires them; they do not create a zero-sized nominal C/C++ object. `new T[0]`
creates no T subobjects. The size bound follows the pinned Clang object's
61-bit maximum size, rather than host `size_t` or a reference-tool memory quota.

Raw MMU mappings may instead end at mathematical `2^64`. An exclusive bound
that equals `2^64` uses `upper_is_limit=true`; it is never wrapped into address 0.
Source-object ranges and raw mapping ranges are deliberately different. A byte at
`2^64-1` can belong to a raw mapping but cannot be the final byte of a source
object whose one-past pointer must remain representable.

Pointer provenance includes actual object identity/generation and optional
absolute range restrictions. Range restrictions survive loss of dereference
provenance. An empty restriction is canonical `{lower:0,upper:0,
upper_is_limit:false,empty:true}`. An origin with `object=None,generation=0` can
restrict numeric use but grants no object authority. Merging incompatible
restrictions intersects them; it does not silently drop the constraint.
Raw byte copying preserves shadow and partial origins without eagerly observing
restricted numeric values. The execution chapter defines the eventual sinks.
In particular, LLVM byte-to-integer/FP conversion strips provenance without
exposing an address; it is not equivalent to `ptrtoint`.

A source allocation's execution storage type is uniformly `array<raw8,N>` for
all `N`, including 0. Its storage layout has size/access `N B`, alignment 1 B,
and stride 8 bits; the segment/allocation supplies actual required alignment.
Typed field/value views have separate verified storage bindings. An allocation
binding can describe the whole object representation but cannot provide a typed
value-comparison mask. No large source object requires an enormous raw scalar.
Type representation limits and configured materialization quotas are separate.

## Guarded accesses and revocation

MEM-003: Every ordinary, volatile, atomic, loader, debugger, foreign-ISA and asynchronous
copyout access participates in the same backing-object protocol.

MEM-002: A guard binds
mapping identity/generation, backing identity/offset, permissions and retained
storage lifetime. Access arithmetic uses `[a,a+n)` in mathematical integers.
Before any effect, validate operand definedness, resource budget, non-null/range,
alignment, complete mapping coverage and permissions, then stage backing errors.
Read requires read permission; write requires write permission; RMW requires both.
A failing load preserves destination IDs. A failing ordinary store/RMW changes
no destination bytes, shadow or result. Cross-page access is one transaction.

Acquire mapping pins under metadata synchronization, then release that lock.
Generation-checked guards keep storage alive but do not hold runtime mutexes
across guest calls, host blocking, cancellation, finalizers or reentry. Revocation
linearizes when new guard admission closes and the mapping generation advances:

```text
open -> closing -> old pins drain -> unmapped
                     |
         all alias/backing/code/IO leases gone -> reclaimable
```

Earlier guards may finish under old permissions. Unmap/reprotect waits for those
guards before returning/publishing replacement permissions. Generation exhaustion
is a resource failure before mutation. Reusing an address does not revive old
object/mapping identities. Revoking one alias does not revoke another alias or
free the shared backing. Waits never hold a lock needed to release a guard.

Byte synchronization keys backing identity and offset, not virtual address.
Multi-backing transactions deduplicate aliases and acquire backing locks in stable
identity order. Host callbacks execute outside locks. Callback-backed ordinary
memory is materialized/staged before commit; externally observable MMIO uses an
explicit service/device boundary. All guest accesses remain host-memory safe even
when guest source behavior is undefined. Serializing ordinary accesses is an
implementation refinement, not a source-language no-tearing or race guarantee.
Unchecked native host loads/stores are not the initial portable implementation.

## Arbitrary-width atomics

MEM-004: Atomic storage widths are every positive size permitted by the verified source
layout and configured runtime quota, including non-power-of-two sizes and sizes
above 16 B. Alignment is an explicit power of two, not inferred from width.
The atomic helper transaction includes bytes, poison/undef/origins, observed value,
CAS success flag, and any FP flags. Every virtual/foreign alias of overlapping
storage joins its backing synchronization domain; conflicting independent domains
reject registration. Process-shared backings require a common broker/domain across
runtime processes. A direct external writer outside that domain is unsupported.

The pinned `__ATOMIC` numeric domain is exact: 0 relaxed, 1 consume, 2 acquire,
3 release, 4 acquire-release, 5 sequentially consistent. Consume may refine to
acquire; LLVM unordered may refine to relaxed. Unknown bits/orders reject.

| Operation | Accepted order |
|---|---|
| load | relaxed, consume, acquire, seq_cst |
| store/flag clear | relaxed, release, seq_cst |
| exchange/integer or FP RMW/flag test-and-set | all six |
| compare-exchange success | all six |
| compare-exchange failure | relaxed, consume, acquire, seq_cst independently of success |
| fence | acquire, release, acq_rel, seq_cst; relaxed/consume follow pinned lowering |

Failure-order validity follows the pinned current LLVM/C++ contract; the old rule
requiring failure no stronger than success is not imposed. Weak CAS may use strong
CAS with no spurious failure. CAS compares either full storage, verified source
value mask, or LLVM integer precision. Padding bits excluded by a value mask are
not guessed from bytes. Poison/undef compared bits use a concrete zero refinement
per observation; observed shadow remains intact. Desired bytes/shadow commit only
on success. Exchange preserves the exact transferred pointer/raw origins.
Integer arithmetic is modulo `2^precision`, including signed/unsigned min/max,
wrap increment/decrement and conditional unsigned subtract variants in the catalog.
Sign extension, high unused bits and shadow use the execution contract, not host
integer overflow. Non-exchange arithmetic clears pointer-origin authority.

FP atomic RMW uses the exact execution FP oracle. LLVM default operations do not
alter source fenv; constrained/source operations merge raised flags before any
configured VM diagnostic trap. A diagnostic leaves memory and result uncommitted.
The integer/FP result is never published before its corresponding memory effect.

The lock-backed generic implementation returns false from `atomic_is_lock_free`.
C/C++ `atomic_flag` is a separate fixed 1 B nominal object with required lock-free
hot operations; it must not be routed through the generic backing mutex. Its
SC path joins generic SC ordering without waiting for a paused generic owner to
release an unrelated object. `atomic_probe.cpp` independently exercises that pin/
fence protocol and generic 33 B operations; it is not proof of all executions.
Generic atomic lock-free macros report 0; the explicit flag guarantee is separate.

Initial generic atomics may strengthen valid orders to sequential consistency.
An SC sequencing protocol orders generic atomics, flag atomics and SC fences.
`singlethread` restricts synchronization to that logical thread; process/system
scope cannot be silently narrowed. A weaker implementation must refine the pinned
LLVM memory model and C/C++ happens-before requirements. Volatile is orthogonal to
atomicity and preserves required access count/order. There is no host-default
memory order, TLS or floating-point environment in the contract.

## Bulk memory and progress

For LLVM bulk helpers, an originally poison/undef length is immediate UB.
A defined zero length is a no-op before pointer/value observation, subject to
separate explicit argument attributes. For nonzero length source/destination
pointer operands must be defined. `memcpy` allows identical source/destination
spans or disjoint spans; other overlap is UB. `memmove` chooses an overlap-safe
direction. `memset` transfers the raw8 value's poison/undef shadow; a defined byte
clears those masks. C source restrict/UB rules remain source-language obligations.

All needed spans are guarded/staged before the first irreversible effect. Long
bulk effects retain a precise direction and committed-byte prefix in a ticket;
resumption continues that prefix and never restarts a completed chunk. A scalar
ordinary access is all-or-none; a bulk operation's declared partial progress is
not an excuse for partial scalar stores. Elementwise atomic bulk lowering records
per-element progress and joins each element's atomic domain.

MEM-006: Default resource budgets are helper chunks of 65536 B, an uninterrupted commit
window at most 1048576 B, and a poll at calls/backedges/transitions or after at
most 4096 committed logical operations. These are configurable work quotas, not
wall-clock response bounds or source ABI limits. Oversized work is decomposed at
explicit progress frontiers or fails a resource request before effect. Host I/O
may have unbounded kernel latency; readiness waits release the guest worker.

## Workers, synchronization and cancellation

MEM-005: Different runnable guest threads may execute simultaneously on different host
threads. A logical guest thread has one worker owner at a time and independently
owns frames, TLS, errno, fenv, pending exceptions, catches and nonlocal state.
Shared mappings, modules, code/token registries and wait queues are synchronized
process objects. State transitions are runnable -> running -> runnable/blocked/
stopped/exited. Publication precedes clearing worker ownership. Wake/cancel races
have one owner and cannot enqueue two workers. Join observes completed cleanup,
not merely host-thread disappearance.

Wait identity is `(backing,byte offset,width)`. Compare/register and update/wake
share word/queue synchronization. Register before parking; a wake between those
steps remains recorded. Timeouts/cancellation remove a waiter once. Spurious
wakeups are allowed; callers recheck predicates. No process/loader/mapping/byte
lock remains held across a guest callback, foreign call, destructor or host wait.
Lock order is metadata -> mapping -> SC protocol -> sorted backings -> wait queue;
transactions prepare outside locks and revalidate generations to avoid inversion.

Cancellation before irreversible reservation can win with no effect. After that
reservation it is deferred until completion; the exact original ticket owns
copyout, results, errno and continuation. Inputs are copied into private host
buffers. Outputs pin and validate all guest destinations before consuming an
external effect, then copy out exactly the successful prefix. If the process
closes, a late completion drains its private buffer and never writes guest memory.
There is no asynchronous Rust/C++ host-stack unwinding through guest code.

A stop transaction advances a nonwrapping epoch and waits for each thread's
matching frontier or already-published blocked state. Interpreter/JIT handoff
requires a private runtime-issued image and consumes it once; serialized state
alone cannot transfer ownership. Signals/debugger delivery occur at eligible
logical frontiers with explicit selected-personality state.

## Clone and current-source changes

MEM-007: Guest fork/clone is a quiescent guest snapshot restored into a fresh runtime
process, never continuation of arbitrary multithreaded Rust state after host
`fork`. Retain only the calling guest thread, private memory/COW contents, shared
broker identities, admitted module/token bindings, explicit transferable handles,
TLS and selected-personality signal state. Recreate host locks/workers. Export
failure or unsupported foreign/handle state returns before child publication.
The legacy clone schema/model exercises a fresh Python process and private/shared
file behavior; it does not establish portable process admission or a broker.
Candidate production clone additionally requires admitted typed live state and
registered personality/handle transfer descriptors, not opaque blobs alone.

| Current source | Observed premise | Required later owned implementation |
|---|---|---|
| `src/user/mm/mod.rs`, `Concurrency` | scheduler assumes one host thread around reclamation | guard/pin/generation and alias-aware access/reclaim |
| `src/user/linux/host.rs`, `fork_process` | host fork child continues runtime state | fresh-runtime restore and handle broker |
| `src/user/darwin/signal/host.rs`, `fork_host` | single-host-thread fork premise | personality snapshot/signal reinitialization |
| `src/user/windows/process/thread/dynamic_tls.rs` | probes precede later serialized writes | parallel guarded TLS transaction |
| `src/smir/lower/runtime/mod.rs` | architectural exits/executable buffers | portable maps, leases, parallel publication/reclaim |

No production file above is modified in this first wave. Primary oracles include
pinned [Atomics](references/llvm-project/llvm/docs/Atomics.md),
[LangRef](references/llvm-project/llvm/docs/LangRef.md), and
[Clang Type.cpp](references/llvm-project/clang/lib/AST/Type.cpp); source identities,
licenses and checksums are integrator-owned in the provenance registry.

Assumptions: actual admitted type/layout graphs and trusted registry facts feed
reference tools; stress by wrong graph/generation/alias tests. Materialization
quotas are resource policy, stress by symbolic large types. High-impact boundary:
shared backings without a common atomic domain cannot participate. Medium-impact
opportunity: stable backing synchronization permits alias-safe incremental native
optimization. Low-impact limit: deterministic protocol schedules do not prove all
parallel interleavings or six-host runtime qualification.
