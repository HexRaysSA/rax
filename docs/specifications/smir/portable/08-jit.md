# Interpretation, JIT and exact state transfer

This is a compiler/runtime contract and independently executable protocol model.
No portable interpreter, x86-64/AArch64 portable JIT, hosted C++ unwinder or
production parallel scheduler is enabled by these files. The existing lifted-ISA
paths retain their current behavior. Executable profile 0.2 admission requires
matching execution, source ABI, runtime and EH roots; envelope 0.1 is framing only.

Ordered state records are in [candidate.json](schema/runtime/candidate.json).
`candidate/live.py`, `flow.py`, `journals.py`, `lifetimes.py`, `native.py`,
`nonlocal_exit.py` and `exceptions.py` are standalone reference protocols under
`tools/smir-runtime-contract/`. Their trusted registry arguments are actual
runtime/admission facts, never authorities created by deserializing a snapshot.

JIT-001: Portable interpretation and x86-64/AArch64 JIT consume only admitted
portable functions and preserve the same typed values, traps, memory/EH effects
and precise progress. Compilation, fallback or skipped tests are not evidence of
native execution. Unsupported host features fail qualification explicitly.

## Native code as implemented

`crates/smir-portable` compiles a module to code for the host: AArch64 and
x86-64, on hosts with a POSIX way of mapping code. `interp::Code::compile`
compiles every function of a module; a run takes an `interp::Engine`, which is
the interpreter or such code, and `smir-run --native` selects the code. It
lives in that crate, with the typed representation it compiles and the
interpreter it must agree with, not in the main crate: nothing of the older
lifted-instruction lowerers is used.

The rule it is built to is that a run ends the same on either engine: the
same values, or the same fault at the same function, block and operation,
after the same number of steps, with the same effects on memory and on the
host in between. The tests hold it to that rule on every authored program
under several sets of limits, on the service, thread and mapping programs,
and on the whole compiler corpus, where every case and every program is run
on both engines and the reports compared.

It gets there by sharing the interpreter's state instead of mirroring it. A
thread's activations are the interpreter's own records, memory is the same
guarded memory, and a step is the same unit. What native code holds is the
path between steps:

| Part | As native code |
|---|---|
| A function | One piece of code: an entry, the blocks, a stub for every edge between blocks, and an exit that returns a status to the caller. |
| A step | Starts by taking one step out of the thread's lease, and gets a new lease from the limit all threads share when that one is used up, exactly as the interpreter's loop does. A run therefore stops at the same step under any limit. |
| An operation | Always possible as a call of the engine, which performs that one operation with the interpreter's code. The operations listed below also have instructions of their own, which read and write the activation's values in place. Those cover the usual case and check that they have it; in any other case they leave the values untouched and the engine performs the operation. |
| A terminator | A jump is a jump to the edge's stub. A conditional branch tests an integer condition itself and jumps to an edge's stub; a condition that is anything else, and a switch, ask the engine which block was chosen. A return asks the engine to bind the results and returns to the calling code. |
| An edge | Makes the target block current and copies each phi's value for that predecessor: one step. All phis read before any is written; where one phi reads what another writes, the values go through cells of the thread's own. |
| A call | The engine puts the callee's activation in place and gives the address of its code, which the caller calls. The host stack holds one return address for each activation. |
| Stopping | A fault, the end of the program or of the thread, or a limit sets the outcome in the thread's record; the code then returns a status through every calling function down to the host. A thread also stops before any operation once the program has ended. |

A value in an activation has a fixed layout for this: one byte that says
what it is, and for an integer its 128 bits at offset 16, in 32 bytes. The
instructions for an operation act on integers of up to 64 bits that are
defined:

| Operation | With instructions of its own | Left to the engine |
|---|---|---|
| Constants | integers, poison and the undefined value | pointers |
| Copies and the values of phis | everything | |
| `add`, `sub` | with and without `nsw` and `nuw` | a result that a flag makes poison |
| `mul` | without flags; with them up to 32 bits and at 64 | 33 to 63 bits with flags; a result that a flag makes poison |
| `and`, `or`, `xor` | everything | |
| `shl` | with and without `nsw` and `nuw` | a shift by the width or more; a result that a flag makes poison |
| `lshr`, `ashr` | without `exact` | with it; a shift by the width or more |
| Division, remainder, rotation | | everything |
| `icmp` | every predicate on integers | pointers |
| `trunc`, `zext`, `sext` | everything | |
| `select` | an integer condition, whatever the arms hold | another condition |

In every row an operand that is poison, undefined, a pointer or wider than 64
bits also goes to the engine. A unit test runs each of these operations at
twelve widths with every flag on operands at the edges of the width and on
poison and undefined operands, some forty thousand functions, and requires
the two engines to agree on each.

The cost of an activation on the host stack is small and fixed, so the limit
on call depth bounds host stack use. Code is compiled once and shared by all
threads of a run. A host that offers no way to map code, or has other
instructions, reports that compiling is unimplemented; the interpreter runs
everywhere.

## Logical frontiers and SSA

JIT-002: A thread checkpoint records process/thread identity, optional worker owner,
nonwrapping ownership epoch, memory generation, global per-thread journal event
sequence, errno, fenv, diagnostic policy and oldest-to-newest logical frames.
Each frame names artifact/module/binding generations, activation, actual function,
position `(block,operation,predecessor)`, status, exact live typed locals, stack/
temporary/varargs allocations, return/unwind continuations, tickets, journals,
bridge/exception/unwind state and explicit operation progress.

Positions are before an operation after the destination block's phis have been
installed simultaneously. Predecessor identity is present exactly when needed
for an incoming CFG edge. Params, phis, operation results and invoke-edge results
are activation-local SSA IDs. An invoke's result definitions exist only on their
own edge. A checkpoint must contain exactly syntactically live IDs, with actual
admitted types and full values/shadow/provenance; neither omitted values nor extra
stale IDs are accepted. `flow.py` computes a backwards fixed point over actual
CFG/phi edges and EH action captures. Complexity is O(V*E*L) in the simple
set-based reference, O(V*L) space. Unreachable labels cannot become executable
state merely because a block ID exists.

JIT-003: A JIT map must reconstruct that exact state at each exit, including exceptional
and partially completed helper exits. Registers/stack locations are implementation
choices, not the logical format.

JIT-004: Code-cache identity includes executable profile,
canonical artifact and deployment bindings, runtime/helper/ABI revisions, host
architecture/features, FP/diagnostic policy, optimization settings and code/module
generations. Host-dependent generated bytes never alter portable semantics.

A private handoff captures canonical bytes only after a thread is parked with no
worker. It seals process/thread/epoch and is registered as the sole transfer owner.
Resume verifies identical bytes and all retained generations/leases, consumes the
handoff once, increments epoch and assigns one new worker. Modified, stale or
replayed images reject. Cancel returns the parked ownership without execution.
There is no public raw-snapshot restore API or transferable host stack pointer.

## Effect tickets and nonreturning operations

A ticket identifies original operation/frontier, optional actual helper import,
state, normal/unwind frontier, private results/exception, cancellation policy and
committed-byte direction/prefix. None helper means a direct core operation; it is
not a fabricated import. Actual admitted operation/catalog completion determines
whether a normal continuation exists: returns uses Some(exact next/normal edge),
raises/nonlocal/terminal uses None. A file-provided completion string is not an
oracle. The optional-normal wire contract is accepted by the named consumers; current
combined receipts determine compiler-freeze evidence.

States are prepared/running/blocked/completed/raised/cancelled. Completed normal
return carries exactly the declared results with exact types. Raised state carries
only the actual retained exception and unwind edge. Nonreturning helpers can never
publish ordinary results or advance a normal PC, including after pending resume.
Terminal outcomes are distinct from raised exceptions and empty result vectors.
Cancellation before reservation wins without effects; after irreversible entry it
is deferred. One original ticket owns memory, errno, sticky flags, exception and
continuation publication. Completion/resume never repeats an already committed
store, callback, foreign call, constructor, destructor or bulk prefix.

## Floating-point environment

Guest fenv belongs to the logical thread. Source environment is 32 B aligned 8 B;
mode is 16 B aligned 8 B. The ABI's INT010 revision-2 byte format is authoritative.
Source rounding modes are nearest-even, downward, upward and toward-zero. Six
sticky flags include explicit-only DENORM (32); source trap-enable field is zero.
The runtime diagnostic mask is separate and covers only invalid, divide-by-zero,
overflow, underflow and inexact, in that priority order. LLVM default arithmetic
does not modify source flags. Constrained/source operations merge flags before a
diagnostic; a trapped result/store remains uncommitted. Host MXCSR/FPCR/FPSR and
host libc fenv are never ambient guest state. Save/install/restore at every worker,
foreign, host callback and interpreter/JIT transition.

`candidate/fenv.py` independently checks the source word/mode masks, snapshots,
flags and FLT_ROUNDS mapping. `powi.py` retains the full signed exponent width,
performs only required selected multiply/square steps, skips the unused final
square and performs one final reciprocal for negative exponents. Operations use
an exact FP oracle, never host long-double substitution. FP/vector/helper scalar
restrictions, LLVM poison/undef/freeze and NaN rules remain the execution owner's
contract and are checked through actual type graphs.

## Typed construction and current object lifetimes

A construction program declares typed formal captures, slots, parents/dependencies,
array counts/strides, active-union alternatives, child programs, destructor coverage
and normal/exception cleanup schedules. Captures exactly cover program.params;
dynamic counts read an unsigned nominal u64 formal, not a call-signature argument
by coincidence. Journal identity is instance/transition/thread/activation/generation,
independent of source object identity. Nested instances name an explicit parent
instance/slot/element and actual child program/object range.

Each authoritative begin/commit/failure/destruction event consumes a global logical
thread event sequence. Every instance's event vector is positive, strictly ordered
and <= thread high-water mark; sequences are unique across that thread's instances.
Replay sorts events, never ticket numbers: parent begin ticket 1, child ticket 2,
child commit 2, parent commit 1 is valid. Constructor commit publishes a completed
subobject only after all required children. Failure owns partial children until
cleanup. Destructor coverage delegates covered subobjects; it does not destroy
them twice. Throwing cleanup retains its exact exception and required termination
policy. Prefix, reverse order, active union, captured type and generation errors
reject before checkpoint transfer.

Constructor history is not the object's current source lifetime. Publication
consumes a completed construction instance and creates a process-owned current-
object certificate: module/object generations, address/program, exact counts,
current live subobject identities/ordinals/child certificates, exact captured
formal environment and owner leases. Claims carry thread/activation/generation/
instance, never a bare journal number; child ownership is explicit.
An explicitly ended member remains absent even if its constructor once committed.
Nested child facts must match actual child program, offset, storage and lifetime.

Destruction on another thread atomically claims this current certificate and
creates a fresh activation-local journal with a seed, no replayed constructor
history and no retagging of the old journal. The class lifetime ends at destructor
START; the destroying claim is an exclusive owner access capability. Required
already-dead children make the source destruction invalid; trivial absent slots
are not invented. Seed ordinals follow the declared cleanup order and current
array elements, independent of later placement-construction timestamps. Normal
or raised destructor cleanup makes the certificate dead; deallocation is separate.
A second claim or stale revision rejects. Current children, active union and
dynamic counts are retained in the process registry until final cleanup.

Transparent replacement forwards old aliases only for exact storage overlay,
same source type ignoring top-level cv, original complete object not const,
neither base nor potentially-overlapping/no_unique_address subobject, and complete
objects or recursively eligible parents. Nontransparent replacement requires a
current lifetime/launder proof for descriptor-mediated handles. Old cleanup claims
stay dead. This does not promise detection of every source raw-pointer lifetime UB.

## Foreign transition frontier

A bridge retains exact source/target domains, admitted descriptor/recipes, call
continuations, source and target cleanup instances, adapter frame, module/code/
object leases, foreign entry count and result publication count. Stages are
prepared, converting_arguments, foreign_running/suspended/returned,
converting_result, cleanup, unwinding, committed, failed. Native entry happens
once. Foreign RETURNED exposes private target storage only: no portable typed
normal result exists until conversion and required cleanup finish. Source results
are an optional vector of actual execution live values; Some([]) is a converted
void result, None is preconversion. Raw target storage is not a source value.
Partial construction remains in exact typed adapter frame+journal state.

Suspension resumes the current stage. Native return cannot be replayed after a
copy/callback/destructor blocks. Source conversion failure takes the original
unwind continuation and retains exact exception ownership. Required temporary
cleanup precedes normal publication; transferred/returned object ownership is
published through its current object certificate, not erroneously destroyed as
an adapter temporary. Descriptor ownership/cleanup roles must distinguish them.

## Exact native checkpoint profiles

Native context is project-normalized state, not FXSAVE or a host ucontext. The
baseline rejects opaque extensions before entry; AVX/SVE/PAuth or extra state
requires a separately admitted profile. Retain actual code/stack objects and
generations, PC/SP, TLS binding and independently admitted CFI row.

| State | x86_64_v1 | aarch64_v1 |
|---|---|---|
| integer | 128 B: RAX,RCX,RDX,RBX,RSP,RBP,RSI,RDI,R8..R15 u64 | 256 B: X0..X30,SP u64 |
| vector | 256 B: XMM0..15, 16 B each | 512 B: V0..31, 16 B each |
| control | RFLAGS u64, MXCSR u32, reserved u32=0 | NZCV,FPCR,FPSR,reserved u32=0 |
| x87 | 112 B exact layout below | 0 B |
| TLS | 32 B: FSbase,GSbase u64; CS,SS,DS,ES,FS,GS u16; reserved u32=0 | 16 B: TPIDR_EL0,TPIDRRO_EL0 u64 |

x87 offsets are 0..79 eight PHYSICAL R0..R7 80-bit images; 80 FCW u16,
82 FSW u16, 84 full FTW u16, 86 FOP u16 (upper five bits zero), 88 FIP u64,
96 FDP u64, 104 reserved u64=0. TOP=(FSW>>11)&7 and ST(i)=R[(TOP+i)%8].
MMX aliases the low 64 bits of physical Ri; it is never a second copy. Empty-tag
register images and unsupported bit encodings are still retained exactly.

CFI register numbers use the ABI's normalized libunwind namespace, not checkpoint
array indices. x86 GPR/PC 0..16 and XMM17..32; AArch64 X0..SP/PC 0..32 and V64..95.
CFA sp/fp has unused reg=0. Recover every register from the ORIGINAL context and
commit together; rule order cannot change results. Stack reads use actual retained
stack bounds. GPR/PC width is 8 B; vector recovery width 8/16 B preserves unused
high bytes where the native ABI specifies. Baseline foreign metadata supports
qualified affine CFI; nonaffine/unknown expression recipes reject explicitly,
not an invented context ABI. Portable logical C++ EH does not require native CFI.

JIT-005: Qualify six host pairs independently: Linux x86-64 System V and
AArch64 AAPCS64; macOS x86-64 Darwin and arm64 Darwin; Windows x64 and ARM64.
Witness host prologue/stack alignment, preserved registers, TLS/fenv switching,
unwind and panic containment, executable-memory W^X transitions, instruction-cache
synchronization, callbacks and exact exit maps. Code publishes only after final
relocation/cache synchronization; revocation drains all PC/return/CFI leases before
reclaim. These remain production qualification gates, not source-contract gaps.

## Private exceptions, owner proxies and source termination

Opaque execution exception E stays SSA, including private LLVM landingpad
`{target("smir.exception"),i32}`. Compiler-only constant-ID slots eliminate to SSA/
phis before every optimization/O0/LTO/emission path. Ordinary memory, integer
casts and aggregate zero cannot forge E. Source `std::exception_ptr` instead is
an 8 B aligned-8 data-pointer field to a process-owned owner proxy, never E bits,
a native unwind header or the thrown payload address.

Allocation carries actual nominal T, size/alignment and owner destructor metadata
before construction. `eh_object_address(E)` returns original uninitialized payload
storage. Explicit typed completion certifies T construction, including scalar/
trivial T after stores. Constructor failure cleans partial subobjects then releases
unthrown storage without a complete T destructor. `eh_raise` checks the completed
certificate and binds the original owner; pure search never executes guest code.
`eh_catch_object(E)` returns selected adjusted SOURCE storage before begin-catch,
without copy/count transition. By-value catch copy has one S026 action with
PRE-invoke destination capture; the original source copy call is removed.

The owner proxy is a guarded read-only 32 B object aligned 8 B: revision u32=1,
reserved u32=0, proxy ID u64, payload ID u64, generation u64. Registry object kind,
exact base, provenance, generation and process grant authority. Copied header
bytes, an interior pointer or payload pointer do not. `eh_current_owner()` returns
null without an ACTIVE catch; otherwise same proxy plus one owner strong ref.
Owner retain/release are null no-ops. Copy retains new before releasing old;
move transfers pointer and nulls source. Each thread's propagation/catch facade
is separate from process payload ownership. `eh_owner_rethrow(ptr)` is void,
completion=raises: fresh E appears only on the original invoke unwind edge.
No old facade is retagged to another thread.

The last owner+facade reference starts one retiring cleanup ticket. Complete T
destructor runs once outside registry locks and may suspend; storage/type/module/
code ownership remains retained until completion. A destructor throw follows source
termination; it is not Rust unwinding. Public process EXIT waits for all such
owner-dependent guest cleanup. Host-held exception owner leases keep process
closing/finalize busy; releasing them cannot cause guest destructor effects after
an already published terminal EXIT.

`eh_uncaught_exceptions()` returns logical-thread propagation count: increment
once per fresh propagation, decrement at catch entry, not during pure search,
resume or retain. Overflow is resource failure before state mutation. `throw;`
uses `eh_rethrow_current()` against the dynamic ACTIVE catch stack, even in a
called function with no lexical E. No active catch invokes source terminate.
Explicit low-level rethrow(E) validates that active catch; resume remains the
existing propagation, not another throw.

The process terminate handler is an atomic retained callable token with actual
portable fixed void() signature. `eh_set_terminate` returns the old token;
`eh_get_terminate` reads the current global. Initial throw captures the then-current
handler. Bare rethrow preserves that snapshot. Exception-pointer dependent rethrow
captures current global. Explicit `std::terminate` selects the top active catch's
captured handler, else current global; implicit unhandled/noexcept/catch-copy
termination establishes an implicit catch of the CAUSING exception and uses its
snapshot. Thus current_exception observes that cause and uncaught count excludes
it while retaining other propagations. Handler runs in the same logical thread
outside locks; it may suspend. Return/throw causes immediate abort without another
handler call. Forced exit/cancellation is a separate terminal protocol.

Primary checks use pinned libcxxabi `cxa_exception.cpp`, `cxa_handlers.cpp`, Clang
CGException and libunwind source plus Intel SDM registered in provenance. These
are bounded baseline choices, not universal binary-only C++ compatibility. The named roles accepted the helper/catalog migration. Current combined witnesses
and remaining cross-role contradictions determine the compiler freeze; production
implementation is a separate gate.

Assumptions: liveness input is already verified SSA/EH, native CPU facts have actual
code/stack/TLS/CFI owners, and certificates derive from trusted transitions. Stress
with extra/missing SSA, stale generation, copied proxy, changed handoff bytes,
parent/child replay and two simultaneous destruction claims. High-impact finding:
execution shape alone cannot certify source ABI or object lifetime. Medium:
process owner proxies permit cross-thread rethrow without illegal opaque memory.
Low: reference replay and native host witnesses do not establish a portable JIT or
six-host foreign unwind implementation.

Ordinary source coroutines use the LLVM owner's required pre-split pipeline and
portable frame geometry. Their inactive heap frame retains owner module/code/
storage generations until destruction even when no VM activation remains. Resume
uses the resuming logical thread's TLS/fenv/errno/catch/uncaught state; it does not
restore creator ambient state. Private E, including aggregate-contained E, cannot
spill into guest coroutine storage. An ordinary 8 B exception_ptr owner proxy may
persist with its generated retain/release lifecycle. A sealed VM safepoint carrying
E is a different runtime operation. Concurrent resume/destroy without required
source synchronization is source UB, never permission for a host data race.


## Partial source objects across coroutine suspension

R042 partial objects are process facts, separate from activation-local J handles
and completed-object certificates. runtime_partial_object stores exact module/
object generations, address/program, captures/counts, historical completed children,
CURRENT live children, phase, optional full owner tuple and leases. Historical
completion never revives an explicitly ended/replaced child. Captured pointer
metadata preserves identity; it never extends the source pointee lifetime.

journal_begin(object,...journal_captures)->J uses one metadata template expanded
in declared cleanup_program.params order into actual nominal.execution types.
The resulting function is fixed portable, noundef false; None is missing metadata,
whereas [] is a verified zero-formal environment. journal_detach(J),
journal_adopt_child(J,u32slot,u64element,child), journal_claim_partial(object)->J
and journal_fail_partial(object,E)->J use existing ordinary call/import records.
All have SELF journal ABI namespace and no target namespace. Process captures
exclude PRESENT exception/J/stack_mark/va_list recursively, using the actual
execution containment graph; code-pointer signature edges are excluded.

Adopt consumes the actual complete child's independent ownership, checks source
program/type, address/extent/generation/slot/count/dependencies/active union, and
advances revisions without copying bytes or replaying constructors. Parent and
first child may share an address. Completion ranks belong to the Builder, advance
monotonically with u64 overflow checked before mutation, and survive resumption.
A prior TID event sequence 500 and resumer sequence 1 cannot reorder children.
Per-thread source event clocks remain separate; no history is retagged.

Detach commits process facts and consumes old J BEFORE entering await_suspend or
publishing a coroutine handle: another thread may resume/destroy before that call
returns. No pending real constructor/foreign effect ticket may be detached.
Bool-false continuation reclaims fresh J; await_suspend throw claims fresh partial
cleanup; symmetric transfer detaches before tail dispatch. A resumed activation
gets an object/partial discriminated seed and exact saved captures/counts/current
children, with no old constructor events.

A child constructor failure while J is active resolves the actual issued old J,
owner tuple, failed effect ticket/current E and invoke-unwind frontier. Its own
partial children must already be cleaned and no other effect may be pending.
Atomically consume old J and failed ticket, then issue fresh cleanup J in the same
thread/activation/generation with a fresh instance; never retag the old J.
Detached failure retains its separate route. Cleanup destroys only CURRENT
completed children in reverse Builder completion order, exactly once, using the
exception schedule even for normal coroutine destruction. It never invokes an
unconstructed complete parent's destructor. Successful aggregate publication
consumes the Builder and transfers current child ownership into a complete object
certificate. Frame/code/module/deallocation leases survive until actual cleanup.

The independent partials.Registry models these transitions under the process
lifetime lock; its private issued handles and trusted effect/frontier inputs are
required. Serialized partial snapshots cannot create ownership or resume authority.


Counts and captures in a new partial factory follow the actual declared slot and
formal orders; dynamic counts require a defined unsigned scalar. A scalar/trivial
leaf commits only from independently replayed actual journal effects over the
same issued owner and current partial seed. A complete child uses adoption of its
actual process certificate. Both produce Builder-local completion ranks. Explicit
typed source-pointer destruction resolves the CURRENT certificate/program and
detaches it from its parent at destructor start. Completed placement construction
rejoins the same current owner slot while retaining historical initial rank;
transparent-alias forwarding still requires all source [basic.life] conditions.

The pinned [CGCoroutine.cpp](references/llvm-project/clang/lib/CodeGen/CGCoroutine.cpp)
source at revision 36763294ef639d8a6a4379d81da653dda1c20686 places coro.save before
await_suspend and coro.suspend after it, including bool-veto and throwing routes.
That compiler evidence establishes the insertion-order constraint; it is not
native execution of the proposed portable source-lifetime instrumentation.
