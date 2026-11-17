# Values and execution

Status: compiler-facing candidate contract for envelope 0.2/profile 2. The
ordered grammar is [candidate.json](schema/execution/candidate.json); its type,
function and exception roots occupy sections 1, 3 and 8. Integrator decisions
INT-D006..016 govern shared references, source ABI, helpers and live state.
Candidate contract acceptance is distinct from the combined compiler freeze.
The production RAX interpreter/JIT does not execute this candidate format.

The earlier `integer_core_draft_v1`, extended type, FP-request and EH-protocol
schemas remain separate historical/reference interfaces. They are neither
inferred from envelope 0.1 nor substitutes for these candidate records.

## Ordinary function addresses and source call sites

The incompatible roots1/3 revision2 and ABI3 cut represents an ordinary source
function pointer as CodeAddress even when its source prototype contains incomplete
by-value types. CodeAddress is a leaf; representing, copying, storing, returning
or comparing it for equality needs no callable Fn or completed call plan. Null is
all zero bits with no origin. A CodeAddress literal holds any exactly 64 defined
bits; nonzero literals retain those bits with no origin, target registration,
exposure, generation, permit or lease. Equality/ne
compare token bits; ordering and integer arithmetic on CodeAddress reject. An
address token does not identify a host PC or carry C++ object/phase authority.

code_bind has one CodeAddress operand and one CodePtr<Fn> result; code_erase has
one CodePtr operand and one CodeAddress result. Scalar/vector shape and lane counts
must match. code_bind.plan is an actual ordinary CallSignature, with no this/VTT,
and its mandatory execution Fn must match the result's actual signature. Static
success does not resolve a provider or issue an address, permit, lease or entry.
At actual execution code_bind checks the current selected target, source plan,
original namespaces, generation and actual entry before publishing its result.
Known incompatibility is code_address_plan, missing actual entry evidence is
code_address_unavailable, malformed authority is code_address_invalid and a
closed/stale generation is code_address_stale. These are non-language-UB faults.

Observing erasure propagates poison, refines undef to null and preserves null.
A genuine live callable origin yields that target's noncall address authority;
originless numeric, label and wrong-domain inputs fail invalid, and a stale
origin fails stale. Neither raw bitcast nor a typed destination substitutes for
this observation. A full raw reconstruction requires ordered complete 64-bit
fragments from the same target, domain, generation AND original permit. Mixed
permits lose provenance even when the token bits are identical. Address origins
remain distinct from callable-code origins; raw address bits cannot upgrade them.

call, invoke and tailcall have mandatory source_plan syntax. None means generic
execution with no SourceOrdinaryCall. Some C is the actual current source call
plan, independently verified against the target Fn and actual SSA/CFG argument,
result and continuation relation. Existing source evaluation and conversions
precede explicit code_bind B; its observing failure precedes the later call's
argument noundef checks. Entry then checks the original retained B->C and actual
provider A->C relations, Fn, generation, leases and current cleanup authority.
Equal Fn alone cannot establish source compatibility. Known same-Fn source-view
mismatch is code_token_signature after argument noundef, without entry publication.
No call site silently rebinds a pointer or recovers C from B, Fn or integer bits.

Ordinary source conversion/exposure uses separate CODE_ADDRESS/CODE registries.
Integer bits retain no authority or permit. Recovery may only reuse a genuine
eligible exposed target/view under the same process, and callable recovery selects
the lowest eligible original permit with checked Fn; it cannot create one. Complete
copy/checkpoint restoration instead retains the original permit. All vector lanes
preflight as one transaction before any publication. The current sequential
reference Machine implements nonobserving value transport and static checks; its
missing actual registry, source-call and checkpoint-permit producers report
unavailable, including whole vector observing operations. It does not execute a
source call via the legacy generic path. Production interpretation/JIT/native
execution is not established by this static implementation.

## Types, values and identity

EXEC-001: A value ID is a u32 unique across parameters, phis, ordinary results and
invoke edge results of one function. Dynamic identity is
`(module_generation, function, activation, value_id)`. Recursive calls allocate
new activations. Blocks and function IDs are u32; function ID 0xffffffff is
reserved for the envelope's no-entry sentinel. IDs are not architectural registers
or memory addresses. Tables are strictly increasing and unique by ID; local SSA
IDs need not be increasing. A qualified reference is `self/id` or
`dependency/slot/declaration_id`. A dependency ID names the consumer declaration,
never a provider's private ID. Link admission binds declarations to exports and
providers for the entire SCC before initialization or code-token publication.

| Execution kind | Exact value model |
|---|---|
| int | N-bit bitvector, 1 <= N <= 2^23; signedness belongs to the operation |
| raw | N bits, 1 <= N <= 2^23, with per-bit poison, undef and pointer origins |
| float | binary16, bfloat16, binary32, binary64, binary128; exact interchange bits |
| data_ptr | 64-bit guest address plus provenance/generation/range; guest_data space |
| code_ptr | 64-bit token plus code/label identity, generation and function signature; a newly bound value retains its original permit |
| code_address | 64-bit noncall target token plus distinct address authority; no signature, 8 B size and 8 B alignment |
| vector | fixed positive lane count; int/raw/float/data_ptr/code_ptr/code_address elements |
| array | fixed count, including zero; homogeneous value elements |
| struct | ordered value fields, including empty; no implicit memory padding |
| function | ordered parameter/result types and noundef lists, cc=portable, variadic=false |
| exception, journal, stack_mark, va_list | opaque registry-branded values, not integers |
| fenv | copyable rounding/sticky snapshot; not thread authority or an opaque handle |

By-value type cycles reject; recursive function signatures through code pointers
are legal. Duplicate structural types are legal. Structural equivalence is
coinductive labeled graph equality, including calling convention, address space,
noundef lists and parameter/result partition. INT-D011 shape identity hashes the
rooted bisimulation quotient, removes numeric IDs and duplicate sharing, then
numbers quotient nodes by ordered root traversal. Its SHA-256 domain is
`SMIR-TYPE-SHAPE-V1\0`. Nominal ABI identity, pointer provenance and live instance
authority are independent of this shape digest. A producer digest is never its
own admission evidence. Source `_BitInt` maximum and nominal signedness are ABI
properties, separate from execution widths.

Constants are recursive `bits/aggregate/zero/poison/undef` variants. Scalar bits
have exactly ceil(N/8) little-endian bytes; high unused bits are zero. DataPtr and typed CodePtr
literal bits must be zero. CodeAddress bits literals are exactly 64 bits and
carry no authority; nonzero callable/data addresses require admitted symbols,
relocations or explicit address conversion; opaque handles and fenv snapshots
cannot be fabricated with a zero literal. Poison/undef can inhabit an opaque
execution type, but cannot become a valid registry identity through freeze or
bitcast. These restrictions are transitive over present by-value components:
zero literals reject nested handles/fenv; freeze rejects nested branded handles.
An array of count0 has no present child values. Freeze of poison/undef fenv selects
the default nearest_even/empty flags/traps snapshot, including within aggregates.
Proven-valid opaque LLVM freeze can lower to copy; it cannot mint a new lease.
A concrete aggregate contains independent component values: extracting
one concrete field does not observe poison in another field.

## CFG, SSA and control transfer

EXEC-002: Each block has phis, ordered operations and exactly one terminator.
There is no fallthrough. Entry has no predecessor or phi. All blocks are reachable
from entry; emitters remove unreachable blocks before emission. A phi has exactly
one input per distinct predecessor, including when several switch cases share
that predecessor. Incoming values dominate the predecessor terminator; other
uses require strict prior local definition or block dominance. Phis read a
pre-phi snapshot and commit simultaneously, preserving swaps and loop cycles.

| Terminator | Behavior |
|---|---|
| jump | explicit target |
| cbranch | scalar i1 selects true/false |
| switch | scalar integer, unique numerically sorted case bit patterns, explicit default |
| indirect_branch | admitted same-function label token and explicit possible target list |
| return | ordered values matching complete result signature; no implicit result |
| tailcall | replace activation after argument capture; preserve caller continuation |
| invoke | call with explicit normal/unwind edge blocks and region |
| throw/rethrow/resume | explicit live exception; protected local transfer is canonical invoke |
| cleanup_return | resume supplied exception; absence requires enclosing admitted cleanup context |
| terminate | explicit termination reason and optional live exception |
| trap/unreachable | diagnostic trap / executed language UB, respectively |

Poison or undef cbranch/switch control is immediate language UB, even if targets
coincide. Undef is otherwise refined per use, so this control rule is an explicit
observation boundary. Indirect branch targets exclude entry, are unique/sorted,
and must agree with the token's function and generation. Tokens for block labels
cannot call functions. Numeric coincidence or a deserialized pointer record cannot
create code, label or object registry authority.

EXEC-003: Calls match ordered types/arity exactly. `function.abi_signature`, when
present, names section 10 `call_signature`, whose source `function_type` remains a
separate nominal type. The descriptor's lowered arguments/results and noundef
attributes must match the execution signature. This is an entry association for
ordinary functions and methods, including constructor/destructor bodies. Hidden
`sret`, `this` and VTT arguments retain their exact ABI roles, order, nominal types
and noundef attributes. They are not added to the source parameter list. A checked
entry association grants no ordinary source-call permit, incoming lifecycle fact,
or reference CLI execution capability. Source `noexcept`, body `escape` and
`no_return` remain distinct contracts; one does not supply another.

Source ellipsis is in that ABI descriptor; execution always has a fixed signature,
including explicit noundef
arena:data_ptr and bytes:u64 suffix where required. `va_start/arg/copy/end` use
admitted arena/cookie/thread/activation state and module-qualified nominal types.

Arguments are captured before callee entry; noundef observes poison/undef including
aggregate components and raw unknown bits. The caller remains at its call frontier
until all normal results validate and commit together. An import suspension keeps
its ticket, captured operands, leases and continuation; resume cannot re-enter a
completed effect. Ordinary `call.unwind` is `nounwind` or `propagate`. A nounwind
violation is language UB; `function.escape=nothrow` has that same meaning.
`escape=terminate` is a termination barrier; `propagate` allows outward search.
A potentially unwinding operation inside a region with handlers/exit actions uses
invoke, not an ordinary propagating call.

Invoke normal results are defined at its normal edge block; its exception lease
is defined at its unwind edge block. Each is a distinct dedicated block with the
invoke as sole predecessor and no phis. A normal result cannot be used/captured
at the invoke's PRE frontier or on its unwind edge. A trap does not choose either
edge or publish call results. Function pointers require exact normalized signature,
nonzero even token and live retained code/module generation. Imported/dependency
calls require fully admitted explicit registry bindings; no host pointer fallback.

Tail calls capture arguments before ending current automatic storage, carry the
original caller continuation and must preserve result shape. They cannot abandon
active cleanup regions, journal/catch obligations, pending effects or nonlocal
checkpoints; emitters lower such sites to ordinary call plus explicit completion.
A reference implementation may bound supported tail targets before any execution;
that resource/feature boundary is not a different guest call convention.
Canonical cleanup_return always supplies its captured exception lease; null is
rejected. A normal cleanup uses ordinary return. Canonical tailcall matches result
noundef attributes and is absent from no_return functions and functions containing
journal/catch/checkpoint operations; ordinary call+return/unreachable expresses
those cases without discarding obligations.

## Integer operations

EXEC-004: For width w bits, M=2^w, unsigned(x)=x in [0,M), signed(x)=x for
x<2^(w-1), otherwise x-M; wrap(z)=z mod M. Calculations use mathematical integers
before wrapping, never host overflow or architectural flags.

| Operations | Result and edge cases |
|---|---|
| i_add/sub/mul | wrap(a+b/a-b/a*b); optional nsw/nuw |
| i_and/or/xor | bitwise N-bit result |
| i_shl | wrap(a*2^b); b>=w poison; optional nsw/nuw |
| i_lshr/ashr | unsigned or signed floor division by 2^b; b>=w poison; optional exact |
| i_udiv/urem | unsigned quotient/remainder; zero or poison divisor immediate UB |
| i_sdiv/srem | q=trunc(signed(a)/signed(b)), r=signed(a)-q*signed(b); zero divisor or MIN/-1 immediate UB for BOTH |
| i_rotl/rotr | bit rotation by unsigned count mod w |
| i_clz/ctz | zero count w, or poison if zero_is_poison; nonzero leading/trailing zero count |
| i_popcount | population count; unused zero_is_poison must be false |
| i_abs | abs(signed(a)) mod M; flag zero_is_poison means MIN-is-poison for this opcode |
| i_bswap | reverse bytes, width multiple of 16; unused flag false |
| i_bitreverse | reverse all w bits; unused flag false |
| trunc/zext/sext | low bits / unchanged unsigned / sign extension, strictly narrower/wider |
| icmp | eq/ne, signed/unsigned lt/le/gt/ge; i1 per scalar/lane |

`nuw` requires the unbounded unsigned result in [0,M); `nsw` requires signed
result in [-2^(w-1),2^(w-1)). For shl use mathematical multiplication, including
negative signed inputs. Violation produces poison. `exact` requires zero discarded
shift bits or division remainder. Flags are sorted, unique and opcode-restricted.
Truncation promises from LLVM are explicit compare/select-to-poison expansions;
they are not silently encoded in an unrecognized trunc field.

Immediate div/rem UB checks precede ordinary poison propagation. A poison dividend
with signed divisor -1 permits the selected overflow UB refinement. Unused flagged
overflow/overshift stays poison and does not eagerly trap. For i8, -7/3=-2 (0xfe)
and remainder -1 (0xff), since -7=(-2)*3+(-1). 255+1 wraps to0; nuw produces poison.

`copy` preserves value state. `select` observes only condition and selected arm;
unselected poison is ignored. `freeze` chooses one concrete result per dynamic
execution and preserves it for all uses. The reference chooses zero for undef
uses and freezes unknown bits to zero: one allowed deterministic refinement,
not exhaustive nondeterministic conformance. Vector arithmetic/comparison/casts
map matching lanes; scalar select can select aggregates. Aggregate extract/insert
use static valid paths; vector extract/insert use scalar integer index, with
out-of-range/poison index producing poison. Shuffle concatenates its two inputs
and selects explicit lane indices; absent optional index produces poison.

## Raw bits, pointers and physical memory

EXEC-008: Raw per-bit poison/undef and pointer-origin fragments survive load/store,
bitcast, vector composition, memcpy and memmove. A fragment records original
pointer identity/generation/domain/range, original bit index and placement. Only
all64 correctly ordered bits of the same pointer restore provenance. Numerically
equal permuted/mixed origins do not. Bitcast to a typed scalar collapses any poison
to whole-scalar poison; otherwise unknown bits choose zero and integer conversion
strips origins without exposing them. Raw freeze replaces unknown bits individually.
`ptrtoaddr` returns a 64-bit address without exposure; `ptrtoint` exposes; inttoptr
can recover only an appropriately exposed admitted live object/code identity.
An unknown numeric address remains unprovenanced and cannot authorize dereference.
The byte-type bitcast rule explicitly strips unrestricted provenance WITHOUT
exposure. A raw->integer/FP conversion of restricted inrange-origin bits instead
observes the address-conversion restriction and diagnoses language UB. Raw and
pointer copies do not eagerly trap. Partial/permuted pointer bits can lose object
provenance while retaining the intersection of all range restrictions; a second
raw round trip cannot erase that restriction. A range-only raw span has objectNone,
generation0 and no object authority.

`ptr_offset` takes signed i64 byte displacement, preserves provenance and applies
explicit inbounds/nuw/nusw/inrange promises. Inbounds tests the original allocation
bounds including one-past; tombstones retain bounds after deallocation, while
subsequent dereference still fails liveness. Zero offset can preserve null.
The exact check_base:boolean field follows inbounds and must be false unless
inbounds is true. When true, original allocation/generation/closed-extent checks
apply even to a zero byte displacement; an invalid promise produces poison.
When false, the original nonzero-displacement rule is retained. LLVM GEP with
nonzero original indices needs this check even when a zero-size stride or
cancellation produces a zero displacement. Dynamic all-original-indices-zero
uses select to retain the original base with its inrange restriction, masking
the unselected strict arm's poison. No liveness check is added to pointer
arithmetic: retained deallocated allocation facts remain valid for inbounds.
The emitter performs source index truncation/multiplication/accumulation promise
checks and emits each required intermediate step; one final displacement cannot
prove those omitted checks. Inrange is relative to the RESULT pointer; accesses
must lie in its half-open interval, comparison's specified closed-end exception
applies, and ptrtoaddr/ptrtoint of a restricted pointer is language UB.
Restrictions are intersected with representable addresses without dropping their
presence. An empty comparison set is distinct from closed point[0,0]; both forbid
positive-size memory access, but only the latter permits comparison at0. A bound
ending2^64 is an exclusive limit, never a pointer value. Ordinary source/LLVM
objects require nonzero base and base+size<=u64MAX, preserving representable one-past;
raw MMU mappings may include the highest byte. Inbounds overflow remains poison.

Section1 memory layouts specify physical bytes independently of nominal ABI:
size/access_bytes/alignment in bytes, field bit_offset/bit_width and sequence
stride in bits. Scalars access ceil(N/8) bytes but may allocate more. Scalar stores
zero high unused bits; a scalar load with nonzero/poison discarded high bits yields
poison (pinned LLVM byte load + trunc nuw). Aggregate store padding is undef and
aggregate load ignores it; raw copies preserve it. Struct fields are ordered,
nonoverlapping explicit views. Arrays stride by child allocation size; vectors
stride by logical lane width. Thus v8i1 accesses1B and array[8xi1] accesses8B.
Empty aggregates have zero effect extent; an opaque handle has no raw layout.

`storage.layout` names actual section1 execution layout; optional `nominal` and
`abi_binding` occur together and select exact section10 source nominal and
storage_binding. The latter verifies byte/bit view, source paths, value/padding
fragments and required alignment. Equal type shapes or matching numeric IDs do
not establish storage compatibility. _BitInt65 may allocate16B/alignment8 while
a typed scalar access touches9B and preserves the remaining7B.
The complete access footprint must fit the source object and cannot clobber source
value bits outside the selected view. Bitfield assignment uses a covering container
plus explicit load/mask/merge/store. A compare mask is not a write-preservation mask.

Defined data/TLS allocation representation is uniformly array<raw8,N>, includingN0,
with u64 count, byte leaf size/access/alignment1 and array size/accessN, alignment1,
stride8bits. Source object alignment is separate. Source maximum object extent is
2^61-1B, consistent with u64 bit extents and the pinned Clang addressing bound;
raw mappings remain separate. Static type/layout/hash validation is O(metadata),
without materializing N bytes. Source nominal.execution is a separate logical view
and mayNone for a nontrivial class. Segment.abi_binding selects the exact complete
allocation/object_bytes binding. Allocation bindings describe representation only:
they cannot authorize a typed source load/store/atomic or comparison mask. Typed
field/value accesses select separate admitted bindings, even for identical shapes.

EXEC-006: Ordinary/volatile load/store, atomic load/store/RMW/cmpxchg/fence and
bulk memory have explicit effects and precise progress. An access guards its
entire extent, liveness, permissions, backing, provenance and alignment before
committing its bytes AND shadow. Volatile preserves count/order even for unused
values. Bulk count must be well-defined before any pointer/value observation;
poison/undef count is immediate UB. Count0 performs no memory/volatile effect and
does not observe pointers or the memset byte, modulo separately enforced source
argument attributes. Nonzero copy/move requires well-defined source/destination;
memset requires a well-defined destination and preserves poison/undef byte shadow.
Memmove snapshots source before destination writes. Memcpy permits identical
source/destination; other overlapping ranges are language UB before writing.
The parallel runtime owns actual alias locks/atomic order and
reclamation; the sequential witness does not prove concurrent native behavior.

Atomic success orders and failure orders are checked independently at this LLVM
pin: cmpxchg failure is relaxed/acquire/seq_cst, even when stronger than success.
No obsolete stronger-failure rejection is inferred. Weak reference CAS chooses no
spurious failures; compare poison/undef bits choose zero per use, observed raw
shadow remains intact, and desired shadow stores only on success. RMW action
names are closed by the schema verifier; integer wrap/min/max/conditional/saturating
and floating six-way min/max families retain their specified distinctions.
The exchange action additionally admits scalar Raw8; exchange of every other raw
width or any vector of Raw8, including elementwise mode, remains rejected. Existing
integer, floating-point and pointer exchange rules are unchanged. CAS keeps all
15 independent pairs of five success orders (relaxed/acquire/release/acq_rel/seq_cst)
and three failure orders (relaxed/acquire/seq_cst). The [scalar Raw8 atomic witnesses](conformance/execution/atomic-bytes/README.md)
exercise actual sequential shadow transport and independent static verification;
they do not qualify parallel commit, precommit quota reservation or fault recovery.
Wide generic byte-backed helpers serialize complete value+shadow+flags, rather
than assuming a hardware instruction width or lowering everything to a host word.

Elementwise atomic load/store/RMW operates fixed-vector byte-sized power-of-two
lanes and power-of-two total bit extent; seq_cst and cmpxchg are excluded. Each
lane is a distinct scalar transaction. Live progress retains next_lane, typed
input snapshot and observed prefix. Fault/suspension never rolls back or replays
completed lanes; no whole-vector atomicity is asserted. Full generic atomics and
source value masks use exact helper storage bindings, not padding guesses.

## Floating point and environment

EXEC-005: Arithmetic add/sub/mul/div/fma/sqrt/frem, neg/abs/copysign, six min/max
families, comparisons, integer/FP conversions and format conversion are executable
candidate operations for all five formats. Normal arithmetic rounds once from
exact mathematics; fma rounds a*b+c once. Frem is x-trunc(x/y)*y, not IEEE nearest
quotient remainder. Sqrt chooses correctly rounded root by integer/rational
midpoint comparisons. Contraction of separate mul/add requires explicit permission.

Subnormals are preserved. Tininess is detected after rounding; underflow requires
inexact tiny result after rounding. Overflow sets overflow+inexact and selects
infinity/max finite according to sign/mode. Rounding modes are nearest_even,
nearest_away, toward_zero, upward, downward; constrained dynamic uses thread mode.
Default mode is exactly nearest_even/ignore and does not alter sticky flags.
Constrained ignore discards status; maytrap/strict OR IEEE status before a VM
diagnostic is reported. Enabled diagnostic priority is invalid, divide_by_zero,
overflow, underflow, inexact; no result commits when diagnostic triggers.

Arithmetic chooses the first NaN operand, preserves sign/payload and sets its quiet
bit; any signaling input raises invalid. Invalid arithmetic without NaN input
returns positive preferred quiet NaN. Fma 0*infinity raises invalid even with quiet
NaN addend. Neg/abs/copysign are bitwise and do not quiet or signal. Exact zero
retains common effective operand sign; cancellation yields -0 under downward.
Minimum/maximum propagate NaNs; minimumnum/maximumnum choose a numeric operand if
exactly one input is NaN. Minnum/maxnum choose that permitted numerical refinement.
-0 orders below +0. Ordered/unordered fcmp predicates follow the explicit closed
predicate set; signaling comparison raises invalid for any NaN, quiet comparison
only for signaling NaN. Vector FP accumulates lane status before result commitment.

FP->integer truncates toward zero; constrained fptosi/fptoui require that mode.
NaN/out-of-range gives poison plus invalid status; finite discarded fraction gives
inexact. Saturating variants clamp at signed/unsigned endpoints, NaN->0, with no
observable flags. Integer->FP and format conversions honor selected rounding.

FP lrint/llrint/lround/llround helpers are single source operations, not a
constrained rint+fptosi sequence. Lrint uses selected rounding and raises inexact
only for changed valid results; lround uses nearest-away and never inexact.
NaN/infinity/out-of-range returns concrete0 (selected freeze refinement) and
invalid WITHOUT intermediate inexact. Flags merge once before result/diagnostic.
Integer-power helper uses full signed exponent magnitude, including MIN, and
sequence-rounded selected multiply/square steps; omit unchosen products and the
unused final square. Negative exponent performs one final reciprocal; exponent0
returns exact1 with no FP arithmetic, even for signaling NaN base. Collect only
executed flags and commit once. This differs from correctly-rounded real pow.
At the LLVM pin constrained_powi exponent is fixedi32; ordinary powi is anyint.
Applicable libm helpers accept scalar/fixed-vector floating_value for llvm_default
and constrained; preserve lane poison and union all actual lane flags before one
whole-result/diagnostic frontier. Ldexp/scalbln exponent vector counts match; powi
has one shared scalar exponent. Four integer-round helpers and fixedi32-result
frexp/ilogb remain scalar. Source c_fenv libm remains scalar, avoiding invented
vector errno aggregation. Actual transcendental implementations require later
runtime qualification; reference integer-power/round witnesses do not prove them.

INT-D009 source fenv is six sticky bits: divide_by_zero1, inexact2, invalid4,
overflow8, underflow16, denormal32. DENORM is explicit sticky state only: arithmetic
never generates it and it is not a VM diagnostic. Ambient round codes are
nearest_even0/downward0x400/upward0x800/toward_zero0xc00; nearest_away is per-op only.
The source snapshot is32B/alignment8: revision:u32=1,round:u32,flags:u32,traps:u32=0,
control:u64=0,reserved:u64=0. Femode is16B/alignment8: round,traps,control.
Fexcept is u32. Default environments are readonly guest objects
`__rax_default_fenv`/`__rax_default_femode` with ordinary relocation/provenance;
there is no host pointer sentinel. Source APIs preserve VM diagnostic policy.

Fenv get/set copy snapshots, never authority. Pack gives raw256; unpack yields
(snapshot, i1valid), with invalid input -> poison snapshot,false and no environment
mutation. Setenv/setmode/selected flag restore/C23 setexcept do not raise; updateenv
restores then raises prior current flags; hold saves/clears source flags only.
Unselected fesetexceptflag flags are preserved by this PROJECT contract. Pinned
LLVM-libc implementation clears them: a verified source-logic difference whose
ISO conformance classification is unknown without the relevant primary ISO text.
It requires an explicit portable adapter, not host fenv_t reuse.

### Floating point as implemented

The interpreter in `crates/smir-portable` executes binary32 and binary64 in
the default environment: every arithmetic, comparison and conversion operation
above except the `fenv_*` operations and the libm helpers. An operation in a
constrained environment, and a value of binary16, bfloat16 or binary128, is
valid and is refused as unimplemented when the module is loaded.

Finite results come from the host's correctly rounded binary32 and binary64
arithmetic, which is the same on every supported host. NaN results do not:
they are chosen from the operand bit patterns by the rule above, so they are
identical everywhere too. The interpreter's differential test compares each
operation with the reference machine, bit for bit, on about nine thousand
operand combinations that include zeros, infinities, subnormals, quiet and
signaling NaNs with payloads, and the limits of the integer types.

## Exceptions, cleanups and nonlocal operations

EXEC-007: Section8 regions form a bounded parent forest. Child block membership
is a subset of parent; overlapping memberships form an ancestor chain. Handler
IDs are function-unique; ordered typed handlers precede at most one catch-all.
Matching/adjustment/RTTI/copy and foreign descriptors are ABI-admitted metadata.
The simple reference's default matcher implements exact nominal identity;
base-class/foreign matching needs the explicit admitted matcher adapter.

Handler.id is a function-local control identity; handler.selector is a distinct
semantic i32 code in1..0x7fffffff for typed and catch-all handlers. Landingpad
returns that selector, never the handler ID; cleanup/no-match returns0. The mapping
is function-local. Equal admitted canonical RTTI catch types share a selector
across regions, and distinct types/catch-all keys cannot collide. Catch-all is one
separate null-RTTI key. Every typed entry must pass reflexive ABI catch normalization
before pairwise consistency checks, including a function with just one handler.
The frontend adjusts arrays/functions and strips catch references; the ABI
comparator ignores only top-level cv, preserving pointee cv, C++ builtin identity,
library cohort and private ownership. Execution shape or numeric references do
not establish caught-type equality. RootContext snapshots actual ABI
catch_compatible and verified consumer declaration aliases into the reference
Dependencies.nominal_equal callback; missing comparison authority rejects.

LLVM eh.typeid.for remains symbolic through optimization/inlining/LTO, then maps
through the same actual per-final-function table before serialization. Replacing
it with an integer before inlining could merge unrelated caller/callee selectors.
Legacy filters have negative selectors; the private C++23 baseline rejects them
as E-EH-FILTER before emission, with no silently invented positive mapping.
Handler IDs remain the runtime catch/unwind context references. Selector values
are never alpha-renamed during content/COMDAT comparison.

```text
invoke PRE -> global search (no cleanup effects) -> selected handler
                     |                                  |
                no handler                         cleanup cursor
                     |                                  |
               termination                    typed unwind edge commit
```

An execution action names separate ABI cleanup_program and adapter_recipe refs.
Its captures biject recipe formal IDs and match nominal.execution types. Ordinary
SSA captures dominate every possible trigger's PRE frontier. Injected exception
is the same live admitted lease. Injected journal is an exact activation/action/
formal live instance binding; matching program alone never selects/mints an
instance. Program.params is a separate captured environment, independent of the
source owner's call_signature and action recipe formals. Count_source uses its
explicit unsigned nominalu64 noundef capture. Nested class arrays use separate
child journal instances parented by (journal,slot,element), preserving partial
constructor prefixes and reverse completion order without duplicate destruction.

Search reads inner-to-outer regions/frames before cleanup. The chosen handler's
cleanup path may differ from full region exit. The cursor, typed captures, journal
and leases survive suspension. Cleanup throw terminates; normal action results
are retained in selected catch context for admitted catch helpers. Do not emit a
second copy of those effects in landingpad CFG. Catch copy and conversions must
finish before caller normal/result publication; foreign RETURNED is only the
conversion-input frontier. Resume after conversion/cleanup suspension does not
re-enter native code or redo completed prefixes. Bare rethrow preserves the
process payload identity and its captured handler policy; a new logical
dispatch facade never retags an old thread's authority. Resume preserves the
existing unwind cursor rather than starting another throw. Native DWARF/SEH/
forced-unwind implementation is a subsequent gate.

Alloca/lifetime/stack save-restore/TLS/va*/setjmp/longjmp are explicit fixed helper
calls with actual section6 catalog version/hash/options and exact section10
bindings where required. No architectural stack pointer or host va_list is reused.
Longjmp restores only an admitted live owner/thread checkpoint; destructors are
not inferred. The runtime/ABI protocol defines invalid nonlocal crossing and
resource/trap outcomes. Helper names, parameters, cancellation/blocking/reentry,
leases and commit points are the exact [catalog](schema/runtime/helpers-v1.json),
not an open attribute bag or undocumented default.
The source association is checked even for an unused import. Namespace existence,
execution signature equality and equal allocation size do not establish its role.
INT032 fixes the following source meanings; exact declarations/layouts are in
[the ABI contract](03-abi.md), independently of the dynamic registry association:

| Helper names | Required original-owner source nominal | Retained dynamic association |
|---|---|---|
| atomic_flag_test/test_and_set/clear | atomic_flag kind, 1 B/A1, checked Raw8 execution | live address/view, state encoding, order/scope and shared backing |
| tls_address | complete whole TLS object, actual target nominal compatible ignoring only top cv | registered start offset, object extent, TLS/module generation |
| guard_acquire/release/abort and TLS variants | declared initialized variable, including complete arrays and reference cells | actual guard object, variable cell/type, owner/module generation |
| va_start/va_copy/va_end | canonical c23 array1 of rax.va_state | original variadic owner, arena/table lease, cookie/cursor |
| va_arg | requested promoted complete source object, actual nominal.execution equivalent to Type0 | actual header type, permitted value exceptions, bounds/padding and cursor commit |
| setjmp_capture/longjmp_restore, both contracts | canonical c23 array1 of rax.jmp_state | original process/thread/activation/checkpoint generation |
| eh_allocate | normalized complete payload object with c23 or cpp23 identity and actual allocation/execution | exact bytes/alignment, construction/destruction, module/lease ownership |

Both reserved state records occupy 32 B/A8, with execution Array32<Raw8>;
their source array-one wrappers use Array1<Array32<Raw8>>. An opaque execution
va_list value does not replace source wrapper storage. Reserved builtin-only
C++ frontend normalization to these c23 graphs is explicit; ordinary C++ source
traits and identities remain their actual declaration facts. A guarded reference
uses its 8 B/A8 DataPtr64 reference cell, retains the actual reference category
and original referent (which may be incomplete), and does not use the referent's
sizeof or the independent guard object's identity as a substitute.

Source default promotions precede va_arg packing/selection. Ordinary _BitInt(N)
retains N and signedness; a declared _BitInt(N):M bitfield yields declared N,
not M or an int32 width heuristic. C++ bit-precise syntax requires the explicitly
enabled extension mode. EH normalization removes top cv and decays array/function
expressions; it does not impose cpp23 on a C-defined payload identity. Source
constructibility, access/abstract/destructor checks remain frontend obligations
plus actual admitted typed recipes, rather than inferences from raw object bytes.
Missing local source metadata, unresolved provider evidence and a malformed known
source kind retain distinct outcomes. Expected consumer graph facts preserve the
original dependency reference as a future provider obligation; they do not certify
the selected provider's layout. No static source-role check issues a live grant.
Core longjmp is the last operation before unreachable and has no ordinary normal
completion; the runtime restores an admitted checkpoint continuation. A generic
reference callback returning normally is a contract violation, not nonlocal proof.
The same rule applies to every catalog helper with completion=raises/nonlocal:
neither immediate return nor normal completion of a pending ticket may publish
ordinary results or advance the normal continuation.
The R023 checkpoint witness remains separate from Machine callback plumbing.
LLVM threadlocal_address uses tls_address_raw, a pure pre-reserved logical-thread
slot lookup with no allocation/initialization/guest exception. C++ dynamic TLS
initialization is an explicit tls_initialize call/invoke. The older high-level
core tls_address binding is explicit and cannot replace this pure intrinsic.

TLS target references use distinct namespaces: SELF names a local TLS segment;
DEP(slot,declaration) names a consumer symbol declaration with symbol_kind=tls.
The admitted deployment and definition-selection plans resolve the latter to an
actual provider TLS symbol and its provider-private segment. Equal numeric IDs
in data, symbol, segment or consumer tables never imply this relationship.
Metadata retains the provider context and its SELF type/layout/storage references.
RootContext.install_external_tls accepts only the actual runtime Registry plus its
privately issued External binding, after all contexts' ABI checks and before
execution verification. Every use rechecks consumer identity/reference, pinned
provider generation and both snapshots. A metadata view grants no address.
All-module semantic/runtime admission and all registered-thread TLS reservations
precede publication. During initialization, access requires the runtime-issued
private cohort authorization. The owner may derive it for an actual source-created
thread or captured typed callback after reservation and checked entry; a claimed
thread number or public module-name lookup cannot derive it. An artificial
published state cannot substitute for that authorization. The raw getter uses the current logical thread's
reserved slot even after a host-worker change, without running an initializer.
Object extent facts on the returned pointer are not LLVM inrange restrictions.
The original source initializer call/invoke and weak-absence behavior remain in
order. A dedicated frontend may explicitly select tls_initialize for that route;
post-link lowering cannot add an effectful call to the pure raw intrinsic.

Core journal names cleanup_program and exact journal_advance contract: three
operands(journal,slot:u32,element:u64), zero results, action exactly construct_begin,
construct_commit,destroy_begin,destroy_commit,ownership_transfer,retain,release.
It changes state/leases only; constructors/destructors are separate admitted calls.
Catch helpers are exactly eh_begin_catch/eh_end_catch and require selected live
handler context. Both catch and journal use ordinary effect tickets when parked,
retaining the same frontier without replay. No static program ID selects a live
journal instance. Completed object lifetimes become process-owned certificates;
later destruction claims a fresh journal seeded from current child/union/count
state, without retagging historical constructor events or requiring user transfer.

journal_begin(object,captures...) has explicit construction/resume contracts.
Its metadata placeholder expands the selected SELF cleanup_program.params in
declaration order through actual nominal.execution references into one fixed
portable signature with false-noundef captures. Formal IDs need not be numerically
ordered. Missing capture evidence differs from an actual zero-formal empty list;
neither source varargs nor equal numeric type IDs can substitute for this graph.

journal_detach consumes the activation-local J and persists a process-owned
partial builder before await_suspend or any coroutine-handle publication: a peer
may resume before await_suspend returns. Resumption, synchronous false return and
cleanup claim fresh J identities with exact thread/activation/generation/instance
owners. Completed child certificates transfer through journal_adopt_child without
copying bytes or fabricating constructor events. Builder-local completion ordinals
span resumer threads independently of their event clocks. Current child ownership
is distinct from historical completion; an ended child cannot be revived by a
saved checkpoint. Publication transfers current children to the completed parent
certificate without inventing a parent constructor. Partial cleanup reverses
only current completed children and never invokes an unconstructed parent destructor.

Process capture environments preserve actual formal values/counts and pointer/
raw range/origin identities. They reject all present exception/journal/stack_mark/
va_list components; fenv snapshots remain value copies. Capture metadata does not
extend a source pointee's lifetime. Detach requires no outstanding effect or real
constructing child. If an owned child-constructor invoke unwinds, fail_partial
uses the actual current exception, failed ticket, old issued J and exact unwind
frontier to consume that J/ticket atomically and claim a fresh cleanup journal;
child-owned partial cleanup must already have completed and no other effect may
remain pending. Detached await_suspend failure uses its separate fresh claim.
These operations change metadata and leases; ordinary generated calls perform
constructors/destructors under their actual completion tickets. Snapshot IDs and
deserialized owner tuples cannot create any of these claims.

The compiler-private portable C++ profile carries E as an opaque SSA exception
value, including landingpad `{E,i32}`. Compiler constant-ID exception slots must
be eliminated to SSA/phis before all optimization/LTO/O0 emission; no ordinary
memory store, load, cast or sizing of E is permitted. Allocation carries the exact
qualified nominal T and source size/alignment before construction. The original
payload getter supplies the constructor address without a catch transition.
Constructor failure releases unconstructed storage after partial cleanup; even
trivial T needs an explicit initialization-complete certificate before raise.
The selected catch getter supplies the adjusted SOURCE pointer before catch-copy.
S026 performs the copy once into the original PRE-invoke captured destination;
the emitted source copy call is removed. It never returns that destination as
the adjusted source pointer or repeats the copy at begin_catch.

Source exception_ptr is an 8 B ordinary data_ptr field with alignment 8 B,
pointing to a registered process owner proxy, separate from payload/E/native
headers. Its immutable 32 B header
contains revision/reserved/proxyID/payloadID/generation; registry provenance,
generation, base, role and liveness grant authority, not those bytes alone.
current_owner retains once or returns null outside an active catch; null retain/
release are no-ops. Owner rethrow has no normal result, creates a current-thread
dispatch facade and exposes E only on the original invoke's unwind edge.

Source `throw;` uses an explicit no-argument runtime helper querying the logical
thread's ACTIVE catch stack, including calls from functions with no lexical E.
A propagation-only cleanup exception is not an active catch. With no active
catch, bare rethrow invokes source termination. Initial throw captures the current
process terminate handler; bare rethrow inherits the caught facade's snapshot;
exception_ptr owner rethrow captures the current process handler in its new
dependent facade. Explicit terminate chooses the top active caught snapshot,
otherwise the current global handler. Implicit termination first establishes a
catch of the causing exception; catch-copy failure's new exception is the cause.
The causing propagation leaves the uncaught count once; outer propagations stay.
Handler return/throw aborts without recursive dispatch. These rules follow the
pinned libc++abi sources in sources.json, not an uncaptured ISO classification.

Reference `Terminated(reason)` is a trusted owner adapter's terminal process-action
request, not a guest value, native handler execution or an OS abort. Only admitted
internal helpers with nonreturning completion or a declared terminate trap, and
cleanup actions, may produce it. Return-capable helpers retain their normal
continuation until an actual terminal outcome discards it. Pending terminal
completion is one-shot and publishes neither normal results nor an unwind edge;
cleanup results/cursors remain uncommitted. Value-only host callbacks cannot
supply this protocol outcome. The runtime-owned lifecycle witness supplies the
source handler/owner/count protocol independently of this control-transfer model.

Portable services have internal execution signatures, often multiple results and
noundeffalse, so service.abi isNone. Guest C/C++ wrappers have separate ordinary
source ABI descriptors. memory.map returns(status,data_ptr) with fresh provenance
from the same mapping ticket. Dynamic function/data lookup descriptors describe
the returned function/source object, not the service signature. Native guest
symbols are metadata-only image/CC/CFI views: no portable address_of/function_token;
an admitted foreign import and bridge supply the portable callable token.

Custom host imports are independently registered value-only application primitives,
not runtime service overrides. Canonical registered descriptor bytes contain the
actual execution graph and SMIR-HOST-V1 hash; file declarations cannot register a
host function. Arguments/results are scalar int/float/raw with no pointer origins;
false-noundef unknown bits freeze to zero while known bits remain. Host entry is
irrevocable, pending completes once, and arbitrary guest exceptions/handles/pointers
cannot be manufactured through callback result bits.

## Restricted constant initialization

Retained multi-symbol LLVM constant expressions cannot all be represented by a
single-base relocation. The runtime's constant-initializer records name ordinary
verified SELF functions and explicit physical result layouts. Their restricted
profile permits exactly constant, copy, freeze, i_add, i_sub, i_xor, i_mul, icmp,
select, extract, insert, extract_element, insert_element, shuffle, trunc, zext,
sext, bitcast, ptrtoint, ptrtoaddr, inttoptr, ptr_offset and address_of. It introduces
no additional instruction set. A program is portable, fixed, ABI=None, ()->[T],
result_noundef=[false], escape=propagate, no_return=false, with exactly one block,
no phis or EH actions/regions, and one returned value of the actual layout type.
Every present SSA value excludes exception/journal/stack_mark/va_list/fenv
components, including unused results. Code-signature edges are not containment;
zero-count arrays contain no child values. Calls, memory reads/writes, helpers,
environment effects, allocation, branches and loops reject this profile.

evaluate_initializer consumes an actual ABI/execution-checked RootContext, SELF
function/layout references and trusted selected runtime reservations. It rechecks
the snapshot and semantics, clones private object facts/shadow/exposure, executes
existing pure semantics and serializes the result through Memory.storage_bytes.
The result contains the typed Value, tuple of Raw8 bytes including poison/undef
and pointer-origin spans, and separate complete private data/code exposure sets.
It modifies neither caller memory nor public registries. Integer pointer guesses
create no origin: code ptrtoint exposes only the exact registered pointer including
its origin and generation; ptrtoaddr creates no exposure. Weak-null symbol absence
requires the runtime's actual issued binding proof, rather than a numeric zero
or a fabricated code-registry entry. Existing deterministic-zero freeze choices
are refinements; independent oracles use that choice or compare permitted
refinements with known bits and origins preserved.

The runtime verifies actual destination extent, selected whole-segment ownership,
nonoverlap, provider/source identity, generations, leases and current TLS thread.
It stages simple relocations before these programs, commits all new bytes/shadow/
origins/exposure together, seals final permissions, then runs the original source
initializers and publishes external entry. Private constant-evaluation failure
aborts before source constructors. Private Raw8 patches have
access alignment1B; layout alignment describes value allocation geometry and
does not impose an implicit aligned host store. An i65 result patches9B while
preserving7B tail padding in a16B allocation. Data programs run once per admission;
TLS programs run per reserved logical-thread instance, without ambient TLS capture
by data programs. Discarded owners cannot publish patches or exposure.
Discardability includes ordinary weak/common definitions and whole COMDAT groups.
Actual whole-segment selection precedes every static effect, including leaf-only
relocations. Missing images for discarded storage do not trigger evaluation or
exposure; no-symbol compiler-private storage remains retained. Independently
selectable aliases cannot claim different slices of one physical segment.
After static commit and before constructor completion, source-captured typed
pointers/callbacks and newly committed process exposures follow normal recovery
semantics under registered leases; unrelated public namespace entry stays closed.
A constructor may create/join a qualified child without waiting for publication.
Constructor failure closes new public entry and retains all escaped worker,
object, code, TLS, callback and exception leases until cleanup/quiescence; it does
not roll back constructor or child effects. Precommit constant-evaluation failure
publishes none of its private static bytes or exposures.

The default reference maximum is65536 operations and1MiB cumulative logical
working bytes: staged object bytes + ceil(width/8) for every SSA definition +
serialized output bytes. A separate100000-node budget includes reservation facts
and all present SSA components, including zero-width aggregates. Saturating
remaining-budget checks precede private cloning or any literal expansion. These
limits describe logical materialization and do not claim exact Python resident
memory. Failure returns a named resource diagnostic before publication. Work is
O(operations + integer/raw work + output bytes) after actual graph verification;
space is O(private facts + SSA materialization + output). Runtime transaction and
independent normalization witnesses remain separately required.

## Admission, resources and reference evidence

`RootContext` derives actual tables from sections1/2/3/4/6/8/10, calls the ABI
owner's verifier, then verifies execution. ABI shape views recompute child digests;
helper views retain real refs. Foreign native type/symbol/unwind evidence must
come from independent inspection/registered producer data, never from a declaration
read back as its own certificate. The component result explicitly still requires
runtime SCC/link/capability/data/TLS admission over all ten sections. A decoded
opaque envelope never reaches execution. The reference Machine re-verifies its
snapshot and preflights required import/dependency/cleanup/symbol adapters before
any guest operation. It executes test adapters, not arbitrary host function pointers.
Independent native evidence separately covers domain build/runtime/library/compiler,
exact compiled layouts/vptr slots, code entry/profile/physicalCC/packet role, unwind
and personality translation capabilities. One portable domain plus multiple foreign
build domains is permitted; all foreign domains share one selected ISA/personality.
Direct foreign-domain pairs require explicit portable hops; same ISA does not imply
C++ compatibility. Snapshot input mutation invalidates the context proof. Consumer
declarations supply static expected types only; definition APIs return actual local
definitions and execution requires bound provider/SCC registry objects.

Precise exits distinguish return, suspension, diagnostic trap, language_ub,
terminate and reference resource exhaustion. Completed effects survive a fault;
faulting results and invoke edges remain uncommitted. Activation/function/block/
operation identifies the frontier; phi entry position -1 is a reference API marker.
Fuel is charged per block entry/operation/terminator; exhaustion says nothing about
program termination. Current reference limits include8MiB record payload,100000
nodes/list elements,256 functions,1024 blocks/function,64 record/by-value nesting,
64Mibit materialized logical type extent and1MiB reference live memory. Vector
count65535 is its fixed-profile resource limit. Larger legal source objects/IR
need explicit resource diagnostics or semantics-preserving legalization; these
limits are not evidence of full hosted library/runtime capacity.
The reference admits at most1024 handlers/function. Selector admission uses at
most H^2 actual ABI comparisons, after reflexive normalization of each typed entry;
this is a reference resource policy, not the source selector namespace limit.
The 64Mibit/100000-value-node quota applies before concrete SSA materialization,
not to symbolic global storage metadata. A huge poison/undef aggregate can remain
unexpanded for a static field extract. Concrete zero/freeze/copy materialization
beyond the quota returns reference resource before allocating or publishing values.
Canonical live-before-frontier sets are computed from actual CFG/phi edges/invoke
edge definitions and PRE-invoke cleanup captures; reference pre-phi marker-1 is not
a runtime checkpoint position. Full restore requires a sealed single-use epoch
handoff in addition to typed value/registry checks.

For B blocks/E edges/V definitions, iterative bitset dominance takes at most B
refinement rounds, O(B*(B+E)*ceil(B/W)) word operations, space O(B^2/W+E+V).
The independent Rust witness instead removes a candidate dominator and searches
for a path to each use, O(V*(B+E)) for its tested graphs. Record codec is O(bytes+
nodes) with bounded depth. Type coinduction compares reachable node pairs;
partition refinement for shape hashing uses at most T splits over reachable type
nodes. Integer cost depends on width/bigint algorithms; rational FP cost depends
on significand/exponent size. No constant-time cryptographic claim is made.

| Assumption | Dependent result | Stress/falsification probe |
|---|---|---|
| S-A1 cross-role candidate decisions are the consumed revision | shared record bindings | merged-schema equality, wrong-table same-ID negatives, integrator decision readback |
| S-A2 deterministic zero is an allowed undef/freeze refinement | reference outcomes | repeated freeze use, poison control/divisor, component selection and sparse raw bits |
| S-A3 native probes are finite independent witnesses | FP32/64 evidence | exact boundary/subnormal/rounding comparisons; NaN result policy separately golden-tested |
| S-A4 native/registry metadata comes from independent trusted admission | foreign/live handles | producer self-certification, wrong generation/thread/program/stack/CFI must reject |
| S-A5 sequential oracle models one legal effect order | memory/atomics witness | runtime parallel/alias/SC tests separately required; never infer multicore behavior |
| S-A6 pinned source identity is stable | LLVM refinements/fenv differences | archive/live SHA-256 and exact revision check |
| S-A7 static CodeAddress/source-plan checks issue no runtime authority | function-address fixtures and ProgramFacts | actual sourceSome/bind Machine start refuses before stack/effects/token publication; genericNone still returns42 |
| S-A8 current corpus migration preserves semantic predicates | new revision counterparts | compare all547 historical names/expected outcomes, then independently run current Python/Rust predicates; old WIRE-REVISION controls do not count |

| Impact | Finding/opportunity | Gate implication |
|---|---|---|
| High | byte shadow must remain coupled to memory under aliases/atomics | actual parallel runtime implementation and qualification required |
| High | checkpoint/cleanup/foreign return progress must survive tier transitions | runtime/JIT/native C++ implementation remains later work |
| High | host tininess/NaN/fenv layouts can differ | direct host constrained FP requires correction and independent qualification |
| Medium | resource limits do not cover arbitrary hosted workloads | emitter legalization/resource diagnostics and larger-runtime testing |
| Medium | default exact nominal matcher is not general C++ catch matching | ABI matcher/native descriptor tests remain separate evidence |
| Low | SSA reference and Rust path-exclusion algorithms differ | useful independent verifier oracle; no complete Rust semantic engine claim |

Primary oracle: pinned LLVM revision36763294ef639d8a6a4379d81da653dda1c20686,
[LangRef](references/llvm-project/llvm/docs/LangRef.md), exact source identities in
[sources.json](schema/execution/sources.json); source license Apache-2.0 WITH
LLVM-exception. Fenv implementation sources and archive checksums are integrator
provenance entries. Project ABI/snapshot choices are identified as project
contracts, not attributed to an uncaptured ISO standard.

Focused validation: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools/smir-format/execution -p 'test_*.py' -v`.
Receipts identify current artifact hashes and finite-case counts. Production
portable interpretation, parallel workers, JIT, LLVM emission, hosted libraries
and native C++ interoperability are not established by these references.

## Original version 3 compiler context

The experimental Root3 revision 3 carrier is consumed by the actual Python
`RootContext.from_module(encoded, *, budget, independent=None)` constructor.
The constructor decodes all ten original roots, verifies the original module
content identity and preserves the complete embedded `source_contract`. It does
not project to revision 2. Revision 2 constructors and public body verification
retain their existing signatures, grammar digest and behavior.

One canonical `SourceQueryBudget` is bound to the original revision 3 owner.
`prepare_source_data`, source-call inspection, ABI factories, candidate-body
verification and public runtime source constraints retain that same ledger.
An equal-limit replacement budget rejects. Actual Types, Layouts and nominal
ABI graphs preserve this ledger through deep copies. Editable `abi_checked`
flags cannot replace the privately recorded original ABI verification receipt.

`verify_candidate_body(*, budget)` verifies ordinary CFG/SSA/types on a fresh
complete original-v3 clone using the real checked ABI, exact symbol/import/TLS
and nominal-comparison dependencies, and actual body predicates. Its frozen
`V3BodyChecks` retains the original owner/stamp and unchanged full-v3 `Verified`.
Its `executable`, `semantic_admission` and `active_v3_verified` fields are false;
it never sets `execution_checked`. The exact `source_journal_observe` record has a
fixed typed-body predicate and a separate finite source-constraint pass below.
`verify_execution` and source-registry issuance still reject revision 3
with `V3_SOURCE_SEMANTIC_ADMISSION_UNAVAILABLE` until source semantics close.

`verify_source_constraints(*, budget)` passes the exact embedded raw contract to
the actual runtime public checker. Replacement external metadata cannot stand in
for the original contract. This finite static relation retains its own explicit
source/CFG/lifetime deferrals and false authority fields. Runtime comparison is a
separately reviewed selected-function relation; this constructor issues no source
function identity. The runtime checker companion must be installed separately.

The initial factory profile is SELF-only and portable-domain-only. It limits
wire payloads to 1 MiB; plain trees to 8192 nodes, depth 64 and lists 256; text to
256 UTF-8 octets (hexadecimal payloads have separate byte bounds); physical types
64, nominal types 16, functions 4, blocks 64 and values 256. Actual function
parameters and physical Fn parameters/results are bounded by 16/8. Nominal
pointer/reference widths are 64 bits; scalar integers are at most 128 bits.
By-value physical graphs have at most 32768 bits and expanded value cost 8192;
raw values may reach 32768 bits, arrays 1024 elements, vectors 16 lanes and
structs 8 fields. Object/layout/storage/mask extents are at most 4096 B.

Source records are flat: at most eight scalar fields, no bases, vptrs,
dynamic/polymorphic records or virtual methods. Journals have at most 64 slots,
16 parameters and 1024 elements per slot; all individual and multiplied slot
extents are at most 4096 B. Parent/child/count-source/covers/dependency expansion
is unavailable. Native/foreign/DEP/bridges, recipes, exception regions, source
inheritance and independent native evidence are outside this cost profile.
The three admitted imports are internal journal_begin, journal_advance and
journal_publish_object; their original signatures/options/metadata still validate.
Outside-profile input reports an explicit resource/profile unavailability before
inherited factories; it does not become a malformed general C++ program.

Logical work, edges and copied payload bytes are charged before actual copies,
shifts, refinement, JSON processing, body allocations and helper validation.
Types/Layout and ABI graph kernels charge their real algorithms. Body loops and
native collections have per-visit and enclosing-length charges. The unchanged
`targets`/`uses` allocations and operation/source-plan shells are precharged on
actual node/container lengths. Internal helper validation reserves its actual
schema/catalog parse, canonical digest, namespace view and Journal capture work
before entering the original runtime predicates. These are explicit logical
accounting bounds; they are not a host instruction, processor-time or RSS proof.

The source-authored fixture and executable witnesses are in
[conformance/execution/root3-context](conformance/execution/root3-context/README.md).
They test original payload/stamp/ledger custody, the composed static path,
version 2 parity, finite boundaries and quota failure before actual factories.
They do not establish complete C23/C++23 lowering, portable execution or compiler
freeze. Assumptions C31..C35 and their falsification probes are recorded there.


## Static retained-Journal observer verification

The assigned version 3 operation is exactly
`{op:source_journal_observe,results:[decl],operands:[],scope_value:S,adoption:A}`.
It defines one ordinary SSA value of the actual existing Journal type. S and A
are distinct function-local source namespaces, with nonbool IDs0..4294967294;
they are not ordinary SSA operands. Ordinary result/type/block IDs retain their
existing full u32 domain, including4294967295. No architectural or host state
supplies missing inputs. The base revision2 operation schema remains unchanged.

The real ordinary verifier recognizes the closed version3 record through a fixed
private predicate, then enforces the same SSA definition/use/dominance/phi and
operation typing rules as other values. It returns `V3BodyChecks.observers` as an
immutable tuple of seven original coordinates: function, block, operation index,
result SSA, SELF physical type, ScopeValue and ReturnAdoption. These coordinates
are inspection; no Journal or source fact is created. The original owner/stamp/B
and complete unmodified functions root remain on the result. The source stamp
is checked after observer collection as well as ordinary validation.

The separate public runtime source checker calls this real typed-body pass on its
complete genuine fresh clone, then validates every actual embedded observer using
the same original ledger. It accepts no caller body receipt or external operation
report. The body pass never calls that checker, and the checker invokes only the
pure `prove_paths` helper rather than the full grounding API, preventing recursion.

The initial source profile has exactly one callee block containing only its
journal_begin operation and an ordinary return, and exactly one caller block
containing only the SELF direct call at index0, observer at index1, then ordinary
return. No prelude, extra block, intervening or following operation is supported.
It uses one legal INLINE partial-factory scope. The callee enters before its actual journal_begin, binds
the actual Journal SSA after that helper and exits retained at its real pointer-
only return. The Journal is a logical retained source association, not an extra
physical Fn result. The caller reserves a create receiver, adopts it once after
normal return, observes immediately as its last ordinary operation and closes its
scope at its own retained return. The actual program/view/class, source call plan,
callee return, receiver S and authoritative phase order must match exactly. No
source_object double bind or caller existing_object rebind is inserted.

During each abstract path, `prove_paths(...,source_observers=True)` checks the
actual observer S at PRE, after original pre_op phases and before result definition.
Undefined/stale captured aliases reject; a later slot cannot replace the saved S.
Default False refuses any observer instead of silently omitting its source use.
New preflight charges4work/1edge per block and operation in both modes; True also
charges8work/1edge/32copied bytes per visited observer lookup. Thus old semantic
rules remain while historical logical cost counts/quotas are not repinned.

This is static typed/body and finite source-association verification. Observation
has no Journal transition or constructor/destructor effect; its intended runtime
facade/epoch/actor/generation/lease checks are not implemented here. It may observe
failure and is not a no-op that an emitter may erase when its result is unused.
No new SourceScopeRef, JournalRef, lifetime or ownership is inferred. Full source
admission, source registry and the old reference Machine remain unavailable for
revision3. Existing Machine construction revalidates through the revision2 grammar
and rejects the actual full-v3 Verified result. There is no generic execution
fallback. R's separate joint alpha relation rewrites only the observer S/adoption
IDs with the source graph's same bijections, preserving ordinary SSA fields.

See [source-observer witnesses](conformance/execution/source-observer/README.md)
for actual positive/boundary/rejection inputs, quota evidence, assumptions and
limits. Rich receivers/lineages, epoch-changing consumers, invoke/EH, lifecycle,
full source-language legality, runtime facade issuance and compiler freeze remain
explicitly outside this finite package.

## Fault registry

[faults-v1.json](faults-v1.json) lists every fault the interpreter raises, with
its class and meaning. A run that does not return ends in one of three ways:

| Class | Meaning | Report |
|---|---|---|
| `trap` | Defined behaviour: the operation is specified to stop the program. | Code, function, block and operation |
| `language_ub` | The program executed undefined behaviour. An engine may stop, as the interpreter does; a conforming program never reaches it. | Code, function, block and operation |
| `resource` | A host limit was reached: steps, call depth or live memory. The program is not at fault. | Code only |

An explicit `trap` terminator reports its own reason token as a `trap`; those
tokens are chosen by the program and are not in the registry. The registry is
generated from the table in `crates/smir-portable/src/interp/faults.rs`, and a
test keeps the two identical. The interpreter's differential test requires
every fault raised by its corpus to be registered under the class it was
reported as, and lists the registered codes the corpus cannot raise.

The helper catalog does not say what a poison or undef size means for
`stack_alloc`, `lifetime_start` and `lifetime_end`. The interpreter refines an
undef size to zero and treats a poison size as undefined behaviour
(`ub_allocation_size`, `ub_lifetime_size`).
