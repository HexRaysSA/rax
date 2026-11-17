# Compiler-private lifetime notes

LLVM051 defines retained source ownership facts through optimization and coroutine
splitting. This compiler IR dialect is consumed before portable emission; it is
not an executable SMIR extension or a runtime admission token. Exact phase/record
shape is [lifetime-marker-contract.json](lifetime-marker-contract.json), checked by
life_markers.py. Qualification results live in external component receipts.

## Anchors and exact call grammar

Original source ownership uses INT011 source-unit UID (64 lowercase hexadecimal
digits). A program anchor is LLVM private constant `[N x i8]`, alignment1, containing
EXACT canonical ordered ABI `encode('cleanup_program',P)` bytes. Its named node is:

```
!smir.life.programs = !{!P, ...}
!P = !{i32 1, ptr @program_anchor, !"unitUID", i32 original_program_id}
```

The compiler checks actual immutable admitted source ABI/execution roots, not a
claimed hash/name. Decode/re-encode and compare referenced nominal/layout/code/
capture graphs. Original unit contexts remain distinct through LTO until final
qualified references are remapped; no source ID is mistaken for a target ID.
Retain program and source-fact anchors in `llvm.compiler.used` until consumption.
They are compiler-only; no guest address/token or serialized authority is issued.

Callee is reserved `__smir_life_v1.<UID>.<site>.<phase>`; site is u32 canonical
decimal. Direct ordinary declaration, no body/alias/ifunc/indirect use/address escape.
Every note has these EXACT attachments:

```
!smir.life !N, !smir.life.transports !T
!N = !{i32 1, ptr @program_anchor, i32 site, !"phase"}
!T = !{!Tcapture0, ...} ; empty except CAPTURED phases
```

All return LLVM void, fixed nonvariadic CC::C normalized portable. OBJECT prototype
is `(ptr AS0 object,i32 slot,i64 element)`; unused slot/element are literal0.
CAPTURED appends ordered actual program-formal transports; ADOPT appends child ptr;
FAIL appends `target("smir.exception")` actual current unwind E, never an E capture.

| Phase | Prototype | Exact lowering/proof boundary |
|---|---|---|
| object.begin | CAPTURED | journal_begin construction, actual object/env |
| construct.begin | OBJECT | journal_advance construct_begin slot/element |
| construct.commit | OBJECT | journal_advance construct_commit after normal ctor/trivial stores |
| adopt | ADOPT | journal_adopt_child actual current completed child |
| suspend.prepare | OBJECT | journal_detach before handle publication |
| resume | CAPTURED | journal_begin resume, fresh owner, exact stable saved env |
| publish | OBJECT | journal_publish_object after source init complete |
| partial.destroy | OBJECT | journal_claim_partial, current completed prefix only |
| fail | FAIL | journal_fail_partial, R042REV3 active-owned/detached frontier |
| object.destroy | OBJECT | journal_claim_destroy, saved process environment |
| slot.destroy.begin | OBJECT | journal_advance destroy_begin before actual destructor |
| slot.destroy.commit | OBJECT | journal_advance destroy_commit after actual cleanup outcome |
| object.done | OBJECT | source frontier complete assertion, no extra guest effect |

Destroy/partial/done/fail do not require constructor values still in SSA: the actual
certificate/Builder holds its environment. Slot phases use actual declared slot
and u64 element checked against dynamic counts. Begin follows argument evaluation,
immediately before actual constructor entry; commit follows actual successful
return (trivial typed initialization follows stores). A failure note uses actual
E/invoke/ticket/current owner after the child's own partial cleanup; R042REV3
consumes old J and issues fresh cleanup J without retagging. Final completed cleanup
retires the certificate under existing protocol; object.done cannot certify a
constructor/destructor that did not run.

## Typed source facts and transformation tracking

Each call has one `"smir.life.values"` operand bundle of ordered pairs:
`(ptr @fact, SAME actual LLVM Value)` for object, optional adopt child, CAPTURED
values, optional FAIL unwind E. Check Value OBJECT identity and LLVM type, not
spelling/type equality or a private numerical source ID.

Each fact anchor contains canonical compact ASCII JSON with sorted keys, no BOM:
`revision:1,unit:UID,ordinal:u32,kind:object|capture|code|unwind,execution:entity_ref,
nominal:opt:entity_ref,storage_binding:opt:entity_ref,code_signature:opt:entity_ref`.
References belong to ORIGINAL actual unit context. Capture nominal/execution match
actual ordered program formal; code signature matches actual code_ptr type; object
uses actual data pointer and source object/storage binding; unwind uses actual
invoke E provenance. Opaque LLVM ptr alone cannot prove any of these.

Metadata retains facts; it does not authenticate them. A compiler-private
`CompilerSourceFacts.bind(unit,LLVMValue,actualASTExpressionOrLValue,loweringResult,
actualContext)` independently checks actual typed source/IR lowering and issues a
private per-view fact. Generic bitcode needs independently validated source-fact
input or E-LIFE-SOURCE-VALUE; no name/hash/expected-formal fallback. The reference
SourceFacts model uses admitted original contexts and issued membership; production
AST checker is a later implementation, not inferred from the reference ledger.

Fact identity is original `(unit,ordinal,anchor)` plus note view. Distinct parent/
first-child/base/null data/code/function-signature views can share ONE LLVM Value.
Keep all facts; conflict only for SAME fact identity with a different descriptor
or invalid per-view remap. Do not demand unrelated nominal views compatible.

Clone/import/CoroSplit use actual LLVM ValueToValueMap and original-unit descriptor
transfer. Ordinary InstCombine/SROA/folding need not export such a map: own
CallbackVH per tracked Value. RAUW callback records actual old/new Value, retargets
with setValPtr(new), and queues per-view transport/source checks until pass complete;
union views at merges. Rematerialized constants need actual RAUW or a checked
frontend rewrite, not matching bits/name. Deletion fails with surviving note use;
otherwise remove stale membership. Recheck pair identity/anchors/source snapshots
at every relevant pass boundary using PassInstrumentation. Unknown lost mapping
fails before output. These hooks are specified in pinned ValueHandle.h/Value.cpp/
PassInstrumentation.h; generic LLVM defaults do not implement the source checker.

## Stable capture transport

EVERY process-safe typed capture is frozen ONCE before first object.begin using
S062 recursive freeze. Preserve known bits/origins; unknown/poison ordinary values
select one defined allowed value. Pointer freeze creates no authority. Present
E/J/stack_mark/VM va_list handles are excluded; copyable fenv is allowed. An undef
SSA can differ per use, so SAME unfrozen SSA does not satisfy saved-env equality.

Encode the SAME defined stable value once, then persist/reuse that SAME transport
for every resume. Never re-freeze per note. Direct transports: iN, bN, IEEE LLVM
FP type, AS0 ptr with actual source/code facts. Captures are logical SSA, not native
byval/sret/coercions.

Here AS0 code facts refer to the existing checked internal CodePtr capture profile,
not a reinterpretation of every source function address. The new source CodeAddress
carrier is AS1; neither AS0 spelling nor AS1 alone supplies a code signature or
authority. This allocation does not broaden the legacy note/source-fact profile,
and B/S compiler-only SSA values remain forbidden ordinary captures. A producer
must use the actual accepted source/type transport contract for a represented
capture, or diagnose; it cannot cast away a required source domain to fit this
legacy profile.

Canonical recursive transport nodes are:

```
scalar/int/raw/FP/data/code: !{!"direct"}
fenv:                     !{!"fenv_bytes32"}
struct:                   !{!"struct",!Tfield0,...}
array/vector count>0:     !{!"array"|!"vector",i64 count,!Telement}
array count0:             !{!"empty_array"}
```

Every present fenv leaf becomes `[32 x i8]`; structs/arrays recurse. A logical vector
whose transported element is not an LLVM vector element uses an array transport,
then reconstructs lanes. Empty array is `[0 x i8]`, with no leaf codec invocation.
Private producer `[32 x i8] @__smir_life_fenv_freeze_pack_v1(target("smir.fenv"))
nounwind` is consumed into EXISTING typed freeze(F) then fenv_pack(Fstable) and byte
construction. S062 gives poison/undef fenv a valid default snapshot, known valid F
unchanged. Never read current resumer fenv. Begin/resume decode identical concrete
bytes, so actual Builder saved capture equality holds. Raw fenv_unpack keeps its
existing nontrapping `(poison,false)` invalid-data behavior; no eager trap is added
for a discarded poison capture. Metadata/frame corruption and actual source value
observation remain independently checked. No new guest opcode/import/site format.

## Attributes, sequencing and final consumption

Producer declarations/notes have no noundef/nonnull/align/dereferenceable/byval/sret/
returned/noalias parameter promises. nounwind required; nocallback/noinline allowed.
Default all-memory effects prevent deletion/speculation/store reordering. Never
readnone/readonly/argmemonly/speculatable/nosync/willreturn/noreturn. An actual
verified optimizer may add proven VALUE promises at a callsite; audit compares
actual operands, then strips those optional promises before consumption. ABI-changing
attributes or effect weakening remain errors. Source declaration prototypes stay
exact. Markers are semantic barriers, never debug-only annotations.

Suspend prepare follows coro.save and PRECEDES await_suspend/handle publication.
Ready=true never detaches; boolfalse and real resume take dedicated fresh-resume
edges; throwing await_suspend uses actual FAIL; symmetric transfer detaches before
tail dispatch. No constructing child or in-flight effect may detach. CoroSplit
replaces save with state store; peer/inline resume can precede await_suspend return.
Do not affect a separate caller activation's journals.

Validate before optimization/import (O0 too), after relevant LTO/clone/pass
boundaries and after final Split. Source site may clone only preserving dynamic
effects/order/captures; static site is not a runtime effect ticket. After FINAL
Split/final source CFG optimization consume into local SSA journal/factory/typed
ABI/EH operations. No J/E frame storage; no later unverified Split/optimization
may spill branded state. Before serialization sweep ACTUAL LLVM module/compiler
artifact ledger for residual note/transport functions, calls, program/fact anchors,
compiler.used entries and smir.life metadata; reject E-LIFE-RESIDUAL. Empty reference
projection is not a whole-module admission token. Debug/source names grant nothing.

## Witness coverage and limits

life_marker_witness.py checks actual admitted source graphs,8 positive notes,
10 strategic rejection cases, residual/missing-map/deletion guards, two distinct
source views sharing one Value/RAUW, two-formal OBJECT-only external destroy,
recursive snapshots/empty arrays and typed capture freeze. It additionally uses
actual10-root codecs/RootContext/live-value validation/runtime Builder to freeze
undef/poison int+pointer before begin/detach/resume on two logical thread IDs;
unprotected unknown-to-concrete environments reject, stabilized environments match.

The source fixture is compiled at O2 with optimization DISABLED only to expose
initial presplit IR without optnone. The fixture producer attaches exact metadata,
program/fact byte anchors, real operand bundles and stable capture SSA. Actual pin
then runs O0/O2/full/Thin PRELINK pipelines. Inspector checks declaration prototypes/
attrs, canonical anchor bytes, per-call phase nodes and SAME actual typed SSA pairs;
ordinary O2 optimizes functions and retains the semantic notes. Thin prelink remains
presplit; actual O0/O2/full prelink contains the marked function's resume definition.
Source fixture uses comparable existing-target int/object geometry, not smir64.
Postlink LLVM24, general AST producer, production fact tracker/emitter and universal
optimizer equivalence are not proven. Source/command/byte hashes and observed
positive/rejection counts belong to current external validation receipts.
