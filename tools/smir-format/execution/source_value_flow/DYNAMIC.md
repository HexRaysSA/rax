# Actual-core dynamic event reference, UNBOUND

This implementation executes the actual copied generic `candidate.machine.Machine`
and `candidate.pure.execute`. It captures the actual completed result, phi incoming
births and scalar-select materialization inside those operations. It does not infer
selection from equal values, rerun operations, or manufacture source facts. The
accepted interface is SEM DYNAMIC-EVENT-01 with mandatory amendments02..05; named
Root/ABI/Runtime/LLVM receipts are in the coordination accepted-interface.json.
Mandatory local amendment06 closes partial-computation host failure through the original sticky terminal exception, as explicitly requested by Root. There is no shared implementation release or public wire/profile ID allocation.

`UnboundFlowRuntime(owner,assertion_bytes,*,parameter_masks,limits,budget)` rechecks
the actual RootContext ABI/body and closed SVA assertion. `parameter_masks` is an
exact tuple of `(actual_parameter_ssa_id,model_mask)` in original parameter order;
mask bit1 denotes MODEL initialized. All parameters require explicit entries.
`Limits(max_events,max_births,max_serial)` contains positive exact integers:
events/births <=2^32-1; serial <=2^64-1. Canonical budget and limits properties are
read-only. `Machine.attach_unbound_value_flow(runtime,*,budget)` requires that same
canonical ledger, exact actual classes/original roots and a fresh unattached core.
Source-registry attachment is mutually exclusive.

The finite body admits scalar Raw8 and Int1/8/64, constants, copy, equal-width
bitcast, freeze, scalar select, i_sub, icmp, phis, jump/cbranch/return. Whole-body
unsupported operations/types refuse before attachment/start. Each dispatch checks
the current frame/generation/activation/frontier, original RootContext snapshot and
actual Machine body against that original. Every current SSA binding must also have the same actual Value object as its recorded current birth, including exact definition/frame/generation/activation/epoch. Entire live binding coverage is checked before dispatch, retained resume and publication; an in-place replacement cannot borrow an old mask. For phi, event input values come from the actual completed snapshot outputs and must match their selected incoming births. Identical immutable Value objects may still belong to different SSA births. A nonblocking dispatch lock prevents
simultaneous or recursive dispatch of this single Machine; this is not a parallel
runtime implementation.

Private-reference grammar, held only in the runtime membership tables:

```
EntryReservation := {machine,function,arguments:ActualValueTuple,
 expected_activation:u64,generation:Identity,epoch:u64,definitions:ActualDeclTuple,
 capacity:Capacity,stage:reserved|completed,frame?:ActualFrame}
Reservation := {machine,frame,activation:u64,generation:Identity,epoch:u64,
 frontier:(block:u32,position:i64),kind:Kind,node:ActualNode,
 definitions:ActualDeclTuple,input_ids:Tuple<u32>,inputs:Tuple<Birth>,
 values:ActualValueTuple,selection:None|Selection,capacity:Capacity,
 stage:reserved|completed}
Event := {machine,frame,generation:Identity,epoch:u64,kind:Kind,
 inputs:Tuple<Birth>,input_values:ActualValueTuple,outputs:ActualValueTuple,
 definitions:ActualDeclTuple,births:Tuple<(Birth,BirthRecord)>,
 predecessor:None|u32,selection:None|Selection,frontier:None|(u32,i64),
 first_serial:None|u64,capacity:Capacity,
 stage:completed|parked|resumable|published}
BirthRecord := {machine,frame,activation:u64,generation:Identity,epoch:u64,
 serial:u64,definition:u32,coordinate:Coordinate,value:ActualValue,
 mask:u64,kind:Kind}
Coordinate := {parameter:u32}|{block:u32,phi_result:u32}
            |{block:u32,operation:u32,result:u32}
Selection := (actual_original_condition,actual_once_materialized_condition,
              original_operand_index:1|2,actual_selected_input_birth)
Capacity := {values_in:u32,births_in:u32,values_out:u32,births_out:u32,events:1}
Kind := parameters|phi_batch|ordinary|noop|select|freeze|literal|numeric_to_byte
```

Entry has argument-count values_in and zero births_in; each ordinary operand has
one actual input birth. Phi inputs are the actual predecessor-selected operands,
snapshotted before any result replacement. All outputs receive successive new
activation-local serials; static IDs and immutable value identities never identify
a dynamic birth. Zero-output batches still emit one event, first_serial=None, with
no serial advance/exhaustion. No wrapping or partial serial allocation is allowed.

Preparation charges the SAME ledger before frame allocation/activation increment,
operation computation, phi snapshot or birth/event publication. With n input values
and m output values its finite model policy charges work=512+128(n+m),
edges=16+8(n+m), copied_bytes=1024+512(n+m). These are reference-policy accounting
units, not a measured allocator or complete delegated-factory bound. Tables also
check event, birth and entire output-serial capacity before computation. Existing
legacy factories/snapshot encoders are not completely metered; full factory cost
qualification remains false. Host allocation failure is not a canonical quota
success guarantee. No canonical budget charge occurs after actual completion.

Model transfer is exact: copy/equal-width bitcast/freeze preserve the mask;
phi/select copy the actual chosen input birth mask; fully defined constants receive
a full-width mask, others zero. Integer i_sub and icmp receive full-width masks iff
all input masks are full, otherwise zero, including self comparison. Int8-to-Raw8
requires BOTH mask255 and an actual fully defined Int8 before pure execution.
The actual originless conversion is retained. A poison select condition refuses
before materialization, reservation, computation, step/PC/serial changes. An undef
condition is materialized by the actual scalar-select branch exactly once. Raw
freeze may change physical poison/undef masks to defined while retaining its input
MODEL mask. Core undef refinement does not establish source initialization.

`request_park_after_next_completion(kind)` parks an actual completed event before
core definitions, sidecars, serials and PC publication. `resume_completed(event,
*,budget)` accepts only that same retained event, epoch, frame, activation, frontier
and original ledger. The Machine also retains the actual output tuple/map before event bookkeeping. A bookkeeping failure retries completion from those same outputs, including when no Event exists yet; it never reexecutes the core operation. Actual select/phi/freeze MemoryError injection controls verify this boundary. The next run publishes it once, even with fuel0, without
recomputation, reselection, reservation or additional step. Repeated parked run
returns the same event; duplicate/foreign/forged/stale references reject. Expiration
invalidates existing references; cancellation/reclamation are not implemented.

If a host exception propagates during actual pure computation, phi selection or control transfer BEFORE a complete actual output tuple/map is retained, the Machine stores that same original exception as terminal. Every subsequent run, including fuel0, raises it without another evaluator/materializer/phi/branch call, step, reservation or publication. This terminal state cannot be reset. A partially advanced control transfer is not rolled back; no later guest progress occurs. Metadata failure AFTER actual output retention remains recoverable through those same outputs. Actual original-function-then-MemoryError controls cover select, incoming phi ordinals1/2/3, freeze, and control branch. Existing guest traps keep the original finished outcome. No hard allocator atomicity guarantee is inferred.

Run from tools/smir-format/execution with a fresh absent PYTHONPYCACHEPREFIX,
PYTHONDONTWRITEBYTECODE=1 and `python3 -B -m unittest
 test_candidate_source_value_flow_dynamic -v` (34 tests). The standalone
`source_value_flow/dynamic_witness.py --check` reproduces five byte-exact actual-core
witnesses. Qualification additionally runs existing115 tests and five fixture groups
under normal and optimized processes, recording actual process flags and every
consumed source digest. A separate qualified snapshot and exact shared-base delta
are delivered; developer logs are historical and are not qualification receipts.

Assumption register:

- D1: actual core result/selection is the oracle. Probe actual materialize spy,
  undef once, poison refusal, identical operand objects and changed-body rejection.
- D2: current births follow dynamic activation-local serials. Probe parallel phi
  swap, reused IDs/objects, original parameter IDs, zero batches, serial exhaustion,
  stale epoch/activation/frontier/map and foreign membership rejection.
- D3: planned canonical capacity fails before publication. Probe exact/one-less
  each budget axis, whole-phi capacity, unchanged activation/steps/maps, original
  resource exception identity, and every supported retained completion class.
- D4: MODEL masks are unbound public assumptions. All source/category/body
  equivalence/admission/runtime/full-cost authority remains false. No genuine
  SourceValueInitRef, SourceNumericUseRef or source-language facts are issued.

High-impact gaps: genuine frontend/body/source-init/source-operation receipts and
source ABI2 admission; full delegated costs; complete hostile host mutation and hard
allocation atomicity. Medium: actual parallel memory/runtime, calls/EH/environment,
source varargs/coroutines/widerRaw/C23 laws, cancellation. Low: the finite event
mechanism may be integrated after a separate exact Root ownership release. No native
SMIR execution, JIT, LLVM emission or hosted-library capability is established.
