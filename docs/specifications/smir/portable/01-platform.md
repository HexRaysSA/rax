# Platform and compatibility

PLAT-001: `portable64-v1` is independent of container, host ISA, host OS,
personality, foreign ISA, compiler version and internal Rust enum layout.
The compiler target is `smir64-unknown-rax`. Personality selection is explicit;
a carrier never changes ABI or infers a personality.

PLAT-002: Version encoding, semantics, runtime imports and foreign ABI profiles
independently. Never reuse published IDs. Unknown required semantics fail before
execution. Optional records may be skipped only in a nonsemantic namespace.
An implementation bug does not change specified behavior. A change to defined
behavior requires a new semantic profile or incompatible version.

The experimental candidate currently uses these independent revisions:

| Surface | Required revision |
|---|---|
| Envelope | 0.2 |
| Semantic profile | 2 |
| Payload roots 1, 2, 3, 5 | 2 |
| Payload roots 4, 6, 7, 8, 9 | 1 |
| ABI payload root 10 | 3 |
| Live-state payload (separate from object root 8) | 2 |
| Record layout input within ABI root 10 | 1 |

The raw leading `u32` payload revision is checked before schema-dependent fields.
An incompatible old root yields `WIRE-REVISION` without an inferred upgrade. Nominal source
identity uses the `SMIR-NOMINAL-SHAPE-V3` hash domain; this is distinct from content
identity, execution type identity and physical call-site identity. Earlier ABI
revision 1 and 2 bytes remain historical test inputs, not accepted revision 3 objects.

The unqualified ABI revision 3 contract retains the required
`vptr_layout.component_order`, appended after its six existing fields. It records
the physical interleaving of `vcall` and `vbase` components; missing order is never
inferred by concatenating the two value vectors. Earlier ABI2 schema snapshots
remain historical. This revision remains a migrating compiler contract until a
new exact candidate and all independent witnesses qualify together. Revision 3
adds mandatory `call_signature.execution`; source function pointer values use
the unparameterized 8 B, 8 B-aligned `CodeAddress` execution representation.
Root 3 revision 2 appends mandatory syntax `source_plan:opt:entity_ref` to call,
invoke and tailcall. `None` preserves a generic typed call; `Some` names the
actual caller's ordinary source plan. The retained pointer binding cannot supply
this call-site plan. These records do not grant runtime entry authority.

PLAT-003: Preserve source/ABI provenance separately from semantic identity.
Native caches are disposable and never define portable program semantics.
Optimization, register allocation, Rust layouts and cache formats are private.

PLAT-004: Program bytes must decode into an unverified representation, then pass
structural/type/control-flow verification, linking and capability admission.
Only an admitted instance can enter an execution engine. Unknown operations
cannot become an interpreter fallback when their semantics are unavailable.

## Intended API separation

```text
0.1 bytes -> DecodedEnvelope (opaque legacy framing)
0.2 bytes -> DecodedCandidateEnvelope -> UnverifiedCandidateModule
                                                   |
                                             VerifiedModule
                                                   |
                                             linked instance
                                                   |
                                             admitted process
                                              /           \
                                       interpreter        JIT
```

The two framing types exist in Rust. The Python reference codec exposes an
unverified candidate payload wrapper. The separate experimental
`crates/smir-portable` Rust crate also decodes all ten roots and can issue a private
`VerifiedObject` only for its explicitly audited static subset. That object retains
unresolved runtime requirements; it is not the linked or admitted instance shown
above. Whole-grammar static verification and all subsequent execution types remain
incomplete. Decoding does not allocate process resources, resolve imports, run
constructors or enter guest code.

PLAT-005: Preserve current Rust compatibility re-exports. Add portable state as
a distinct execution mode; do not represent it using fictitious x86 registers.
Keep C embedding handles opaque and size/version negotiated. Do not promise a
stable Rust ABI. Execution engines share a logical state contract, not a host
physical-register layout.

## First-wave boundary

The shared requirement and gate registries are integrator-owned. Each role may
publish isolated draft reference transports with symbolic names. The explicit
experimental 0.2/profile2 candidate reserves ten required semantic section roots;
it is separate from legacy 0.1 framing. Contract freeze is recorded in external
qualification accounting. Draft transports do
not allocate stable public operation/type/trap IDs independently.
A source language ABI type identity is distinct from an execution value type.
Code pointer tokens are distinct from guest data addresses and host pointers;
exact token restrictions and relocation checks follow the accepted cross-role
decisions in `interface-decisions.json`.

`compiler-contract.json` records component review, exact candidate inputs,
outstanding blockers, named reviews and qualifying witness references.
It is evidence accounting, not an executable module. A candidate's content hash
identifies the reviewed artifacts; it conveys neither host qualification nor a
stable production ABI promise.

The source-library ABI epoch is distinct from wire, payload and compiler-profile
versions. The current reference recognizes exact legacy epoch 1 and the separate
epoch-2 site/identity with `RAX_PORTABLE_SOURCE_ABI_REVISION=2`. Existing generator
APIs default to epoch 1. Epoch 2 is a compiler-facing configuration boundary;
current full ABI verification returns typed unavailable until its genuine original
source-category producer and module qualification exist. An unbound descriptor
or equal-width native type is insufficient. See the source-byte conformance
reference and current status; this boundary does not qualify hosted execution.

The current finite SourceValueFlow reference adds an executable closed assertion
schema and checker over actual original core ABI/body/SSA owners, with39 cases
and517 execution tests per Python mode. Current consumed-source closure is856
hashes with no drift. It issues no source/category/body-equivalence/private-event
or runtime facts; known source ABI2 remains unavailable without genuine evidence.
The union construction-phase contract initially supports quiescent transitions
only. Full in-construction source laws/issuers remain required freeze gaps.

R25 current qualification covers517 execution and230 runtime tests per Python
mode plus40 native category-reference tests per mode/four CLI checks, with908
consumed source hashes current. Native observations and the quiescent union
protocol are UNBOUND references. SourceValueFlow schema reads use unbuffered
FileIO with measured descriptor bounds; no physical device/cache/allocator bound
is inferred. Genuine source/category/body/value/init/phase issuers and required
language/representation routes remain missing. Full compiler/platform gates stay false.

R26 integrates the [portable type frontend](../../../../tools/smir-abi/PORTABLE-TYPE-FRONTEND.md).
It runs a real out-of-tree pinned Clang TargetInfo for the portable LP64/little-endian
ABI and projects finite declarations into executable type, nominal, layout and
call-plan fragments. An independent checker verifies geometry and complete emitted
fragment relations. No LLVM checkout files are modified.

Root independently passes 168 actual cases across O0/O2_NDEBUG native builds and
normal/optimized Python, with 160 native tool invocations. Both fresh owner builds
guard 660 inputs each. Parent-module identity, loader filtering, absent-native
unavailability and nonwriting schema checks are exercised. Root freshly reruns
ABI64, epoch/projection13 and basic CI28 tests per Python mode. All 917 consumed
source hashes match current bytes. Execution517/runtime230 retain unchanged R25
as-run evidence; Rust178+3 retain their earlier unchanged as-run scope.

This is an UNBOUND type facet. Function bodies, records, source varargs, complete
source recipes and genuine private source issuers remain unavailable. No source
ABI2 execution, backend emission, compiler freeze or production admission follows.

R27 integrates the [actual-core event reference](../../../../tools/smir-format/execution/source_value_flow/DYNAMIC.md)
under the exact seven-file ownership map, with one dependent active fixture
provenance update. The real generic Python interpreter now retains actual
parameter/phi/operation births and scalar selections, carries explicit public
model masks, and publishes completed results once across park/resume. Retained
outputs survive metadata failure; a host failure during computation preserves
the original terminal exception. Current SSA binding identity and actual phi
snapshot checks reject stale value/birth pairs. No source facts are issued.

Fresh Root checks pass 551 execution, 230 runtime and 77 ABI/projection tests in
each normal/optimized Python mode. Execution has 213 and runtime 223 actual
process audits per mode, with verified flags, absent cache prefixes and no source
drift or unexpected inputs. Actual installed focused checks pass 149 tests and
six fixture groups per mode. The active union provenance change replaces exactly
two interpreter digest entries; 14 scenarios and all 1878 prior SMOs remain exact.
All 921 consumed source hashes match the current tree. A fresh independent C++
record codec oracle supports the runtime checks; no guest native execution is
inferred. Earlier native type/category and Rust checks retain their guarded
as-run scope. Historical failed cuts and counterexamples remain archived.

This is a finite sequential reference implementation. Genuine source/category/
body/initialization/phase issuers, source ABI2 execution, required language and
representation routes, full costs and every production platform gate remain
incomplete. Compiler freeze is false. The next explicitly owned work remains
first-wave: actual-core memory/init reference, nested union protocol, physical
Raw8 helpers and portable C record layout witnesses, each requiring its own
review, exact shared ownership and observed integration checks.

R28 adds an executable finite nested-union protocol reference with actual guarded Core memory effects. Its quiescent public model and initialization plane do not issue source construction, lifetime, active-member or initialization facts. It grants no production execution capability.
