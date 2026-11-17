# Static source-contract reference tool

This package verifies a finite compiler-facing source-contract graph against the
actual portable module's ten roots, execution types, ABI plans, ordinary SSA/CFG,
Journal declarations and helper calls. Its comparator checks a joint bijection of
private contract IDs over the reachable function closure, including address-taken
functions and return-adoption callees. Ordinary module IDs must match.

These inspection results are conditional. Every result has `binding='unbound'`
and immutable `source_fact_authority=False`, `runtime_authority=False` and
`active_v3_verified=False`. No result admits execution, creates a SourceAlias or
ScopeRef, provides a Journal capability, or proves native/JIT execution.

Run from the repository root; paths can also be absolute from another directory:

```sh
export PYTHONPATH="$PWD/tools/smir-runtime-contract"
F=docs/specifications/smir/portable/conformance/runtime/source-contracts
python3 -B -m source_contracts verify "$F/original-pointer.smo" \
  "$F/original-pointer.source-contract.json" --budget "$F/explicit-budget.json"
python3 -B -m source_contracts compare \
  "$F/original-pointer.smo" "$F/original-pointer.source-contract.json" \
  "$F/original-pointer.smo" "$F/original-pointer-scoped.source-contract.json" \
  --function 0 --budget "$F/explicit-budget.json"
```

The second command returns `result:false` and exit 1 because the static contracts
differ. Success reports never serialize Python owner handles or internal tokens.
Coordinates contain the original source schema digest and sorted root digests.

The required budget is a closed JSON object with four exact integer fields:
`max_work`, `max_edges`, `max_copied_bytes` (unsigned 64-bit counts) and
`max_depth` (1 through 128). Boolean values, duplicate keys, unknown fields and
implicit defaults are rejected. Work and edges are logical units; copied bytes
are payload octets, not allocator capacity or processor measurements. The sample
budget grants 10^12 of each count and depth 128; callers select their own policy.

The budget file has a fixed 4096-octet cap and lexical nesting limit 1, checked
before JSON parsing, ledger construction or owner construction. One canonical
`SourceQueryBudget` covers both sides of comparison, bounded inputs, schema
loads, original verifier reservations, graph search, result capture and final
original-owner checks. Module files are capped at 16 MiB and contract JSON at
8 MiB; stat/descriptor/path changes during bounded reads reject. Contract JSON
nesting is bounded before parsing by `min(64, max_depth)`. Existing wire decoders
and real ABI/execution verifiers remain authoritative. Quotas can reject without
publishing a partial result.

| Exit | Meaning |
|---|---|
| 0 | Conditional verification, static comparison true, or help |
| 1 | Completed finite static comparison false |
| 2 | Input, usage or semantic rejection |
| 3 | Valid evidence outside the represented finite profile |
| 4 | Logical resource exhaustion |
| 70 | Unexpected internal exception |

Every non-help command emits exactly one closed JSON object. Error output has
`status:'error'`, class, original known diagnostic code, and detail limited to
4096 UTF8 octets. The explicit finite-profile refusal catalog also maps ambiguous return/adoption and
physical-clone requirements to unavailable. Unknown exceptions remain internal; they are never converted
into success or unavailable evidence. Duplicate options, implicit abbreviation,
unknown commands/options, nondecimal functions and the u32 sentinel reject.

The public Python API requires the actual `candidate.context.RootContext` and the
canonical budget class returned by `candidate.source_data_projection.source_api`:

```python
from source_contracts import verify, compare
constraints = verify(owner, raw_contract, budget=ledger)
comparison = compare(left_owner, left_raw_contract, right_owner, right_raw_contract,
                     function_id, budget=ledger)
```

`StaticConstraints` retains the original owner and `SourceStamp`, sorted unique
`checked_bindings`, `checked_scope_values`, `checked_exits`, and deferred diagnostic
tuple. `StaticComparison` retains genuine left/right constraints, the boolean
finite result, requested function, sorted closure and union of deferred results.
The four authority/binding fields are frozen and excluded from constructor inputs.
Reports, producer callbacks and newly reconstructed owners cannot substitute for
an original owner. Fresh factory indexes do not trust editable original caches;
their internal proof objects are never reissued as original-owner facts.

For two genuine revision-3 Python owners, each owner must have been constructed
with the identical explicit ledger used for this query. Verification compares the
complete embedded source contract to the supplied raw contract and runs actual ABI
and ordinary-body verification on a fresh complete v3 context. It neither projects
root3 to v2 nor issues semantic admission. Original owners and their full stamps
remain attached to the result. Mixed v2/v3 comparisons explicitly refuse with
`SCV_REVISION_PAIR_UNAVAILABLE`. The command-line reader remains v2 only.

The v3 comparator validates both complete modules before comparing the selected
function and supported direct/address-taken/adoption dependency closure. It omits
only each module's own `root2.manifest.identity` from temporary shallow comparison
views. Every other non-root3 field remains observable; actual selected ordinary
function records and the relevant source graph are compared. A valid changed
unreachable function may compare equal for a different selected function. This is
not full-module identity. Tail calls and other unsupported closure routes refuse.
Retained values use a metered iterative builtin-only walker, bounded to depth 64
and 16384 logical pairs. Both dictionary key sets are checked before membership;
no user equality or recursive Python container equality is invoked. Each alpha
candidate is charged for its actual bounded copy, sort and JSON serialization.
Existing v2 comparison behavior remains unchanged.

Finite profile: at most 64 execution types, 16 source nominals, four functions,
64 blocks, 256 counted SSA/operation entries, eight supported internal helper
imports, four Journals, 64 slots per Journal and slot count at most 1024. Source
nominals are simple kinds or flat scalar records; external dependencies/bridges
are unavailable. Conservative original-factory reservations precede factory calls.
The comparator supports at most 64 source nodes and eight nodes in an ambiguous
namespace partition. Worst-case search time is
`O(product(partition_size!) * (V + E))`, with `O(V + E)` retained graph/mapping
space plus bounded original factories and JSON captures. Every search step is
precharged. This is a finite reference profile, not a general verifier complexity
or host out-of-memory guarantee.

Full canonical subject resolution, source-language access legality, effective CV,
whole-CFG source lifetime coverage, actual incoming/created/returned alias issuers,
Scope/S/Journal generations, lifecycle implementation, source semantic admission and
cache integration remain explicit deferred obligations. A passing local suite
cannot establish the compiler freeze or the whole platform.

Reproduction and focused tests:

```sh
python3 -B -m source_contracts.schema --check
python3 -B -m source_contracts.fixtures --check
python3 -B -m unittest discover -s tools/smir-runtime-contract/source_contracts \
  -t tools/smir-runtime-contract -p 'test_*.py'
python3 -B -O -m unittest discover -s tools/smir-runtime-contract/source_contracts \
  -t tools/smir-runtime-contract -p 'test_*.py'
```

Schema ID: `urn:rax:smir:runtime:source-contracts:reference:1`, a local inspection
schema, not a wire root/operation assignment. The input preserves the accepted
revision-4 raw contract grammar. Fixture blueprints are declarative ten-root
records from the corrected R6 witnesses; the codec reconstructs exact objects.
They are not compiler-origin layout evidence. `fixture-provenance.json` records exact source template/oracle identities;
`generated-catalog.json` records
reproduction bytes/hashes, not a successful verification receipt. Generators only
write this new owned prefix, and `--check` does not write products.

Assumption register:

| ID | Assumption and dependent result | Falsification probe |
|---|---|---|
| SC1 | Canonical module paths/classes identify the reference implementations. All results depend on this. | Preload conflicting candidate/context/common/codec/ABI/budget modules; require input rejection. |
| SC2 | Original roots and active grammar remain unchanged during checking. Every source coordinate depends on this. | Mutate an original root or replace the schema; require snapshot/digest rejection. |
| SC3 | Finite reservations cover represented factory work in logical units. Completion depends on this profile. | Oversized valid original module gives unavailable; zero and one-work-short policies give resource failure. |
| SC4 | Strict nominal equivalence includes category, CV and definition identity. Binding joins depend on this. | Actual equivalent nominal IDs pass; category/CV/class/definition/namespace negatives reject. |
| SC5 | Static graph equality is weaker than execution/source-fact admission. Every comparison depends on this scope. | Inspect frozen flags, deferred obligations, definite unequal graphs and no private handles in JSON. |

High-impact open finding: passing source constraints leaves actual runtime/source
lifetime issuers and full path coverage unresolved. Medium-impact limitation:
factorial private-ID comparison is quota-bound and finite. Low-impact opportunity:
nonwriting reproduction makes new witness/schema drift independently detectable.
Primary implementation oracles are the current `candidate.context`,
`candidate.type_system`, ABI `NominalGraph`, original wire schemas/codec and the
accepted four RUNTIME-COMPILER-CONTRACT-TOOL contract revisions; no external source
or current upstream conformance claim is introduced here.


Revision-3 static Journal observers have a separate finite two-pass reference
profile: actual ordinary ABI/body/SSA validation first, then exact source
association and path-use checks. The supported callee has one inline scope around
its original journal_begin and logical retained exit; its ordinary return is only
a pointer. The caller has one block with call, observer, return, adopts once and
has no new Journal binding. The path proof checks its exact saved source value at
observer PRE. Richer bodies/lineages/EH/epochs explicitly refuse.

Observer-bearing comparison includes complete actual selected function records
and source graph in the joint finite alpha relation. Only the operator's
scope_value/adoption fields follow their original source namespace bijections;
ordinary SSA/type/CFG/return fields remain fixed. Valid unreachable ordinary
functions remain outside the selected closure after full module validation.
Logical quotas pay for actual new scans and candidate bodies; historical used
counts are not stable thresholds. No original root/stamp/body is rewritten.

See conformance/runtime/source-observer for the explicit-budget public witness,
actual SEM-owned binary reference and authored rejection tests. CLI module reader
remains v2. Every authority/admission boundary and whole-platform limitation above
remains in force.
