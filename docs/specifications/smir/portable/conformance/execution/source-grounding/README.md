# Original-source grounding reference

`candidate.source_grounding.ground(owner, request, *, budget)` checks finite compiler
constraints against the actual original `RootContext`, its canonical source stamp
and one cumulative canonical `SourceQueryBudget`. It calls the genuine public runtime
contract verifier, canonical source-join verifier and ABI path APIs. A prior report,
factory callback or serialized inspection record is not an evidence input.

The input grammar is the closed `schema/execution/source_grounding.json`. Its exact
nested runtime carrier, canonical join and ABI source-program grammars are embedded
with renamed local schema references. The original grammar files are hash-checked,
and their actual public validators still run; embedding does not replace their
semantic checks. Local IDs are non-Boolean integers 0 through 4294967294. Local tables
have at most 4096 rows. Unknown fields, missing references, cycles and mismatched
namespaces reject before unsafe lookups. No default ABI, pointer or architectural
state is synthesized.

The frozen result contains original process-local `owner` and `stamp` handles,
canonical sorted `(function,binding)` pairs, `(function,scope,journal_slot)` triples,
`(function,visited_abstract_states)` pairs and sorted deferred obligations. `binding`
is always `unbound`; `source_fact_authority`, `runtime_authority` and
`active_v3_verified` are constructor-invariant false. These are static constraints,
not transferable private facts or execution admission.

The finite normal CFG checker preserves captured S aliases across copy/select/phi,
checks parent references before enter and retained receivers before close, rejects
stale/self references and missing normal exits, and never substitutes the newest
slot. Its rooted origin forest requires every alias to reach a genuine same-function
nonalias root; equal type, address, label or raw pointer bits do not establish that
root or dynamic alias identity. Exact source bit geometry equals Journal octet
geometry multiplied by 8; root Journal slot 0 is independent of cleanup field 0.

Physical lifecycle, exceptional paths, dynamic index bounds, projected/replacement/
launder operations and hierarchical Journal mapping remain outside this profile.
Existing-receiver adoption checks freshness and then refuses its unsupported transfer
protocol; a reserved create receiver is not required to be live prematurely. Actual
source alias operation truth, Journal outcomes, private issuers and all upstream
deferrals remain obligations. The checker does not establish C++ lifetime, EH,
portable execution, native execution, JIT, hosted libraries or compiler freeze.

Run the public regression module from the repository root:

```sh
cd tools/smir-format/execution
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_candidate_source_grounding
PYTHONDONTWRITEBYTECODE=1 python3 -O -m unittest -v test_candidate_source_grounding
```

Every complete source witness runs in an isolated child. Its original owner, R/P/ABI
oracles and cumulative ledger all live in that same child. The parent receives test
counts, not proof inputs. Module import preserves the parent's legacy codec/search
path. A direct API call from an incompatible existing runtime import context retains
the genuine runtime verifier's `SCV_IMPORT_CONTEXT` rejection. Child optimization
mode is checked explicitly; unknown private test names cannot fall back to a valid
case. Set `SMIR_GROUNDING_TEST_DIR` or `TMPDIR` to isolate temporary guard artifacts.
There is no public execution or inspection CLI in this package.

`fixtures/` holds 13 original encoded module variants, matching source JSON and raw
request blueprints. Positive controls include published sret, diamond, phi, loop,
live retained/parent scopes and rooted origins. Rejections include missing exits,
live re-entry, leaked caller scope, stale receivers/parents and origin cycles. Before
writing a request, the generator decodes its exact SMO and binds coordinates to that
module's actual identity and root digests. The manifest records static expected
constraints or exact rejection codes, never lifetime or authority facts.

From the repository root, the nonwriting reproducibility check is:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 docs/specifications/smir/portable/conformance/execution/source-grounding/generate_fixtures.py --check
```

The case catalog distinguishes real original public-input witnesses from explicitly
malformed standalone abstract-boundary tests. Long-chain forest checks test the
linear algorithm; they do not claim that the runtime verifier admits a large ABI
profile. The initial 53 strategic cases remain, with additional closed-input,
original-owner/schema guards, artifact decoding and import-isolation checks.

Assumptions and probes: original source/ledger identity (mutation, wrong owner/budget,
editable callback rejection); captured S freshness (loops, same-site ordering, phi,
stale/live/self cases); rooted origin custody (same-byte cyclic/rooted contrast,
shared tails, wrong terminals and quotas); geometry/namespace separation (root versus
field rejection); conditional operation truth (upstream obligations preserved).
High limits are active-root3 encoding, lifecycle/EH/source-operation proofs and
private runtime admission. Medium limits are the finite source/CFG/Journal profile.
No untracked foundation files or LLVM checkout files are modified by these tools.

Mutually exclusive return exits use a cumulatively precharged return-by-exit index.
The 1024-leaf helper-only branch stress checks observed return-row visits against
charged work; it is not a claim that the runtime verifier admits this large profile.


The pure helper now has signature
`prove_paths(function,contract,budget,*,source_observers=False)`. The exact bool
True checks every actual source_journal_observe S use at operation PRE after the
original pre_op phases. False rejects the new operation, including unvisited
records; it does not omit source uses. The preflight charges4work/1edge per block
and operation even in default mode; True additionally charges8work/1edge/32copied
payload bytes per visited lookup. Old no-observer semantics stay, while historical
quota counts are tied to their original source and must not be repinned. The
full `ground` API retains its separately supported original-program profile; R's
version3 observer pass reuses only this pure algorithm on its actual validated
original functions/contract. No `ground -> R.verify -> ground` recursion, synthetic
phase, callback or SourceFacts issuance is introduced. Fresh normal/O old-module
and nonwriting fixture checks cover this cost migration.
